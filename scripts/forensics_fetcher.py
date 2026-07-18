#!/usr/bin/env python3
"""
Bitcoin Puzzle Blockchain Forensics — Data Fetcher & Validator
==============================================================

Entry point of the pipeline. Fetches, validates and computes the transaction
and signature data every other script here consumes, and writes the result to
JSON so downstream analysis runs offline against a fixed dataset rather than
re-querying explorers (which rate-limit, and whose responses drift over time).

What it does:
  1. Fetches all transactions for each exposure puzzle address (P65-P160)
  2. Identifies the 2019-05-31 exposure TXs (1000 sat sends FROM puzzle addresses)
  3. Extracts raw TX hex and parses DER signatures (r, s, pubkey)
  4. Computes SIGHASH_ALL z values from raw transactions
  5. For solved puzzles, computes exact ECDSA nonces (k)
  6. Verifies nonce correctness: k*G should have x-coordinate == r
  7. Validates all existing skill data (addresses, keys, pubkeys)
  8. Detects data discrepancies (e.g., wrong P130 key/address in skill)
  9. Fetches P71 exposure TX data (public key, signatures)
  10. Checks for P65 exposure TX (signed before it was solved)
  11. Software fingerprinting: TX version, locktime, sequence, fee patterns
  12. Saves everything to a comprehensive JSON results file

APIs used:
  - Primary: blockstream.info/api (good rate limits)
  - Fallback: mempool.space/api
  
Requirements:
  pip install requests

Usage:
  python forensics_fetcher.py
  # Output: forensics_results.json (upload to Claude)

Author: Generated for Mohamad's Bitcoin Puzzle research
"""

import json
import hashlib
import struct
import time
import sys
import os
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# secp256k1 curve parameters
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# API configuration
API_PRIMARY = "https://blockstream.info/api"
API_FALLBACK = "https://mempool.space/api"
REQUEST_DELAY = 1.5  # seconds between API calls (be polite)
MAX_RETRIES = 3

# ═══════════════════════════════════════════════════════════════════════════
# ALL PUZZLE DATA — Complete reference
# ═══════════════════════════════════════════════════════════════════════════

# Exposure puzzle addresses (creator sent 1000 sat FROM each on 2019-05-31)
EXPOSURE_PUZZLES = {
    65:  "18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe",
    70:  "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    75:  "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt",
    80:  "1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe",
    85:  "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr",
    90:  "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU",
    95:  "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC",
    100: "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F",
    105: "1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib",
    110: "12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg",
    115: "1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv",
    120: "17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT",
    125: "1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5",
    130: "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua",
    135: "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v",
    140: "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
    145: "19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg",
    150: "1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy",
    155: "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ",
    160: "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv",
}

# Puzzle 71 (our main target)
P71_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# Known private keys for solved exposure puzzles
SOLVED_KEYS = {
    65:  0x1a838b13505b26867,
    70:  0x349b84b6431a6c4ef1,
    75:  0x4c5ce114686a1336e07,
    80:  0xea1a5c66dcc11b5ad180,
    85:  0x11720c4f018d51b8cebba8,
    90:  0x2ce00bb2136a445c71e85bf,
    95:  0x527a792b183c7f64a0e8b1f4,
    100: 0xaf55fc59c335c8ec67ed24826,
    105: 0x16f14fc2054cd87ee6396b33df3,
    110: 0x35c0d7234df7deb0f20cf7062444,
    115: 0x60f4d11574f5deee49961d9609ac6,
    120: 0xb10f22572c497a836ea187f2e1fc23,
    125: 0x1c533b6bb7f0804e09960225e44877ac,
    130: 0x33e7665705359f04f28b88cf897c603c9,
}

# Known public keys for exposure puzzles (from known_data.md)
KNOWN_PUBKEYS = {
    65:  "0230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b",
    70:  "0290e6900a58d33393bc1097b5aed31f2e4e7cbd3e5466af958665bc0121248483",
    75:  "03726b574f193e374686d8e12bc6e4142adeb06770e0a2856f5e4ad89f66044755",
    80:  "037e1238f7b1ce757df94faa9a2eb261bf0aeb9f84dbf81212104e78931c2a19dc",
    85:  "0329c4574a4fd8c810b7e42a4b398882b381bcd85e40c6883712912d167c83e73a",
    90:  "035c38bd9ae4b10e8a250857006f3cfd98ab15a6196d9f4dfd25bc7ecc77d788d5",
    95:  "02967a5905d6f3b420959a02789f96ab4c3223a2c4d2762f817b7895c5bc88a045",
    100: "03d2063d40402f030d4cc71331468827aa41a8a09bd6fd801ba77fb64f8e67e617",
    105: "03bcf7ce887ffca5e62c9cabbdb7ffa71dc183c52c04ff4ee5ee82e0c55c39d77b",
    110: "0309976ba5570966bf889196b7fdf5a0f9a1e9ab340556ec29f8bb60599616167d",
    115: "0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55",
    120: "02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630",
    125: "0233709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e",
    130: "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852",
    135: "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16",
    140: "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640",
    145: "03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5",
    150: "03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49",
    155: "035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6",
    160: "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673",
}

# Data discrepancies to flag (found in skill review)
SKILL_DISCREPANCIES = {
    "P130_address_forensic_findings": {
        "file": "references/forensic_findings.md",
        "field": "P130 Address",
        "wrong_value": "1Fo47CkGKfJ3GTHeJfRnBRAfpnjxuKE8LH",
        "correct_value": "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua",
        "source": "known_data.md line 169",
    },
    "P130_key_forensic_findings": {
        "file": "references/forensic_findings.md",
        "field": "P130 Private Key K",
        "wrong_value": "0x3e65cb5e09770e3cb8e2e0e7355e3db78e8cec18",
        "correct_value": "0x33e7665705359f04f28b88cf897c603c9",
        "source": "known_data.md line 169",
    },
    "P130_key_nonce_recovery_script": {
        "file": "scripts/nonce_recovery.py",
        "field": "SOLVED_KEYS[130]",
        "wrong_value": "missing (commented out)",
        "correct_value": "0x33e7665705359f04f28b88cf897c603c9",
        "source": "known_data.md line 169",
    },
}

# Creator info
CREATOR_FUNDING_TX = "08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15"
CREATOR_ADDRESS = "1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F"
CREATOR_PUBKEY = "024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda"

# ═══════════════════════════════════════════════════════════════════════════
# ELLIPTIC CURVE MATH (secp256k1)
# ═══════════════════════════════════════════════════════════════════════════

def modinv(a, m=N):
    """Modular inverse using Python's built-in pow."""
    return pow(a % m, -1, m)

def ec_add(p1, p2):
    """Add two points on secp256k1."""
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    elif x1 == x2:
        return None  # point at infinity
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, point=None):
    """Scalar multiplication on secp256k1 using double-and-add."""
    if point is None:
        point = (Gx, Gy)
    result = None
    addend = point
    k = k % N
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

def pubkey_to_point(pubkey_hex):
    """Decode compressed public key to (x, y) point."""
    prefix = int(pubkey_hex[:2], 16)
    x = int(pubkey_hex[2:], 16)
    # y² = x³ + 7 mod P
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y % 2) != (prefix % 2):
        y = P - y
    return (x, y)

def point_to_pubkey(point, compressed=True):
    """Encode (x, y) point as compressed public key hex."""
    x, y = point
    if compressed:
        prefix = "02" if y % 2 == 0 else "03"
        return prefix + format(x, '064x')
    else:
        return "04" + format(x, '064x') + format(y, '064x')

# ═══════════════════════════════════════════════════════════════════════════
# BITCOIN TRANSACTION PARSING & SIGHASH
# ═══════════════════════════════════════════════════════════════════════════

def double_sha256(data):
    """Bitcoin's standard double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def read_varint(data, pos):
    """Read Bitcoin varint from bytes, return (value, new_pos)."""
    val = data[pos]
    if val < 0xfd:
        return val, pos + 1
    elif val == 0xfd:
        return struct.unpack_from('<H', data, pos + 1)[0], pos + 3
    elif val == 0xfe:
        return struct.unpack_from('<I', data, pos + 1)[0], pos + 5
    else:
        return struct.unpack_from('<Q', data, pos + 1)[0], pos + 9

def write_varint(val):
    """Encode integer as Bitcoin varint bytes."""
    if val < 0xfd:
        return bytes([val])
    elif val <= 0xffff:
        return b'\xfd' + struct.pack('<H', val)
    elif val <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', val)
    else:
        return b'\xff' + struct.pack('<Q', val)

def parse_raw_tx(raw_hex):
    """
    Parse a raw Bitcoin transaction hex string into its components.
    Returns dict with version, inputs, outputs, locktime, and witness flag.
    """
    data = bytes.fromhex(raw_hex)
    pos = 0
    
    # Version (4 bytes LE)
    version = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    
    # Check for segwit marker
    has_witness = False
    if data[pos] == 0x00 and data[pos + 1] != 0x00:
        has_witness = True
        pos += 2  # skip marker (0x00) and flag (0x01)
    
    # Input count
    in_count, pos = read_varint(data, pos)
    
    inputs = []
    for i in range(in_count):
        # Previous TX hash (32 bytes, internal byte order)
        prev_hash = data[pos:pos+32][::-1].hex()
        pos += 32
        # Previous output index (4 bytes LE)
        prev_index = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        # ScriptSig
        script_len, pos = read_varint(data, pos)
        scriptsig = data[pos:pos+script_len].hex()
        pos += script_len
        # Sequence (4 bytes LE)
        sequence = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        
        inputs.append({
            'prev_hash': prev_hash,
            'prev_index': prev_index,
            'scriptsig': scriptsig,
            'scriptsig_len': script_len,
            'sequence': sequence,
        })
    
    # Output count
    out_count, pos = read_varint(data, pos)
    
    outputs = []
    for i in range(out_count):
        # Value (8 bytes LE, satoshi)
        value = struct.unpack_from('<Q', data, pos)[0]
        pos += 8
        # ScriptPubKey
        script_len, pos = read_varint(data, pos)
        scriptpubkey = data[pos:pos+script_len].hex()
        pos += script_len
        
        outputs.append({
            'value': value,
            'scriptpubkey': scriptpubkey,
        })
    
    # Witness data (if segwit)
    witness_data = []
    if has_witness:
        for i in range(in_count):
            wit_count, pos = read_varint(data, pos)
            witness_items = []
            for j in range(wit_count):
                wit_len, pos = read_varint(data, pos)
                witness_items.append(data[pos:pos+wit_len].hex())
                pos += wit_len
            witness_data.append(witness_items)
    
    # Locktime (4 bytes LE)
    locktime = struct.unpack_from('<I', data, pos)[0]
    
    return {
        'version': version,
        'has_witness': has_witness,
        'inputs': inputs,
        'outputs': outputs,
        'witness': witness_data,
        'locktime': locktime,
        'raw_hex': raw_hex,
    }

def compute_sighash_all(raw_hex, input_index, prev_scriptpubkey_hex):
    """
    Compute SIGHASH_ALL for a legacy (non-segwit) transaction.
    
    This creates the hash that was signed by the private key.
    
    Steps:
    1. Parse the raw transaction
    2. For each input: set scriptSig to empty, EXCEPT input_index
    3. For input_index: set scriptSig to prev_scriptpubkey
    4. Append SIGHASH_ALL type (0x01000000) as 4-byte LE
    5. Double SHA-256 the result
    """
    tx = parse_raw_tx(raw_hex)
    
    # Build the serialization for signing
    result = b''
    
    # Version
    result += struct.pack('<I', tx['version'])
    
    # Input count
    result += write_varint(len(tx['inputs']))
    
    for i, inp in enumerate(tx['inputs']):
        # Previous TX hash (reversed back to internal byte order)
        result += bytes.fromhex(inp['prev_hash'])[::-1]
        # Previous output index
        result += struct.pack('<I', inp['prev_index'])
        
        if i == input_index:
            # This input gets the previous output's scriptPubKey
            script_bytes = bytes.fromhex(prev_scriptpubkey_hex)
            result += write_varint(len(script_bytes))
            result += script_bytes
        else:
            # Other inputs get empty scriptSig
            result += write_varint(0)
        
        # Sequence
        result += struct.pack('<I', inp['sequence'])
    
    # Output count
    result += write_varint(len(tx['outputs']))
    
    for out in tx['outputs']:
        result += struct.pack('<Q', out['value'])
        script_bytes = bytes.fromhex(out['scriptpubkey'])
        result += write_varint(len(script_bytes))
        result += script_bytes
    
    # Locktime
    result += struct.pack('<I', tx['locktime'])
    
    # SIGHASH_ALL type (4 bytes LE)
    result += struct.pack('<I', 1)
    
    # Double SHA-256
    z_bytes = double_sha256(result)
    z = int.from_bytes(z_bytes, 'big')
    
    return z, z_bytes.hex()

# ═══════════════════════════════════════════════════════════════════════════
# DER SIGNATURE PARSING
# ═══════════════════════════════════════════════════════════════════════════

def parse_der_signature(script_hex):
    """
    Parse a P2PKH scriptSig to extract ECDSA r, s, sighash, and pubkey.
    
    Format: <push_len> <DER_sig> <sighash_byte> <push_len> <pubkey>
    DER: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    """
    try:
        pos = 0
        # First push byte = length of (DER signature + sighash byte)
        push_len = int(script_hex[pos:pos+2], 16)
        pos += 2
        sig_and_hash = script_hex[pos:pos + push_len * 2]
        pos += push_len * 2
        
        # Last byte of sig_and_hash is sighash type
        sighash = int(sig_and_hash[-2:], 16)
        der_sig = sig_and_hash[:-2]
        
        # Parse DER: 30 <total_len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
        if der_sig[:2] != '30':
            raise ValueError(f"Expected DER SEQUENCE tag 0x30, got 0x{der_sig[:2]}")
        
        p = 4  # skip "30 <len>"
        
        # Parse r
        if der_sig[p:p+2] != '02':
            raise ValueError(f"Expected INTEGER tag 0x02 for r")
        p += 2
        r_len = int(der_sig[p:p+2], 16)
        p += 2
        r_hex = der_sig[p:p + r_len * 2]
        p += r_len * 2
        
        # Parse s
        if der_sig[p:p+2] != '02':
            raise ValueError(f"Expected INTEGER tag 0x02 for s")
        p += 2
        s_len = int(der_sig[p:p+2], 16)
        p += 2
        s_hex = der_sig[p:p + s_len * 2]
        
        # Strip leading zeros (DER encodes as signed, so may have 0x00 prefix)
        r_hex = r_hex.lstrip('0') or '0'
        s_hex = s_hex.lstrip('0') or '0'
        
        r = int(r_hex, 16)
        s = int(s_hex, 16)
        
        # Parse public key
        pubkey_push = int(script_hex[pos:pos+2], 16)
        pos += 2
        pubkey = script_hex[pos:pos + pubkey_push * 2]
        
        return {
            'r': r,
            's': s,
            'r_hex': '0x' + format(r, 'x'),
            's_hex': '0x' + format(s, 'x'),
            'r_bits': r.bit_length(),
            's_bits': s.bit_length(),
            'sighash': sighash,
            'pubkey': pubkey,
        }
    except Exception as e:
        return {'error': str(e), 'raw_scriptsig': script_hex}

# ═══════════════════════════════════════════════════════════════════════════
# API FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

session = requests.Session()
session.headers.update({'User-Agent': 'PuzzleForensics/1.0'})

def api_get(endpoint, base_url=None, retries=MAX_RETRIES):
    """
    Make a GET request to blockchain API with retry logic and fallback.
    """
    if base_url is None:
        base_url = API_PRIMARY
    
    for attempt in range(retries):
        try:
            url = f"{base_url}{endpoint}"
            resp = session.get(url, timeout=30)
            
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                wait = (attempt + 1) * 5
                print(f"  ⏳ Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            elif resp.status_code == 404:
                return None
            else:
                print(f"  ⚠ HTTP {resp.status_code} for {endpoint}")
                if attempt < retries - 1:
                    time.sleep(2)
                continue
                
        except requests.exceptions.RequestException as e:
            print(f"  ⚠ Request error: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    
    # Try fallback API
    if base_url == API_PRIMARY:
        print(f"  → Trying fallback API (mempool.space)...")
        return api_get(endpoint, base_url=API_FALLBACK, retries=2)
    
    return None

def fetch_address_txs(address):
    """Fetch all transactions for a Bitcoin address."""
    all_txs = []
    last_txid = None
    
    while True:
        endpoint = f"/address/{address}/txs"
        if last_txid:
            endpoint += f"/chain/{last_txid}"
        
        resp = api_get(endpoint)
        if resp is None:
            break
        
        try:
            txs = resp.json()
        except:
            break
            
        if not txs:
            break
        
        all_txs.extend(txs)
        
        if len(txs) < 25:  # blockstream returns max 25 per page
            break
        
        last_txid = txs[-1]['txid']
        time.sleep(REQUEST_DELAY)
    
    return all_txs

def fetch_raw_tx(txid):
    """Fetch raw transaction hex by txid."""
    resp = api_get(f"/tx/{txid}/hex")
    if resp and resp.status_code == 200:
        return resp.text.strip()
    return None

def fetch_tx_info(txid):
    """Fetch decoded transaction info by txid."""
    resp = api_get(f"/tx/{txid}")
    if resp and resp.status_code == 200:
        return resp.json()
    return None

def fetch_prev_output(txid, vout_index):
    """Fetch the scriptPubKey of a previous output (needed for SIGHASH)."""
    resp = api_get(f"/tx/{txid}")
    if resp and resp.status_code == 200:
        tx_data = resp.json()
        if vout_index < len(tx_data.get('vout', [])):
            return tx_data['vout'][vout_index].get('scriptpubkey', '')
    return None

# ═══════════════════════════════════════════════════════════════════════════
# NONCE RECOVERY
# ═══════════════════════════════════════════════════════════════════════════

def recover_nonce(r, s, z, private_key):
    """
    Recover ECDSA nonce k given known private key K.
    
    k = (z + r * K) * s^(-1) mod n
    
    Returns (k, verified) where verified checks k*G has x-coordinate == r.
    """
    k = ((z + r * private_key) * modinv(s)) % N
    
    # Verify: k*G should have x-coordinate == r
    try:
        kG = ec_mul(k)
        verified = (kG[0] == r)
    except:
        verified = False
    
    return k, verified

def verify_pubkey_matches_privkey(privkey, expected_pubkey_hex):
    """Verify that a private key generates the expected public key."""
    point = ec_mul(privkey)
    computed_pubkey = point_to_pubkey(point)
    return computed_pubkey.lower() == expected_pubkey_hex.lower()

# ═══════════════════════════════════════════════════════════════════════════
# EXPOSURE TX IDENTIFICATION
# ═══════════════════════════════════════════════════════════════════════════

def find_exposure_tx(txs, puzzle_address):
    """
    Find the 2019-05-31 exposure transaction from a list of transactions.
    
    Criteria:
    - Date around 2019-05-31
    - Spends FROM the puzzle address (input is puzzle address)
    - Sends a small amount (≤ 1000-2000 sat per output, or total output is small)
    
    Returns the exposure TX dict or None.
    """
    candidates = []
    
    for tx in txs:
        # Check if this TX spends from our address
        is_spending = False
        for vin in tx.get('vin', []):
            if vin.get('prevout', {}).get('scriptpubkey_address') == puzzle_address:
                is_spending = True
                break
        
        if not is_spending:
            continue
        
        # Check date - should be around 2019-05-31
        block_time = tx.get('status', {}).get('block_time', 0)
        if block_time == 0:
            continue
        
        tx_date = datetime.fromtimestamp(block_time, tz=timezone.utc)
        
        # Look for transactions in May-June 2019
        if tx_date.year == 2019 and tx_date.month in [5, 6]:
            candidates.append({
                'txid': tx['txid'],
                'date': tx_date.isoformat(),
                'block_height': tx.get('status', {}).get('block_height'),
                'tx_data': tx,
            })
    
    if not candidates:
        return None
    
    # If multiple candidates, prefer the one closest to 2019-05-31
    target_date = datetime(2019, 5, 31, tzinfo=timezone.utc)
    candidates.sort(key=lambda c: abs((datetime.fromisoformat(c['date']) - target_date).total_seconds()))
    
    return candidates[0]

# ═══════════════════════════════════════════════════════════════════════════
# SOFTWARE FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════

def fingerprint_tx(parsed_tx):
    """Extract software fingerprinting details from a parsed transaction."""
    fingerprint = {
        'version': parsed_tx['version'],
        'locktime': parsed_tx['locktime'],
        'has_witness': parsed_tx['has_witness'],
        'num_inputs': len(parsed_tx['inputs']),
        'num_outputs': len(parsed_tx['outputs']),
        'sequences': [inp['sequence'] for inp in parsed_tx['inputs']],
        'output_values': [out['value'] for out in parsed_tx['outputs']],
        'output_script_types': [],
    }
    
    for out in parsed_tx['outputs']:
        spk = out['scriptpubkey']
        if spk.startswith('76a914') and spk.endswith('88ac'):
            fingerprint['output_script_types'].append('P2PKH')
        elif spk.startswith('a914') and spk.endswith('87'):
            fingerprint['output_script_types'].append('P2SH')
        elif spk.startswith('0014'):
            fingerprint['output_script_types'].append('P2WPKH')
        elif spk.startswith('0020'):
            fingerprint['output_script_types'].append('P2WSH')
        elif spk.startswith('5120'):
            fingerprint['output_script_types'].append('P2TR')
        else:
            fingerprint['output_script_types'].append(f'unknown({spk[:8]}...)')
    
    # Sequence analysis
    all_final = all(s == 0xffffffff for s in fingerprint['sequences'])
    fingerprint['all_sequences_final'] = all_final
    
    return fingerprint

# ═══════════════════════════════════════════════════════════════════════════
# MAIN DATA COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def process_puzzle(puzzle_num, address, results):
    """
    Process a single puzzle:
    1. Fetch all TXs for the address
    2. Find the exposure TX
    3. Extract signature data
    4. Compute SIGHASH
    5. If solved, compute nonce
    """
    print(f"\n{'='*60}")
    print(f"  Processing P{puzzle_num}: {address}")
    print(f"{'='*60}")
    
    puzzle_result = {
        'puzzle_number': puzzle_num,
        'address': address,
        'known_pubkey': KNOWN_PUBKEYS.get(puzzle_num),
        'private_key_known': puzzle_num in SOLVED_KEYS,
        'private_key_hex': hex(SOLVED_KEYS[puzzle_num]) if puzzle_num in SOLVED_KEYS else None,
        'total_txs': 0,
        'exposure_tx': None,
        'signature_data': None,
        'sighash_z': None,
        'recovered_nonce': None,
        'nonce_verified': None,
        'fingerprint': None,
        'errors': [],
        'all_spending_txs': [],
    }
    
    # Step 1: Fetch transactions
    print(f"  📡 Fetching transactions...")
    time.sleep(REQUEST_DELAY)
    txs = fetch_address_txs(address)
    puzzle_result['total_txs'] = len(txs)
    print(f"  ✓ Found {len(txs)} transactions")
    
    if not txs:
        puzzle_result['errors'].append("No transactions found for address")
        return puzzle_result
    
    # Collect all spending TXs for reference
    for tx in txs:
        for vin in tx.get('vin', []):
            if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                block_time = tx.get('status', {}).get('block_time', 0)
                tx_date = datetime.fromtimestamp(block_time, tz=timezone.utc).isoformat() if block_time else "unknown"
                puzzle_result['all_spending_txs'].append({
                    'txid': tx['txid'],
                    'date': tx_date,
                    'block_height': tx.get('status', {}).get('block_height'),
                })
                break
    
    # Step 2: Find exposure TX
    print(f"  🔍 Looking for exposure TX (~2019-05-31)...")
    exposure = find_exposure_tx(txs, address)
    
    if not exposure:
        puzzle_result['errors'].append("No exposure TX found around 2019-05-31")
        print(f"  ✗ No exposure TX found")
        # List all spending TXs for debugging
        for stx in puzzle_result['all_spending_txs']:
            print(f"    Spending TX: {stx['txid'][:16]}... on {stx['date']}")
        return puzzle_result
    
    exposure_txid = exposure['txid']
    puzzle_result['exposure_tx'] = {
        'txid': exposure_txid,
        'date': exposure['date'],
        'block_height': exposure['block_height'],
    }
    print(f"  ✓ Exposure TX: {exposure_txid}")
    print(f"    Date: {exposure['date']}")
    
    # Step 3: Get raw TX and parse
    print(f"  📦 Fetching raw TX hex...")
    time.sleep(REQUEST_DELAY)
    raw_hex = fetch_raw_tx(exposure_txid)
    
    if not raw_hex:
        puzzle_result['errors'].append(f"Failed to fetch raw TX hex for {exposure_txid}")
        print(f"  ✗ Failed to fetch raw TX hex")
        return puzzle_result
    
    puzzle_result['exposure_tx']['raw_hex'] = raw_hex
    
    # Parse the transaction
    try:
        parsed_tx = parse_raw_tx(raw_hex)
        puzzle_result['fingerprint'] = fingerprint_tx(parsed_tx)
    except Exception as e:
        puzzle_result['errors'].append(f"TX parse error: {e}")
        print(f"  ✗ TX parse error: {e}")
        return puzzle_result
    
    # Step 4: Find the input that spends from our puzzle address
    # We need to identify which input index corresponds to our puzzle address
    tx_info = exposure['tx_data']
    input_index = None
    prev_txid = None
    prev_vout = None
    
    for i, vin in enumerate(tx_info.get('vin', [])):
        if vin.get('prevout', {}).get('scriptpubkey_address') == address:
            input_index = i
            prev_txid = vin.get('txid')
            prev_vout = vin.get('vout')
            break
    
    if input_index is None:
        puzzle_result['errors'].append("Could not find puzzle address in TX inputs")
        print(f"  ✗ Could not find puzzle address in TX inputs")
        return puzzle_result
    
    puzzle_result['exposure_tx']['input_index'] = input_index
    
    # Step 5: Parse the scriptSig
    scriptsig = parsed_tx['inputs'][input_index]['scriptsig']
    puzzle_result['exposure_tx']['scriptsig'] = scriptsig
    
    print(f"  🔑 Parsing signature...")
    sig_data = parse_der_signature(scriptsig)
    
    if 'error' in sig_data:
        # Might be a segwit input - check witness data
        if parsed_tx['has_witness'] and parsed_tx['witness']:
            wit = parsed_tx['witness'][input_index]
            if len(wit) >= 2:
                # Witness: [signature, pubkey]
                sig_hex = wit[0]
                pubkey_hex = wit[1]
                # Reconstruct as if it were a P2PKH scriptSig for parsing
                fake_scriptsig = format(len(bytes.fromhex(sig_hex)), '02x') + sig_hex + format(len(bytes.fromhex(pubkey_hex)), '02x') + pubkey_hex
                sig_data = parse_der_signature(fake_scriptsig)
                sig_data['is_witness'] = True
                puzzle_result['exposure_tx']['is_segwit'] = True
        
        if 'error' in sig_data:
            puzzle_result['errors'].append(f"Signature parse error: {sig_data['error']}")
            print(f"  ✗ Signature parse error: {sig_data['error']}")
            return puzzle_result
    
    puzzle_result['signature_data'] = sig_data
    print(f"  ✓ r: {sig_data['r_hex']}")
    print(f"    s: {sig_data['s_hex']}")
    print(f"    r bits: {sig_data['r_bits']}, s bits: {sig_data['s_bits']}")
    print(f"    PubKey: {sig_data['pubkey'][:16]}...")
    print(f"    Sighash: {sig_data['sighash']:02x}")
    
    # Verify pubkey matches expected
    expected_pubkey = KNOWN_PUBKEYS.get(puzzle_num)
    if expected_pubkey:
        extracted_pubkey = sig_data['pubkey']
        if extracted_pubkey.lower() == expected_pubkey.lower():
            print(f"  ✓ PubKey matches known_data.md")
            puzzle_result['pubkey_match'] = True
        else:
            print(f"  ⚠ PubKey MISMATCH!")
            print(f"    Expected: {expected_pubkey}")
            print(f"    Got:      {extracted_pubkey}")
            puzzle_result['pubkey_match'] = False
            puzzle_result['extracted_pubkey'] = extracted_pubkey
    
    # Step 6: Compute SIGHASH_ALL (z value)
    print(f"  🔢 Computing SIGHASH_ALL (z value)...")
    
    # We need the previous output's scriptPubKey
    prev_scriptpubkey = None
    
    # First try to get it from the API response
    for vin in tx_info.get('vin', []):
        if vin.get('prevout', {}).get('scriptpubkey_address') == address:
            prev_scriptpubkey = vin.get('prevout', {}).get('scriptpubkey')
            break
    
    if not prev_scriptpubkey and prev_txid is not None:
        # Fetch it
        time.sleep(REQUEST_DELAY)
        prev_scriptpubkey = fetch_prev_output(prev_txid, prev_vout)
    
    if not prev_scriptpubkey:
        puzzle_result['errors'].append("Could not determine previous scriptPubKey for SIGHASH")
        print(f"  ✗ Could not get previous scriptPubKey")
        return puzzle_result
    
    puzzle_result['exposure_tx']['prev_scriptpubkey'] = prev_scriptpubkey
    
    try:
        # For segwit, SIGHASH is computed differently (BIP143)
        # But the 2019 exposure TXs are likely legacy P2PKH
        is_segwit = puzzle_result.get('exposure_tx', {}).get('is_segwit', False)
        
        if is_segwit:
            # BIP143 SIGHASH for segwit
            z, z_hex = compute_sighash_bip143(raw_hex, input_index, prev_scriptpubkey, 
                                                tx_info['vin'][input_index]['prevout']['value'])
            puzzle_result['sighash_method'] = 'BIP143'
        else:
            z, z_hex = compute_sighash_all(raw_hex, input_index, prev_scriptpubkey)
            puzzle_result['sighash_method'] = 'LEGACY'
        
        puzzle_result['sighash_z'] = {
            'z_int': z,
            'z_hex': '0x' + format(z, '064x'),
            'z_raw_hex': z_hex,
        }
        print(f"  ✓ z = 0x{format(z, '064x')[:32]}...")
        
    except Exception as e:
        puzzle_result['errors'].append(f"SIGHASH computation error: {e}")
        print(f"  ✗ SIGHASH error: {e}")
        return puzzle_result
    
    # Step 7: Recover nonce (if private key is known)
    if puzzle_num in SOLVED_KEYS:
        print(f"  🧮 Recovering nonce...")
        K = SOLVED_KEYS[puzzle_num]
        r = sig_data['r']
        s = sig_data['s']
        
        # Handle low-s normalization (BIP62)
        # If s > N/2, the canonical form uses N - s
        s_for_nonce = s
        if s > N // 2:
            s_for_nonce = N - s
            print(f"  ℹ Using canonical s (low-s)")
        
        # Try both s and N-s
        k1, v1 = recover_nonce(r, s, z, K)
        k2, v2 = recover_nonce(r, N - s, z, K)
        
        if v1:
            k, verified = k1, v1
            puzzle_result['s_used'] = 'original'
        elif v2:
            k, verified = k2, v2
            puzzle_result['s_used'] = 'negated (N-s)'
        else:
            # Also try with sighash byte variants
            k, verified = k1, v1  # default
            puzzle_result['s_used'] = 'original (unverified)'
            print(f"  ⚠ Nonce verification failed — z value may need adjustment")
        
        puzzle_result['recovered_nonce'] = {
            'k_int': k,
            'k_hex': '0x' + format(k, '064x'),
            'k_bits': k.bit_length(),
        }
        puzzle_result['nonce_verified'] = verified
        
        if verified:
            print(f"  ✓ k = 0x{format(k, '064x')[:32]}...")
            print(f"    k bits: {k.bit_length()}")
            print(f"    Verification: PASSED ✓ (k*G).x == r")
        else:
            print(f"  ⚠ k = 0x{format(k, '064x')[:32]}...")
            print(f"    Verification: FAILED ✗")
    
    # Step 8: Verify private key matches known public key
    if puzzle_num in SOLVED_KEYS and expected_pubkey:
        K = SOLVED_KEYS[puzzle_num]
        key_matches = verify_pubkey_matches_privkey(K, expected_pubkey)
        puzzle_result['privkey_pubkey_match'] = key_matches
        if key_matches:
            print(f"  ✓ Private key matches known public key")
        else:
            print(f"  ✗ Private key does NOT match known public key!")
    
    return puzzle_result


def compute_sighash_bip143(raw_hex, input_index, scriptcode_hex, input_value):
    """
    BIP143 sighash computation for segwit inputs.
    
    hashPrevouts || hashSequence || outpoint || scriptCode || amount || 
    nSequence || hashOutputs || nLocktime || nHashType
    """
    tx = parse_raw_tx(raw_hex)
    
    # hashPrevouts = double_sha256(all prevout outpoints)
    prevouts = b''
    for inp in tx['inputs']:
        prevouts += bytes.fromhex(inp['prev_hash'])[::-1]
        prevouts += struct.pack('<I', inp['prev_index'])
    hash_prevouts = double_sha256(prevouts)
    
    # hashSequence = double_sha256(all sequences)
    sequences = b''
    for inp in tx['inputs']:
        sequences += struct.pack('<I', inp['sequence'])
    hash_sequence = double_sha256(sequences)
    
    # outpoint being spent
    inp = tx['inputs'][input_index]
    outpoint = bytes.fromhex(inp['prev_hash'])[::-1] + struct.pack('<I', inp['prev_index'])
    
    # scriptCode (for P2WPKH, it's OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG)
    # If the prev scriptpubkey is 0014<hash>, the scriptCode is 76a914<hash>88ac
    if scriptcode_hex.startswith('0014'):
        hash160 = scriptcode_hex[4:]
        scriptcode = f'76a914{hash160}88ac'
    else:
        scriptcode = scriptcode_hex
    
    scriptcode_bytes = bytes.fromhex(scriptcode)
    
    # hashOutputs = double_sha256(all outputs)
    outputs = b''
    for out in tx['outputs']:
        outputs += struct.pack('<Q', out['value'])
        spk = bytes.fromhex(out['scriptpubkey'])
        outputs += write_varint(len(spk))
        outputs += spk
    hash_outputs = double_sha256(outputs)
    
    # Build preimage
    preimage = b''
    preimage += struct.pack('<I', tx['version'])
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += outpoint
    preimage += write_varint(len(scriptcode_bytes))
    preimage += scriptcode_bytes
    preimage += struct.pack('<Q', input_value)
    preimage += struct.pack('<I', inp['sequence'])
    preimage += hash_outputs
    preimage += struct.pack('<I', tx['locktime'])
    preimage += struct.pack('<I', 1)  # SIGHASH_ALL
    
    z_bytes = double_sha256(preimage)
    z = int.from_bytes(z_bytes, 'big')
    
    return z, z_bytes.hex()


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def validate_existing_data(results):
    """
    Validate all existing skill data and flag discrepancies.
    """
    validations = {
        'known_discrepancies': SKILL_DISCREPANCIES,
        'key_validations': {},
        'pubkey_validations': {},
        'address_validations': {},
    }
    
    # Validate private keys match public keys
    print(f"\n{'='*60}")
    print(f"  Validating private key ↔ public key consistency")
    print(f"{'='*60}")
    
    for pnum, privkey in SOLVED_KEYS.items():
        expected_pubkey = KNOWN_PUBKEYS.get(pnum)
        if expected_pubkey:
            matches = verify_pubkey_matches_privkey(privkey, expected_pubkey)
            validations['key_validations'][f'P{pnum}'] = {
                'private_key': hex(privkey),
                'expected_pubkey': expected_pubkey,
                'matches': matches,
            }
            status = "✓" if matches else "✗ MISMATCH"
            print(f"  P{pnum}: {status}")
        
        # Validate key is in correct bit range
        expected_bits = pnum
        actual_bits = privkey.bit_length()
        in_range = (actual_bits == expected_bits) or (actual_bits == expected_bits - 0)
        # Key should be in [2^(n-1), 2^n - 1]
        lower = 1 << (pnum - 1)
        upper = (1 << pnum) - 1
        in_range = lower <= privkey <= upper
        
        validations['key_validations'][f'P{pnum}']['in_bit_range'] = in_range
        if not in_range:
            print(f"  ⚠ P{pnum} key {hex(privkey)} NOT in range [2^{pnum-1}, 2^{pnum}-1]!")
    
    return validations

# ═══════════════════════════════════════════════════════════════════════════
# NONCE PATTERN ANALYSIS (preliminary)
# ═══════════════════════════════════════════════════════════════════════════

def analyze_nonces(results):
    """
    Perform preliminary nonce pattern analysis on recovered nonces.
    """
    nonces = {}
    for pnum, data in sorted(results['puzzles'].items(), key=lambda x: int(x[0])):
        if data.get('recovered_nonce') and data.get('nonce_verified'):
            nonces[int(pnum)] = data['recovered_nonce']['k_int']
    
    if len(nonces) < 2:
        return {'status': 'insufficient_data', 'count': len(nonces)}
    
    analysis = {
        'count': len(nonces),
        'puzzles_with_nonces': sorted(nonces.keys()),
        'nonce_bit_lengths': {},
        'top_byte_distribution': {},
        'rfc6979_check_needed': True,
        'preliminary_observations': [],
    }
    
    for pnum, k in sorted(nonces.items()):
        analysis['nonce_bit_lengths'][f'P{pnum}'] = k.bit_length()
        k_hex = format(k, '064x')
        analysis['top_byte_distribution'][f'P{pnum}'] = int(k_hex[:2], 16)
    
    # Check bit length distribution
    bit_lengths = list(analysis['nonce_bit_lengths'].values())
    if all(b == 256 for b in bit_lengths):
        analysis['preliminary_observations'].append(
            "All nonces are full 256-bit — no truncation bias detected"
        )
    elif any(b < 200 for b in bit_lengths):
        analysis['preliminary_observations'].append(
            "WARNING: Some nonces have suspiciously low bit counts — potential bias!"
        )
    
    # Check for obvious patterns
    k_values = [nonces[p] for p in sorted(nonces.keys())]
    
    # Check consecutive differences
    if len(k_values) >= 2:
        diffs = []
        for i in range(len(k_values) - 1):
            diff = (k_values[i+1] - k_values[i]) % N
            diffs.append(diff)
        
        # Check if differences are constant (LCG with c=0)
        if len(set(diffs)) == 1:
            analysis['preliminary_observations'].append(
                "CRITICAL: Constant difference between consecutive nonces — possible LCG!"
            )
        
        # Check if all differences have similar bit length
        diff_bits = [d.bit_length() for d in diffs]
        if max(diff_bits) - min(diff_bits) < 5:
            analysis['preliminary_observations'].append(
                "Note: Nonce differences have similar bit lengths — may indicate structure"
            )
    
    # Check for common GCD (could indicate shared factor)
    from math import gcd
    if len(k_values) >= 2:
        g = k_values[0]
        for v in k_values[1:]:
            g = gcd(g, v)
        if g > 1:
            analysis['preliminary_observations'].append(
                f"Note: GCD of all nonces = {g} (> 1 may indicate shared structure)"
            )
    
    if not analysis['preliminary_observations']:
        analysis['preliminary_observations'].append(
            "No obvious patterns detected in preliminary analysis. "
            "Full RFC 6979 verification and lattice analysis needed."
        )
    
    return analysis

# ═══════════════════════════════════════════════════════════════════════════
# P71 SPECIFIC DATA
# ═══════════════════════════════════════════════════════════════════════════

def fetch_p71_data():
    """Fetch P71 specific data — balance, TX count, public key if exposed."""
    print(f"\n{'='*60}")
    print(f"  Fetching P71 data: {P71_ADDRESS}")
    print(f"{'='*60}")
    
    p71_data = {
        'address': P71_ADDRESS,
        'public_key': None,
        'balance': None,
        'tx_count': 0,
        'exposure_tx': None,
        'all_txs': [],
    }
    
    time.sleep(REQUEST_DELAY)
    txs = fetch_address_txs(P71_ADDRESS)
    p71_data['tx_count'] = len(txs)
    print(f"  ✓ Found {len(txs)} transactions")
    
    # Check for any spending TX (would expose public key)
    for tx in txs:
        for vin in tx.get('vin', []):
            if vin.get('prevout', {}).get('scriptpubkey_address') == P71_ADDRESS:
                # This TX spends from P71 — public key is exposed!
                scriptsig = vin.get('scriptsig', '')
                if scriptsig:
                    try:
                        sig = parse_der_signature(scriptsig)
                        p71_data['public_key'] = sig.get('pubkey')
                        print(f"  🔑 P71 Public Key EXPOSED: {sig.get('pubkey', 'parse error')}")
                    except:
                        pass
                
                # Check witness
                if vin.get('witness'):
                    wit = vin['witness']
                    if len(wit) >= 2:
                        p71_data['public_key'] = wit[1]
                        print(f"  🔑 P71 Public Key EXPOSED (witness): {wit[1]}")
        
        # Record TX summary
        block_time = tx.get('status', {}).get('block_time', 0)
        tx_date = datetime.fromtimestamp(block_time, tz=timezone.utc).isoformat() if block_time else "unconfirmed"
        
        # Calculate value flow for this address
        received = sum(out.get('value', 0) for out in tx.get('vout', []) 
                      if out.get('scriptpubkey_address') == P71_ADDRESS)
        spent = sum(vin.get('prevout', {}).get('value', 0) for vin in tx.get('vin', [])
                   if vin.get('prevout', {}).get('scriptpubkey_address') == P71_ADDRESS)
        
        p71_data['all_txs'].append({
            'txid': tx['txid'],
            'date': tx_date,
            'received': received,
            'spent': spent,
        })
    
    # Calculate total balance
    total_received = sum(t['received'] for t in p71_data['all_txs'])
    total_spent = sum(t['spent'] for t in p71_data['all_txs'])
    p71_data['balance'] = total_received - total_spent
    p71_data['balance_btc'] = p71_data['balance'] / 1e8
    
    print(f"  💰 Balance: {p71_data['balance']} sat ({p71_data['balance_btc']:.8f} BTC)")
    
    if p71_data['public_key'] is None:
        print(f"  ℹ P71 public key NOT exposed (no spending TX)")
    
    return p71_data

# ═══════════════════════════════════════════════════════════════════════════
# CREATOR FUNDING TX VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_creator_funding_tx():
    """Validate and extract details from the creator's funding TX."""
    print(f"\n{'='*60}")
    print(f"  Validating Creator Funding TX")
    print(f"{'='*60}")
    
    funding_data = {
        'txid': CREATOR_FUNDING_TX,
        'creator_address': CREATOR_ADDRESS,
        'creator_pubkey': CREATOR_PUBKEY,
    }
    
    time.sleep(REQUEST_DELAY)
    tx_info = fetch_tx_info(CREATOR_FUNDING_TX)
    
    if not tx_info:
        funding_data['error'] = "Failed to fetch funding TX"
        print(f"  ✗ Failed to fetch funding TX")
        return funding_data
    
    # Validate structure: 1 input → 256 outputs
    funding_data['num_inputs'] = len(tx_info.get('vin', []))
    funding_data['num_outputs'] = len(tx_info.get('vout', []))
    funding_data['block_height'] = tx_info.get('status', {}).get('block_height')
    
    block_time = tx_info.get('status', {}).get('block_time', 0)
    funding_data['date'] = datetime.fromtimestamp(block_time, tz=timezone.utc).isoformat() if block_time else None
    
    print(f"  Inputs: {funding_data['num_inputs']}")
    print(f"  Outputs: {funding_data['num_outputs']}")
    print(f"  Block: {funding_data['block_height']}")
    print(f"  Date: {funding_data['date']}")
    
    if funding_data['num_outputs'] == 256:
        print(f"  ✓ Confirmed 256 outputs (P1-P256)")
    else:
        print(f"  ⚠ Expected 256 outputs, got {funding_data['num_outputs']}")
    
    # Get upstream TX info
    if tx_info.get('vin'):
        upstream_txid = tx_info['vin'][0].get('txid', '')
        upstream_vout = tx_info['vin'][0].get('vout', 0)
        funding_data['upstream_txid'] = upstream_txid
        funding_data['upstream_vout'] = upstream_vout
        print(f"  Upstream TX: {upstream_txid}")
        
        # Validate the partial hash from skill
        if upstream_txid.startswith('9b11b90a'):
            print(f"  ✓ Upstream TX matches skill partial hash '9b11b90a...'")
        else:
            print(f"  ⚠ Upstream TX does NOT start with '9b11b90a' — skill has wrong partial hash")
            funding_data['upstream_partial_mismatch'] = True
    
    # Extract scriptSig and validate signature
    if tx_info.get('vin'):
        scriptsig = tx_info['vin'][0].get('scriptsig', '')
        if scriptsig:
            sig = parse_der_signature(scriptsig)
            if 'error' not in sig:
                funding_data['signature'] = sig
                funding_data['pubkey_from_sig'] = sig['pubkey']
                
                if sig['pubkey'].lower() == CREATOR_PUBKEY.lower():
                    print(f"  ✓ Creator pubkey matches")
                else:
                    print(f"  ⚠ Creator pubkey MISMATCH!")
    
    # Get fee
    total_in = sum(vin.get('prevout', {}).get('value', 0) for vin in tx_info.get('vin', []))
    total_out = sum(vout.get('value', 0) for vout in tx_info.get('vout', []))
    funding_data['total_input_sat'] = total_in
    funding_data['total_output_sat'] = total_out
    funding_data['fee_sat'] = total_in - total_out
    
    print(f"  Total input: {total_in} sat ({total_in/1e8:.8f} BTC)")
    print(f"  Total output: {total_out} sat ({total_out/1e8:.8f} BTC)")
    print(f"  Fee: {funding_data['fee_sat']} sat")
    
    return funding_data

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  Bitcoin Puzzle Blockchain Forensics — Data Fetcher v1.0    ║")
    print("║  Fetching & validating all skill parameters                 ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  API: {API_PRIMARY}")
    print(f"  Delay: {REQUEST_DELAY}s between requests")
    print(f"  Puzzles to process: {len(EXPOSURE_PUZZLES)}")
    print(f"  Solved keys available: {len(SOLVED_KEYS)}")
    print()
    
    results = {
        'metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'api_used': API_PRIMARY,
            'script_version': '1.0',
            'total_puzzles': len(EXPOSURE_PUZZLES),
            'solved_puzzles': len(SOLVED_KEYS),
        },
        'puzzles': {},
        'p71_data': None,
        'creator_funding': None,
        'validations': None,
        'nonce_analysis': None,
        'known_discrepancies': SKILL_DISCREPANCIES,
    }
    
    # Phase 0: Validate existing data
    results['validations'] = validate_existing_data(results)
    
    # Phase 1: Validate creator funding TX
    results['creator_funding'] = validate_creator_funding_tx()
    
    # Phase 2: Fetch P71 data
    results['p71_data'] = fetch_p71_data()
    
    # Phase 3: Process each exposure puzzle
    total = len(EXPOSURE_PUZZLES)
    for idx, (pnum, addr) in enumerate(sorted(EXPOSURE_PUZZLES.items()), 1):
        print(f"\n  [{idx}/{total}] ", end="")
        try:
            puzzle_result = process_puzzle(pnum, addr, results)
            results['puzzles'][str(pnum)] = puzzle_result
        except Exception as e:
            print(f"\n  ✗ EXCEPTION processing P{pnum}: {e}")
            results['puzzles'][str(pnum)] = {
                'puzzle_number': pnum,
                'address': addr,
                'error': str(e),
            }
        
        # Save intermediate results every 5 puzzles
        if idx % 5 == 0:
            print(f"\n  💾 Saving intermediate results...")
            save_results(results, 'forensics_results_partial.json')
    
    # Phase 4: Nonce pattern analysis
    print(f"\n{'='*60}")
    print(f"  Performing nonce pattern analysis...")
    print(f"{'='*60}")
    results['nonce_analysis'] = analyze_nonces(results)
    
    # Phase 5: Generate summary
    results['summary'] = generate_summary(results)
    
    # Save final results
    output_file = 'forensics_results.json'
    save_results(results, output_file)
    
    print(f"\n╔══════════════════════════════════════════════════════════════╗")
    print(f"║  COMPLETE! Results saved to: {output_file:<30s} ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    
    # Print summary
    print_summary(results)


def save_results(results, filename):
    """Save results to JSON, handling large integers."""
    
    def json_serializer(obj):
        if isinstance(obj, int) and obj > 2**53:
            return f"0x{obj:x}"
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=json_serializer)


def generate_summary(results):
    """Generate a human-readable summary of all findings."""
    summary = {
        'exposure_txs_found': 0,
        'exposure_txs_missing': [],
        'signatures_extracted': 0,
        'sighash_computed': 0,
        'nonces_recovered': 0,
        'nonces_verified': 0,
        'pubkey_mismatches': [],
        'key_range_errors': [],
        'data_issues': [],
    }
    
    for pnum_str, data in results['puzzles'].items():
        pnum = int(pnum_str)
        
        if data.get('exposure_tx') and data['exposure_tx'].get('txid'):
            summary['exposure_txs_found'] += 1
        else:
            summary['exposure_txs_missing'].append(pnum)
        
        if data.get('signature_data') and 'error' not in data['signature_data']:
            summary['signatures_extracted'] += 1
        
        if data.get('sighash_z'):
            summary['sighash_computed'] += 1
        
        if data.get('recovered_nonce'):
            summary['nonces_recovered'] += 1
        
        if data.get('nonce_verified'):
            summary['nonces_verified'] += 1
        
        if data.get('pubkey_match') == False:
            summary['pubkey_mismatches'].append(pnum)
        
        if data.get('errors'):
            for err in data['errors']:
                summary['data_issues'].append(f"P{pnum}: {err}")
    
    # Check validations
    if results.get('validations'):
        for key, val in results['validations'].get('key_validations', {}).items():
            if not val.get('in_bit_range'):
                summary['key_range_errors'].append(key)
    
    return summary


def print_summary(results):
    """Print a nice summary to console."""
    s = results.get('summary', {})
    
    print(f"\n{'='*60}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  Exposure TXs found:     {s.get('exposure_txs_found', 0)} / {len(EXPOSURE_PUZZLES)}")
    print(f"  Signatures extracted:   {s.get('signatures_extracted', 0)}")
    print(f"  SIGHASH z computed:     {s.get('sighash_computed', 0)}")
    print(f"  Nonces recovered:       {s.get('nonces_recovered', 0)}")
    print(f"  Nonces verified:        {s.get('nonces_verified', 0)}")
    
    if s.get('exposure_txs_missing'):
        print(f"\n  Missing exposure TXs: {s['exposure_txs_missing']}")
    
    if s.get('pubkey_mismatches'):
        print(f"\n  ⚠ PubKey mismatches: {s['pubkey_mismatches']}")
    
    if s.get('key_range_errors'):
        print(f"\n  ⚠ Key range errors: {s['key_range_errors']}")
    
    if s.get('data_issues'):
        print(f"\n  Data issues:")
        for issue in s['data_issues'][:20]:
            print(f"    - {issue}")
    
    # P71 info
    p71 = results.get('p71_data', {})
    if p71:
        print(f"\n  P71 Balance: {p71.get('balance_btc', '?')} BTC")
        print(f"  P71 Public Key: {p71.get('public_key', 'NOT EXPOSED')}")
    
    # Nonce analysis
    na = results.get('nonce_analysis', {})
    if na and na.get('count', 0) > 0:
        print(f"\n  Nonce Analysis ({na['count']} nonces):")
        for obs in na.get('preliminary_observations', []):
            print(f"    → {obs}")
    
    # Known discrepancies
    print(f"\n  Known Skill Discrepancies:")
    for key, disc in SKILL_DISCREPANCIES.items():
        print(f"    {key}:")
        print(f"      Wrong:   {disc['wrong_value'][:60]}")
        print(f"      Correct: {disc['correct_value'][:60]}")
    
    print(f"\n  📁 Upload 'forensics_results.json' to Claude for skill update!")


if __name__ == '__main__':
    main()
