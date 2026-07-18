#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  SIGHASH RECOMPUTATION & RFC 6979 VERIFICATION                         ║
║                                                                          ║
║  This script:                                                            ║
║    1. Fetches the raw exposure TX (17e4e323...) from blockchain APIs     ║
║    2. Strips signatures to reconstruct unsigned TX per input             ║
║    3. Computes SIGHASH_ALL (double-SHA256) for each of 21 inputs        ║
║    4. Recovers nonces k from known private keys                          ║
║    5. Checks RFC 6979 compliance for all 14 solved puzzles              ║
║    6. Saves complete results to JSON for upload back to Claude           ║
║                                                                          ║
║  Requirements: pip install requests                                      ║
║  Usage: python verify_sighash_rfc6979.py                                ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
import hmac
import json
import struct
import sys
import time
from io import BytesIO

# ═══════════════════════════════════════════════════════════════════════
# Try to import requests; give helpful error if missing
# ═══════════════════════════════════════════════════════════════════════
try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed.")
    print("Install it with: pip install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

EXPOSURE_TXID = "17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3"

# secp256k1 curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Known private keys for solved puzzles (input_index -> private_key)
# Input ordering: P65=0, P70=1, P75=2, P80=3, P85=4, P90=5, P95=6,
#                 P100=7, P105=8, P110=9, P115=10, P120=11, P125=12,
#                 P130=13, P135=14(unsolved), P140=15, P145=16,
#                 P150=17, P155=18, P160=19, funding=20
KNOWN_KEYS = {
    0:  (65,  0x1a838b13505b26867),
    1:  (70,  0x349b84b6431a6c4ef1),
    2:  (75,  0x4c5ce114686a1336e07),
    3:  (80,  0xea1a5c66dcc11b5ad180),
    4:  (85,  0x11720c4f018d51b8cebba8),
    5:  (90,  0x2ce00bb2136a445c71e85bf),
    6:  (95,  0x527a792b183c7f64a0e8b1f4),
    7:  (100, 0xaf55fc59c335c8ec67ed24826),
    8:  (105, 0x16f14fc2054cd87ee6396b33df3),
    9:  (110, 0x35c0d7234df7deb0f20cf7062444),
    10: (115, 0x60f4d11574f5deee49961d9609ac6),
    11: (120, 0xb10f22572c497a836ea187f2e1fc23),
    12: (125, 0x1c533b6bb7f0804e09960225e44877ac),
    13: (130, 0x33e7665705359f04f28b88cf897c603c9),
    # 14-19: unsolved (P135-P160), 20: funding key (unknown)
}

# Previously recovered nonces (for cross-verification)
KNOWN_NONCES = {
    0:  0x68592d1aa72720ae7333beb3bd9d6a8e69c0567fb91720318c6289d48227c05d,
    1:  0x79577177c7a329a48d26bcf81b5db9e88b458bf8e76665f3a9ff4ab4f0cad08e,
    2:  0x123503c481722a0b4161fc681b8c786425664c102101a649d665ca788da72e7f,
    3:  0x93c7e4ce32301e1676eeef686e851d3b84a0174f7e9f0c523df966c96a24e886,
    4:  0x18fbd62747eb6a108af69ae775878af10075590fc534036710c2cb6121a24710,
    5:  0x0640c641a09b8b28b721f3c861916de8eb1fab230ad5fa33dd0e03739b4936c9,
    6:  0xb3591ed9fac56c96f20f13646c6d4a4371c1c34db9126ee203d9ecb823c46930,
    7:  0x1ac46997d73e24a7167fa8b9825927cb59d23528c69328ce71de3087a8c79c1f,
    8:  0x0129543698812c5d61918bddd6b24712b0d757aecba20a21c7971a3b652142af,
    9:  0xcaf9bf64e2440011a0c52746068da91cb7f9b1e20b0a4ac0816babbb85c4bcba,
    10: 0x9dd8dc8f8073f11e60ac3dd7a371313c847366b5dff74f46c9fac279eb3a2fea,
    11: 0x1e0283128ecdd93e9f8fa5b63841bacb2da3338f9178e36e29a13d534c1bd9fb,
    12: 0x8edf4133b6490e274b8caa8e14ffa139df1b919f785d988dc54b268f0fc98ca2,
    13: 0x48b29e355781af91077b51c2a572561c0c99a6b8a8d439fd3bf287bc8d8f19b2,
}

# ═══════════════════════════════════════════════════════════════════════
# BITCOIN SERIALIZATION HELPERS
# ═══════════════════════════════════════════════════════════════════════

def read_varint(stream):
    """Read a Bitcoin varint from a byte stream."""
    b = stream.read(1)[0]
    if b < 0xfd:
        return b
    elif b == 0xfd:
        return struct.unpack('<H', stream.read(2))[0]
    elif b == 0xfe:
        return struct.unpack('<I', stream.read(4))[0]
    else:
        return struct.unpack('<Q', stream.read(8))[0]


def write_varint(val):
    """Encode a Bitcoin varint."""
    if val < 0xfd:
        return bytes([val])
    elif val <= 0xffff:
        return b'\xfd' + struct.pack('<H', val)
    elif val <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', val)
    else:
        return b'\xff' + struct.pack('<Q', val)


def read_bytes(stream, n):
    """Read exactly n bytes from stream."""
    data = stream.read(n)
    if len(data) != n:
        raise ValueError(f"Expected {n} bytes, got {len(data)}")
    return data


def double_sha256(data):
    """Bitcoin's standard double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_der_signature(scriptsig_bytes):
    """
    Parse a DER-encoded ECDSA signature from a P2PKH scriptSig.
    Returns (r, s, sighash_type, pubkey_bytes).
    """
    stream = BytesIO(scriptsig_bytes)
    
    # Read signature push length
    sig_push_len = stream.read(1)[0]
    sig_data = stream.read(sig_push_len)
    
    # Last byte of sig_data is sighash type
    sighash_type = sig_data[-1]
    der_sig = sig_data[:-1]
    
    # Parse DER: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    if der_sig[0] != 0x30:
        raise ValueError(f"Expected 0x30, got 0x{der_sig[0]:02x}")
    
    der_len = der_sig[1]
    idx = 2
    
    if der_sig[idx] != 0x02:
        raise ValueError(f"Expected 0x02 for r, got 0x{der_sig[idx]:02x}")
    idx += 1
    
    r_len = der_sig[idx]
    idx += 1
    r_bytes = der_sig[idx:idx+r_len]
    r = int.from_bytes(r_bytes, 'big')
    idx += r_len
    
    if der_sig[idx] != 0x02:
        raise ValueError(f"Expected 0x02 for s, got 0x{der_sig[idx]:02x}")
    idx += 1
    
    s_len = der_sig[idx]
    idx += 1
    s_bytes = der_sig[idx:idx+s_len]
    s = int.from_bytes(s_bytes, 'big')
    
    # Read pubkey push
    pubkey_push_len = stream.read(1)[0]
    pubkey = stream.read(pubkey_push_len)
    
    return r, s, sighash_type, pubkey


def get_p2pkh_scriptpubkey(pubkey_bytes):
    """
    Build P2PKH scriptPubKey from a compressed public key.
    OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    # Hash160 = RIPEMD160(SHA256(pubkey))
    sha = hashlib.sha256(pubkey_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    return b'\x76\xa9\x14' + h160 + b'\x88\xac'


# ═══════════════════════════════════════════════════════════════════════
# TRANSACTION PARSING
# ═══════════════════════════════════════════════════════════════════════

class TxInput:
    def __init__(self):
        self.prev_txid = b''      # 32 bytes, little-endian
        self.prev_vout = 0        # 4 bytes
        self.scriptsig = b''      # variable
        self.sequence = 0         # 4 bytes
        # Parsed from scriptsig:
        self.r = 0
        self.s = 0
        self.sighash_type = 0
        self.pubkey = b''


class TxOutput:
    def __init__(self):
        self.value = 0            # 8 bytes (satoshis)
        self.scriptpubkey = b''   # variable


class Transaction:
    def __init__(self):
        self.version = 0
        self.inputs = []
        self.outputs = []
        self.locktime = 0
        self.raw_hex = ""
    
    @classmethod
    def from_hex(cls, hex_string):
        """Parse a raw transaction from hex."""
        tx = cls()
        tx.raw_hex = hex_string
        raw = bytes.fromhex(hex_string)
        stream = BytesIO(raw)
        
        # Version (4 bytes LE)
        tx.version = struct.unpack('<I', read_bytes(stream, 4))[0]
        
        # Number of inputs
        num_inputs = read_varint(stream)
        
        for i in range(num_inputs):
            inp = TxInput()
            inp.prev_txid = read_bytes(stream, 32)
            inp.prev_vout = struct.unpack('<I', read_bytes(stream, 4))[0]
            scriptsig_len = read_varint(stream)
            inp.scriptsig = read_bytes(stream, scriptsig_len)
            inp.sequence = struct.unpack('<I', read_bytes(stream, 4))[0]
            
            # Parse the DER signature
            try:
                inp.r, inp.s, inp.sighash_type, inp.pubkey = parse_der_signature(inp.scriptsig)
            except Exception as e:
                print(f"  WARNING: Could not parse signature for input {i}: {e}")
            
            tx.inputs.append(inp)
        
        # Number of outputs
        num_outputs = read_varint(stream)
        
        for i in range(num_outputs):
            out = TxOutput()
            out.value = struct.unpack('<Q', read_bytes(stream, 8))[0]
            scriptpubkey_len = read_varint(stream)
            out.scriptpubkey = read_bytes(stream, scriptpubkey_len)
            tx.outputs.append(out)
        
        # Locktime (4 bytes LE)
        tx.locktime = struct.unpack('<I', read_bytes(stream, 4))[0]
        
        return tx
    
    def compute_sighash(self, input_index, prev_scriptpubkey, sighash_type=1):
        """
        Compute the SIGHASH for a specific input (SIGHASH_ALL).
        
        For SIGHASH_ALL:
        1. Copy the transaction
        2. Clear all input scriptSigs
        3. Set the current input's scriptSig to the previous output's scriptPubKey
        4. Append sighash type as 4-byte LE
        5. Double-SHA256 the serialized result
        """
        # Serialize: version
        result = struct.pack('<I', self.version)
        
        # Number of inputs
        result += write_varint(len(self.inputs))
        
        for i, inp in enumerate(self.inputs):
            # Previous output hash (32 bytes)
            result += inp.prev_txid
            # Previous output index (4 bytes)
            result += struct.pack('<I', inp.prev_vout)
            
            if i == input_index:
                # Current input: use previous output's scriptPubKey
                result += write_varint(len(prev_scriptpubkey))
                result += prev_scriptpubkey
            else:
                # Other inputs: empty scriptSig
                result += write_varint(0)
            
            # Sequence
            result += struct.pack('<I', inp.sequence)
        
        # Number of outputs
        result += write_varint(len(self.outputs))
        
        for out in self.outputs:
            result += struct.pack('<Q', out.value)
            result += write_varint(len(out.scriptpubkey))
            result += out.scriptpubkey
        
        # Locktime
        result += struct.pack('<I', self.locktime)
        
        # Append sighash type as 4-byte little-endian
        result += struct.pack('<I', sighash_type)
        
        # Double SHA-256
        sighash = double_sha256(result)
        return sighash


# ═══════════════════════════════════════════════════════════════════════
# RFC 6979 IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════

def rfc6979_generate_k(private_key_int, msg_hash_int, curve_order):
    """
    Generate deterministic nonce k per RFC 6979 using HMAC-SHA256.
    Private key is always encoded as 32 bytes (secp256k1 standard).
    """
    # int2octets: private key as 32 bytes
    x = private_key_int.to_bytes(32, 'big')
    # bits2octets: message hash as 32 bytes
    h1 = msg_hash_int.to_bytes(32, 'big')
    
    # Step b: V = 0x01 * 32
    V = b'\x01' * 32
    # Step c: K = 0x00 * 32
    K = b'\x00' * 32
    # Step d
    K = hmac.new(K, V + b'\x00' + x + h1, hashlib.sha256).digest()
    # Step e
    V = hmac.new(K, V, hashlib.sha256).digest()
    # Step f
    K = hmac.new(K, V + b'\x01' + x + h1, hashlib.sha256).digest()
    # Step g
    V = hmac.new(K, V, hashlib.sha256).digest()
    
    # Step h: generate candidates
    while True:
        T = b''
        while len(T) < 32:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = int.from_bytes(T[:32], 'big')
        if 1 <= k < curve_order:
            return k
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


# ═══════════════════════════════════════════════════════════════════════
# FETCH RAW TRANSACTION
# ═══════════════════════════════════════════════════════════════════════

def fetch_raw_tx(txid):
    """
    Fetch raw transaction hex from multiple API sources.
    Tries several APIs in order of reliability.
    """
    apis = [
        {
            'name': 'blockstream.info',
            'url': f'https://blockstream.info/api/tx/{txid}/hex',
            'type': 'text',
        },
        {
            'name': 'mempool.space',
            'url': f'https://mempool.space/api/tx/{txid}/hex',
            'type': 'text',
        },
        {
            'name': 'blockchain.info',
            'url': f'https://blockchain.info/rawtx/{txid}?format=hex',
            'type': 'text',
        },
        {
            'name': 'blockcypher.com',
            'url': f'https://api.blockcypher.com/v1/btc/main/txs/{txid}?includeHex=true',
            'type': 'json',
            'key': 'hex',
        },
    ]
    
    for api in apis:
        try:
            print(f"  Trying {api['name']}...", end=' ', flush=True)
            resp = requests.get(api['url'], timeout=30)
            if resp.status_code == 200:
                if api['type'] == 'text':
                    raw_hex = resp.text.strip()
                else:
                    raw_hex = resp.json()[api['key']]
                
                # Validate: should be hex and reasonable length
                if len(raw_hex) > 100 and all(c in '0123456789abcdef' for c in raw_hex.lower()):
                    print(f"OK ({len(raw_hex)//2} bytes)")
                    return raw_hex.lower()
                else:
                    print(f"Invalid response (len={len(raw_hex)})")
            else:
                print(f"HTTP {resp.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(1)  # Be nice to APIs
    
    return None


# ═══════════════════════════════════════════════════════════════════════
# NONCE RECOVERY
# ═══════════════════════════════════════════════════════════════════════

def recover_nonce(z_int, r, s, private_key, order):
    """
    Recover ECDSA nonce k from known private key.
    k = (z + r * K) * s^{-1} mod n
    """
    s_inv = pow(s, -1, order)
    k = ((z_int + r * private_key) * s_inv) % order
    return k


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("  SIGHASH RECOMPUTATION & RFC 6979 VERIFICATION")
    print("  Exposure TX: 17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3")
    print("=" * 80)
    print()
    
    # ─── Step 1: Fetch raw transaction ───
    print("━━ Step 1: Fetching raw transaction hex ━━")
    print()
    
    raw_hex = fetch_raw_tx(EXPOSURE_TXID)
    
    if raw_hex is None:
        print()
        print("  ERROR: Could not fetch raw transaction from any API.")
        print("  Please manually provide the raw TX hex.")
        print()
        print("  You can get it from:")
        print("    https://blockstream.info/api/tx/17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3/hex")
        print()
        print("  Then paste it into a file called 'raw_tx.hex' and re-run this script.")
        
        # Try to read from file
        try:
            with open('raw_tx.hex', 'r') as f:
                raw_hex = f.read().strip().lower()
            print(f"  Found raw_tx.hex file ({len(raw_hex)//2} bytes)")
        except FileNotFoundError:
            sys.exit(1)
    
    # Save raw hex for reference
    with open('raw_tx.hex', 'w') as f:
        f.write(raw_hex)
    print(f"  Saved raw TX hex to raw_tx.hex ({len(raw_hex)//2} bytes)")
    print()
    
    # ─── Step 2: Parse transaction ───
    print("━━ Step 2: Parsing transaction ━━")
    print()
    
    tx = Transaction.from_hex(raw_hex)
    print(f"  Version:  {tx.version}")
    print(f"  Inputs:   {len(tx.inputs)}")
    print(f"  Outputs:  {len(tx.outputs)}")
    print(f"  Locktime: {tx.locktime}")
    print()
    
    if len(tx.inputs) != 21:
        print(f"  WARNING: Expected 21 inputs, got {len(tx.inputs)}")
    
    # Verify output
    for i, out in enumerate(tx.outputs):
        print(f"  Output {i}: {out.value} sat, scriptPubKey={out.scriptpubkey.hex()}")
    print()
    
    # ─── Step 3: Extract signatures and compute SIGHASH for each input ───
    print("━━ Step 3: Computing SIGHASH for each input ━━")
    print()
    
    results = {}
    
    for idx in range(len(tx.inputs)):
        inp = tx.inputs[idx]
        
        # The previous output's scriptPubKey = P2PKH of this input's pubkey
        if len(inp.pubkey) == 0:
            print(f"  Input {idx:2d}: SKIPPED (no pubkey parsed)")
            continue
        
        prev_scriptpubkey = get_p2pkh_scriptpubkey(inp.pubkey)
        
        # Compute SIGHASH_ALL
        sighash_bytes = tx.compute_sighash(idx, prev_scriptpubkey, inp.sighash_type)
        z = int.from_bytes(sighash_bytes, 'big')
        
        result = {
            'input_index': idx,
            'pubkey': inp.pubkey.hex(),
            'r': hex(inp.r),
            's': hex(inp.s),
            'sighash_type': inp.sighash_type,
            'z_hex': hex(z),
            'z_bits': z.bit_length(),
            'r_bits': inp.r.bit_length(),
            's_bits': inp.s.bit_length(),
        }
        
        # If we have the private key, recover nonce and check RFC 6979
        if idx in KNOWN_KEYS:
            puzzle_num, priv_key = KNOWN_KEYS[idx]
            result['puzzle_num'] = puzzle_num
            result['private_key'] = hex(priv_key)
            
            # Recover nonce
            k = recover_nonce(z, inp.r, inp.s, priv_key, N)
            result['recovered_k'] = hex(k)
            result['k_bits'] = k.bit_length()
            
            # Cross-check with previously known nonce
            if idx in KNOWN_NONCES:
                old_k = KNOWN_NONCES[idx]
                result['old_k'] = hex(old_k)
                result['k_matches_old'] = (k == old_k)
            
            # Check RFC 6979
            k_rfc = rfc6979_generate_k(priv_key, z, N)
            result['rfc6979_k'] = hex(k_rfc)
            result['rfc6979_match'] = (k == k_rfc)
            
            # Print result
            rfc_status = "✅ RFC6979" if k == k_rfc else "❌ NOT RFC6979"
            old_status = ""
            if idx in KNOWN_NONCES:
                old_status = " | k_changed!" if k != KNOWN_NONCES[idx] else " | k_same"
            
            print(f"  Input {idx:2d} (P{puzzle_num:3d}): z=0x{z:064x}")
            print(f"           k=0x{k:064x}")
            print(f"           {rfc_status}{old_status}")
        else:
            # Unsolved puzzle or funding input
            label = f"P{65 + idx*5}" if idx < 20 else "funding"
            print(f"  Input {idx:2d} ({label:8s}): z=0x{z:064x}")
            print(f"           r=0x{inp.r:064x}")
            print(f"           s=0x{inp.s:064x}")
            result['label'] = label
        
        results[str(idx)] = result
        print()
    
    # ─── Step 4: Summary ───
    print("━━ Step 4: Summary ━━")
    print()
    
    rfc_total = 0
    rfc_match = 0
    z_changed = 0
    
    for idx_str, res in results.items():
        if 'rfc6979_match' in res:
            rfc_total += 1
            if res['rfc6979_match']:
                rfc_match += 1
        if 'k_matches_old' in res and not res['k_matches_old']:
            z_changed += 1
    
    print(f"  RFC 6979 compliance: {rfc_match}/{rfc_total}")
    print(f"  Nonces changed from previous computation: {z_changed}")
    print()
    
    if rfc_match == rfc_total:
        print("  ╔═══════════════════════════════════════════════════════════╗")
        print("  ║  ALL nonces match RFC 6979!                              ║")
        print("  ║  Previous z values were incorrect.                       ║")
        print("  ║  Creator used compliant deterministic nonce generation.  ║")
        print("  ║  FORENSICS NONCE ATTACK: CLOSED (no weakness).          ║")
        print("  ╚═══════════════════════════════════════════════════════════╝")
    elif rfc_match == 0:
        print("  ╔═══════════════════════════════════════════════════════════╗")
        print("  ║  NO nonces match RFC 6979!                               ║")
        print("  ║  Creator used non-deterministic (random) nonce RNG.     ║")
        print("  ║  PROCEED TO: HNP lattice / Polynonce / PRNG analysis.   ║")
        print("  ╚═══════════════════════════════════════════════════════════╝")
    else:
        print(f"  ╔═══════════════════════════════════════════════════════════╗")
        print(f"  ║  MIXED: {rfc_match}/{rfc_total} match RFC 6979.                         ║")
        print(f"  ║  This is unusual — investigate further.                  ║")
        print(f"  ╚═══════════════════════════════════════════════════════════╝")
    
    print()
    
    # ─── Step 5: Save results ───
    output_file = "sighash_rfc6979_results.json"
    
    # Add metadata
    output = {
        'metadata': {
            'txid': EXPOSURE_TXID,
            'tx_version': tx.version,
            'num_inputs': len(tx.inputs),
            'num_outputs': len(tx.outputs),
            'locktime': tx.locktime,
            'raw_hex_length': len(raw_hex) // 2,
            'rfc6979_matches': rfc_match,
            'rfc6979_total': rfc_total,
            'z_values_changed': z_changed,
        },
        'inputs': results,
    }
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"  Results saved to: {output_file}")
    print(f"  Upload this file back to Claude for analysis.")
    print()
    print("=" * 80)
    print("  DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
