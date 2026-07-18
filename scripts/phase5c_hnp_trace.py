#!/usr/bin/env python3
"""
Phase 5C: HNP LATTICE ATTACK & ADDRESS TRACING
================================================
With 151 ECDSA signatures from the same private key (173ujr... wallet),
we attempt a Hidden Number Problem lattice attack to recover the key.

Additionally, traces the co-output addresses from the upstream TX
and searches for the 2023 top-up transaction.

Usage: python3 phase5c_hnp_trace.py
Output: phase5c_results.txt

Requirements: pip install requests
Optional: pip install fpylll (for actual lattice reduction)
"""

import json
import hashlib
import struct
import sys
import os
from datetime import datetime

OUTPUT_FILE = "phase5c_results.txt"
output_lines = []

def out(line=""):
    print(line)
    output_lines.append(line)

def save_output():
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    print(f"\n[+] Results saved to: {os.path.abspath(OUTPUT_FILE)}")

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

UPSTREAM_WALLET = '173ujrhEVGqaZvPHXLqwXiSmPVMo225cqT'
UPSTREAM_PUBKEY = '031c24239a829a89d7e1'  # First 20 hex chars from results
FUNDING_TXID = '08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15'
UPSTREAM_FUNDING_TXID = '9b11b90a212c27c982013bafe1d4a0730e01357245f0d074051a988e4bba1662'

# Co-output addresses from the upstream TX
CO_OUTPUT_ADDRESSES = {
    '1Aru8MzMVyWHxdCXN1p7e66jLKHCFUu3ZM': 150_000_000,   # 1.5 BTC
    '19gpJ5ry1EDppuvP9Hi43x4EX89stj8U77': 200_000_000,    # 2.0 BTC
    '3NTKgoHrYuktTXczxYfhLifTzfuNKcEc9B': 10_000_000_000, # 100 BTC (P2SH!)
}

# Puzzle addresses for top-up search
PUZZLE_ADDRESSES = {
    66: '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so',
    67: '1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9',
    68: '1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ',
    69: '19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG',
    70: '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR',
    71: '1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU',
    72: '1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR',
    73: '12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4',
    74: '1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv',
    75: '1J36UjUByGroXcCvmj13U6uwaVv9caEeAt',
    130: '1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua',
    135: '16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v',
    160: '1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv',
}

# ============================================================
# API HELPERS
# ============================================================

def api_get(url, timeout=20):
    import requests
    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        out(f"    [!] {str(e)[:80]}")
    return None

def api_get_text(url, timeout=20):
    import requests
    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            return resp.text.strip()
    except:
        pass
    return None

def parse_scriptsig(hex_data):
    data = bytes.fromhex(hex_data)
    idx = 0
    elements = []
    while idx < len(data):
        op = data[idx]; idx += 1
        if 1 <= op <= 75:
            elements.append(data[idx:idx+op]); idx += op
        elif op == 76:
            length = data[idx]; idx += 1
            elements.append(data[idx:idx+length]); idx += length
        elif op == 77:
            length = int.from_bytes(data[idx:idx+2], 'little'); idx += 2
            elements.append(data[idx:idx+length]); idx += length
        else:
            break
    return elements

def parse_der(sig_bytes):
    try:
        idx = 0
        if sig_bytes[idx] != 0x30: return None, None
        idx += 2
        assert sig_bytes[idx] == 0x02; idx += 1
        r_len = sig_bytes[idx]; idx += 1
        r = int.from_bytes(sig_bytes[idx:idx+r_len], 'big'); idx += r_len
        assert sig_bytes[idx] == 0x02; idx += 1
        s_len = sig_bytes[idx]; idx += 1
        s = int.from_bytes(sig_bytes[idx:idx+s_len], 'big')
        return r, s
    except:
        return None, None

def fetch_address_txs(address, max_pages=5):
    all_txs = []
    last_txid = None
    import time
    for page in range(max_pages):
        url = f"https://mempool.space/api/address/{address}/txs"
        if last_txid:
            url += f"/chain/{last_txid}"
        data = api_get(url)
        if not data or len(data) == 0:
            break
        all_txs.extend(data)
        last_txid = data[-1]['txid']
        if len(data) < 25:
            break
        time.sleep(0.5)
    return all_txs

# ============================================================
# SECTION 1: EXTRACT FULL SIGNATURE DATA FOR HNP
# ============================================================

def extract_full_signatures():
    out(f"\n{'='*78}")
    out(f"  1. EXTRACTING FULL SIGNATURE DATA FOR HNP ATTACK")
    out(f"{'='*78}")
    
    out(f"\n  Fetching TXs from {UPSTREAM_WALLET[:20]}...")
    out(f"  Need: (r, s, z) tuples where z = message hash")
    out(f"  For ECDSA: s = k^(-1) * (z + r*d) mod n")
    out(f"  HNP approach: given (r_i, s_i, z_i), find d such that")
    out(f"    k_i = s_i^(-1) * (z_i + r_i * d) mod n")
    out(f"  If k_i has biased bits, lattice reduction can recover d.")
    
    txs = fetch_address_txs(UPSTREAM_WALLET, max_pages=8)
    out(f"  Retrieved {len(txs)} transactions")
    
    sig_data = []  # (r, s, z, txid, vin_idx)
    
    for tx in txs:
        txid = tx['txid']
        
        # We need the raw TX hex to compute z (sighash)
        # For now, extract r, s from each input that spends from our address
        for vin_idx, vin in enumerate(tx.get('vin', [])):
            prevout = vin.get('prevout', {})
            if prevout.get('scriptpubkey_address') != UPSTREAM_WALLET:
                continue
            
            scriptsig = vin.get('scriptsig', '')
            if not scriptsig:
                continue
            
            elems = parse_scriptsig(scriptsig)
            if len(elems) < 2:
                continue
            
            sig_bytes = elems[0]
            sighash_type = sig_bytes[-1]
            r, s = parse_der(sig_bytes[:-1])
            pk_hex = elems[1].hex()
            
            if r and s:
                sig_data.append({
                    'txid': txid,
                    'vin_idx': vin_idx,
                    'r': r,
                    's': s,
                    'sighash_type': sighash_type,
                    'pubkey': pk_hex,
                    'r_bits': r.bit_length(),
                    's_bits': s.bit_length(),
                })
    
    out(f"  Extracted {len(sig_data)} total signatures")
    
    # Verify all from same pubkey
    pubkeys = set(s['pubkey'] for s in sig_data)
    out(f"  Unique public keys: {len(pubkeys)}")
    for pk in pubkeys:
        count = sum(1 for s in sig_data if s['pubkey'] == pk)
        out(f"    {pk[:40]}... ({count} signatures)")
    
    return sig_data

# ============================================================
# SECTION 2: NONCE BIAS DETECTION
# ============================================================

def detect_nonce_bias(sig_data):
    out(f"\n{'='*78}")
    out(f"  2. NONCE BIAS DETECTION (MSB/LSB Analysis)")
    out(f"{'='*78}")
    
    out(f"""
  For HNP to work, we need BIASED nonces. RFC 6979 produces
  uniformly random-looking nonces, BUT:
  
  1. Pre-v0.10 Bitcoin Core used OpenSSL which had known nonce biases
  2. Some implementations leak bits through timing
  3. Buggy implementations might truncate or zero-pad nonces
  
  We analyze the r-values (which are derived from k*G, so r = (k*G).x mod n)
  to detect statistical anomalies in the nonce distribution.
""")
    
    if not sig_data:
        out(f"  No signature data available.")
        return
    
    r_values = [s['r'] for s in sig_data]
    s_values = [s['s'] for s in sig_data]
    
    # Test 1: r-value bit length distribution
    r_bits = [r.bit_length() for r in r_values]
    s_bits = [s.bit_length() for s in s_values]
    
    out(f"  Test 1: Bit length distribution")
    out(f"    r-value bits: min={min(r_bits)}, max={max(r_bits)}, mean={sum(r_bits)/len(r_bits):.1f}")
    out(f"    s-value bits: min={min(s_bits)}, max={max(s_bits)}, mean={sum(s_bits)/len(s_bits):.1f}")
    
    # Distribution of r bit lengths
    from collections import Counter
    r_bit_dist = Counter(r_bits)
    out(f"\n    r-value bit length histogram:")
    for bits in sorted(r_bit_dist.keys()):
        count = r_bit_dist[bits]
        bar = '#' * min(count, 60)
        pct = count / len(r_bits) * 100
        out(f"      {bits:>3d} bits: {count:>4d} ({pct:5.1f}%) {bar}")
    
    s_bit_dist = Counter(s_bits)
    out(f"\n    s-value bit length histogram:")
    for bits in sorted(s_bit_dist.keys()):
        count = s_bit_dist[bits]
        bar = '#' * min(count, 60)
        pct = count / len(s_bits) * 100
        out(f"      {bits:>3d} bits: {count:>4d} ({pct:5.1f}%) {bar}")
    
    # Expected: for uniform 256-bit values, ~50% should be 256 bits, ~25% 255 bits, etc.
    expected_256 = len(r_values) * 0.5
    expected_255 = len(r_values) * 0.25
    expected_254 = len(r_values) * 0.125
    
    actual_256_r = r_bit_dist.get(256, 0)
    actual_255_r = r_bit_dist.get(255, 0)
    actual_254_r = r_bit_dist.get(254, 0)
    
    out(f"\n    Expected vs Actual (r-values, n={len(r_values)}):")
    out(f"      256 bits: expected={expected_256:.0f}, actual={actual_256_r}, "
        f"ratio={actual_256_r/expected_256:.3f}" if expected_256 > 0 else "")
    out(f"      255 bits: expected={expected_255:.0f}, actual={actual_255_r}, "
        f"ratio={actual_255_r/expected_255:.3f}" if expected_255 > 0 else "")
    out(f"      254 bits: expected={expected_254:.0f}, actual={actual_254_r}, "
        f"ratio={actual_254_r/expected_254:.3f}" if expected_254 > 0 else "")
    
    # Test 2: MSB bias (top 8 bits of r)
    out(f"\n  Test 2: MSB analysis (top byte of r-values)")
    msb_bytes = [(r >> 248) & 0xFF for r in r_values]
    msb_dist = Counter(msb_bytes)
    
    # For uniform distribution, each byte value should appear ~equal times
    # But r is really (k*G).x mod p, so it's not perfectly uniform
    out(f"    Top byte values seen: {len(msb_dist)} unique")
    out(f"    Most common: {msb_dist.most_common(5)}")
    out(f"    Least common: {msb_dist.most_common()[-5:]}")
    
    # Test 3: LSB bias (bottom 8 bits of r)
    out(f"\n  Test 3: LSB analysis (bottom byte of r-values)")
    lsb_bytes = [r & 0xFF for r in r_values]
    lsb_dist = Counter(lsb_bytes)
    
    # Check for even/odd bias
    even_count = sum(1 for r in r_values if r % 2 == 0)
    odd_count = len(r_values) - even_count
    out(f"    Even r-values: {even_count} ({even_count/len(r_values)*100:.1f}%)")
    out(f"    Odd r-values:  {odd_count} ({odd_count/len(r_values)*100:.1f}%)")
    out(f"    (Expected: ~50% each)")
    
    # Test 4: Check for small nonces (MSB zeros in k, which would show as
    # r-values in a specific range)
    out(f"\n  Test 4: Small nonce detection")
    small_r = sum(1 for r in r_values if r.bit_length() < 250)
    out(f"    r-values with < 250 bits: {small_r}/{len(r_values)}")
    out(f"    (Expected for uniform k: ~{len(r_values) * (1 - 2**250/2**256):.1f}, "
        f"i.e. nearly 0)")
    
    if small_r > 0:
        for s in sig_data:
            if s['r'].bit_length() < 250:
                out(f"    *** SMALL r: {s['r_bits']} bits in TX {s['txid'][:20]}...")
    
    # Test 5: Consecutive r-value difference analysis
    out(f"\n  Test 5: Sequential r-value correlation")
    if len(r_values) >= 2:
        diffs = []
        for i in range(len(r_values) - 1):
            diff = abs(r_values[i+1] - r_values[i])
            diff_bits = diff.bit_length()
            diffs.append(diff_bits)
        
        out(f"    |r[i+1] - r[i]| bit lengths: min={min(diffs)}, max={max(diffs)}, "
            f"mean={sum(diffs)/len(diffs):.1f}")
        out(f"    (Expected for independent values: ~255-256)")
    
    # Test 6: Check if r-values cluster (would indicate nonce reuse or correlation)
    out(f"\n  Test 6: r-value clustering (checking for values within 2^200)")
    clusters = 0
    for i in range(len(r_values)):
        for j in range(i+1, min(i+20, len(r_values))):
            if abs(r_values[i] - r_values[j]).bit_length() < 200:
                clusters += 1
                out(f"    CLUSTER: r[{i}] and r[{j}] differ by only "
                    f"{abs(r_values[i] - r_values[j]).bit_length()} bits!")
    if clusters == 0:
        out(f"    No clusters found (r-values appear independent)")
    
    # Test 7: s-value low-s check (all should be low-s for BIP 62)
    out(f"\n  Test 7: BIP 62 low-s verification")
    high_s_count = sum(1 for s in s_values if s > N // 2)
    out(f"    High-s values: {high_s_count}/{len(s_values)}")
    out(f"    (Expected for BIP 62 compliant: 0)")
    
    if high_s_count > 0:
        out(f"    *** HIGH-S VALUES FOUND — pre-BIP62 or non-standard signing! ***")
    
    # Summary assessment
    out(f"\n  BIAS ASSESSMENT SUMMARY:")
    bias_found = False
    
    if actual_256_r / max(expected_256, 1) < 0.7 or actual_256_r / max(expected_256, 1) > 1.3:
        out(f"    [!] r-value MSB distribution shows potential bias")
        bias_found = True
    
    if small_r > 2:
        out(f"    [!] Multiple small r-values detected — possible nonce truncation")
        bias_found = True
    
    if even_count / len(r_values) < 0.4 or even_count / len(r_values) > 0.6:
        out(f"    [!] Significant even/odd bias in r-values")
        bias_found = True
    
    if high_s_count > 0:
        out(f"    [!] Non-BIP62 signatures found — older/non-standard signing")
        bias_found = True
    
    if not bias_found:
        out(f"    No significant bias detected.")
        out(f"    Nonces appear cryptographically random (consistent with RFC 6979).")
        out(f"    HNP lattice attack is UNLIKELY to succeed without additional info.")
    else:
        out(f"    BIAS DETECTED — HNP lattice attack may be viable!")
        out(f"    Recommend: Extract full (r, s, z) tuples and run lattice reduction.")

# ============================================================
# SECTION 3: CO-OUTPUT ADDRESS TRACING
# ============================================================

def trace_co_outputs():
    out(f"\n{'='*78}")
    out(f"  3. CO-OUTPUT ADDRESS TRACING")
    out(f"{'='*78}")
    
    out(f"""
  The upstream TX (9b11b90a...) sent funds to these addresses alongside
  the puzzle creator funding. These may be:
    - Other creator-controlled addresses
    - Exchange deposits
    - Other recipients in the same withdrawal batch
  
  Tracing each address for activity and connections.
""")
    
    import time
    
    for addr, value in CO_OUTPUT_ADDRESSES.items():
        out(f"\n  --- {addr} ({value/1e8:.2f} BTC) ---")
        
        addr_info = api_get(f"https://mempool.space/api/address/{addr}")
        if addr_info:
            chain = addr_info.get('chain_stats', {})
            out(f"    TX count:        {chain.get('tx_count', '?')}")
            out(f"    Total received:  {chain.get('funded_txo_sum', 0)/1e8:.4f} BTC")
            out(f"    Total spent:     {chain.get('spent_txo_sum', 0)/1e8:.4f} BTC")
            out(f"    Balance:         {(chain.get('funded_txo_sum', 0) - chain.get('spent_txo_sum', 0))/1e8:.4f} BTC")
            
            tx_count = chain.get('tx_count', 0)
            if tx_count > 1000:
                out(f"    Assessment:      HIGH volume (exchange/service)")
            elif tx_count > 50:
                out(f"    Assessment:      MODERATE volume")
            elif tx_count > 5:
                out(f"    Assessment:      LOW volume (personal/dedicated)")
            else:
                out(f"    Assessment:      MINIMAL activity")
            
            # Check if P2SH (multisig?)
            if addr.startswith('3'):
                out(f"    Address type:    P2SH (could be multisig, exchange cold wallet)")
            elif addr.startswith('1'):
                out(f"    Address type:    P2PKH (legacy)")
            elif addr.startswith('bc1'):
                out(f"    Address type:    Bech32 (SegWit)")
        
        # Fetch first few TXs for this address
        addr_txs = api_get(f"https://mempool.space/api/address/{addr}/txs")
        if addr_txs:
            out(f"    Recent transactions ({min(len(addr_txs), 5)} shown):")
            for tx in addr_txs[:5]:
                txid = tx['txid']
                n_in = len(tx.get('vin', []))
                n_out = len(tx.get('vout', []))
                fee = tx.get('fee', 0)
                
                # Check if our address is sender or receiver
                is_sender = any(
                    vin.get('prevout', {}).get('scriptpubkey_address') == addr
                    for vin in tx.get('vin', [])
                )
                is_receiver = any(
                    vout.get('scriptpubkey_address') == addr
                    for vout in tx.get('vout', [])
                )
                direction = "SEND" if is_sender and not is_receiver else \
                           "RECV" if is_receiver and not is_sender else \
                           "BOTH" if is_sender and is_receiver else "?"
                
                # Get counterparty addresses
                counterparties = set()
                for vout in tx.get('vout', []):
                    a = vout.get('scriptpubkey_address', '')
                    if a and a != addr:
                        counterparties.add(a)
                for vin in tx.get('vin', []):
                    a = vin.get('prevout', {}).get('scriptpubkey_address', '')
                    if a and a != addr:
                        counterparties.add(a)
                
                cp_str = ', '.join(list(counterparties)[:3])
                if len(counterparties) > 3:
                    cp_str += f" (+{len(counterparties)-3} more)"
                
                out(f"      {txid[:16]}... {direction:>4s} in={n_in} out={n_out} "
                    f"fee={fee:,}")
                if counterparties:
                    out(f"        Counterparties: {cp_str}")
                
                # Check for connections to puzzle addresses or creator
                for cp in counterparties:
                    if cp == UPSTREAM_WALLET:
                        out(f"        ** CONNECTED TO UPSTREAM WALLET!")
                    if cp == '1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F':
                        out(f"        ** CONNECTED TO CREATOR FUNDING ADDRESS!")
                    if cp in PUZZLE_ADDRESSES.values():
                        puzzle_num = [k for k, v in PUZZLE_ADDRESSES.items() if v == cp][0]
                        out(f"        ** CONNECTED TO PUZZLE {puzzle_num}!")
        
        time.sleep(1)  # Rate limiting

# ============================================================
# SECTION 4: 2023 TOP-UP TRANSACTION SEARCH
# ============================================================

def search_2023_topup():
    out(f"\n{'='*78}")
    out(f"  4. SEARCHING FOR 2023 TOP-UP TRANSACTION")
    out(f"{'='*78}")
    
    out(f"""
  In April 2023, ~1000 BTC was distributed to puzzle addresses,
  increasing prizes by roughly 10x. We need to find the TX(s)
  and extract the SENDER information for additional forensic data.
  
  Strategy: Check known puzzle addresses for large deposits.
""")
    
    import time
    
    # Check several puzzle addresses for the top-up
    check_addresses = {
        66: '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so',
        70: '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR',
        71: '1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU',
        75: '1J36UjUByGroXcCvmj13U6uwaVv9caEeAt',
        80: '1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe',
        100: '1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F',
        120: '17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT',
        130: '1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua',
        135: '16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v',
        160: '1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv',
    }
    
    topup_txids = set()
    topup_senders = {}
    
    for puzzle_num, addr in sorted(check_addresses.items()):
        out(f"\n  Checking P{puzzle_num}: {addr}")
        
        addr_txs = api_get(f"https://mempool.space/api/address/{addr}/txs")
        if not addr_txs:
            out(f"    [!] Could not fetch transactions")
            time.sleep(1)
            continue
        
        out(f"    Found {len(addr_txs)} transactions")
        
        for tx in addr_txs:
            txid = tx['txid']
            
            # Skip the original funding TX
            if txid == FUNDING_TXID:
                out(f"    Skipping original funding TX")
                continue
            
            # Check if this TX deposits to this puzzle address
            for vout in tx.get('vout', []):
                if vout.get('scriptpubkey_address') == addr:
                    value = vout.get('value', 0)
                    
                    if value > 1_000_000:  # > 0.01 BTC (significant deposit)
                        out(f"    DEPOSIT: {value:,} sat ({value/1e8:.4f} BTC)")
                        out(f"      TXID: {txid}")
                        out(f"      Version: {tx.get('version', '?')}, "
                            f"Locktime: {tx.get('locktime', '?')}")
                        out(f"      Inputs: {len(tx.get('vin', []))}, "
                            f"Outputs: {len(tx.get('vout', []))}")
                        out(f"      Fee: {tx.get('fee', '?')} sat")
                        
                        topup_txids.add(txid)
                        
                        # Extract ALL sender information
                        for vin_idx, vin in enumerate(tx.get('vin', [])):
                            prev = vin.get('prevout', {})
                            sender_addr = prev.get('scriptpubkey_address', '?')
                            sender_val = prev.get('value', 0)
                            
                            out(f"      Sender vin[{vin_idx}]: {sender_addr} "
                                f"({sender_val:,} sat)")
                            
                            # Extract signature from sender
                            scriptsig = vin.get('scriptsig', '')
                            if scriptsig:
                                elems = parse_scriptsig(scriptsig)
                                if len(elems) >= 2:
                                    pk = elems[1].hex()
                                    sig_bytes = elems[0]
                                    r, s = parse_der(sig_bytes[:-1])
                                    out(f"        PubKey: {pk[:40]}...")
                                    if r:
                                        out(f"        r={r.bit_length()}bit, "
                                            f"s={s.bit_length()}bit")
                                    
                                    if sender_addr not in topup_senders:
                                        topup_senders[sender_addr] = {
                                            'pubkey': pk,
                                            'signatures': [],
                                            'total_value': 0,
                                        }
                                    topup_senders[sender_addr]['signatures'].append({
                                        'r': r, 's': s, 'txid': txid
                                    })
                                    topup_senders[sender_addr]['total_value'] += sender_val
                                elif len(elems) == 0 and vin.get('witness'):
                                    # SegWit input
                                    witness = vin.get('witness', [])
                                    out(f"        SegWit witness ({len(witness)} items)")
                                    if len(witness) >= 2:
                                        out(f"        PubKey: {witness[1][:40]}...")
                            elif vin.get('witness'):
                                witness = vin.get('witness', [])
                                out(f"        SegWit witness ({len(witness)} items)")
                        
                        # Check all outputs of this TX
                        out(f"      All outputs:")
                        for vout_idx, vout in enumerate(tx.get('vout', [])):
                            out_addr = vout.get('scriptpubkey_address', '?')
                            out_val = vout.get('value', 0)
                            marker = ""
                            if out_addr == addr:
                                marker = " <-- THIS PUZZLE"
                            elif out_addr == UPSTREAM_WALLET:
                                marker = " <-- UPSTREAM WALLET"
                            elif out_addr in PUZZLE_ADDRESSES.values():
                                pn = [k for k, v in PUZZLE_ADDRESSES.items() if v == out_addr]
                                marker = f" <-- PUZZLE {pn[0]}" if pn else ""
                            out(f"        vout[{vout_idx}]: {out_val:>15,} sat -> "
                                f"{out_addr[:30]}...{marker}")
        
        time.sleep(0.5)
    
    # Summary of top-up findings
    out(f"\n  TOP-UP SUMMARY:")
    out(f"  Unique top-up TXIDs found: {len(topup_txids)}")
    for txid in topup_txids:
        out(f"    {txid}")
    
    out(f"\n  Top-up sender addresses:")
    for addr, info in topup_senders.items():
        out(f"    {addr}")
        out(f"      PubKey: {info['pubkey'][:40]}...")
        out(f"      Total value: {info['total_value']:,} sat ({info['total_value']/1e8:.4f} BTC)")
        out(f"      Signatures: {len(info['signatures'])}")
        
        # Check if this sender pubkey matches the upstream wallet pubkey
        if info['pubkey'][:20] == UPSTREAM_PUBKEY:
            out(f"      *** SAME PUBKEY AS UPSTREAM WALLET! ***")
    
    return topup_senders

# ============================================================
# SECTION 5: HNP LATTICE SETUP (preparation for SageMath)
# ============================================================

def prepare_hnp_data(sig_data):
    out(f"\n{'='*78}")
    out(f"  5. HNP LATTICE ATTACK PREPARATION")
    out(f"{'='*78}")
    
    out(f"""
  The Hidden Number Problem (HNP) for ECDSA:
  
  Given: n (curve order), (r_i, s_i, z_i) for i = 1..m
  Find:  d (private key) such that
         k_i = s_i^(-1) * (z_i + r_i * d) mod n
  
  If the nonces k_i have B biased bits (e.g., top B bits are 0),
  then for m >= ceil(256/B) signatures, a lattice attack can find d.
  
  With 151 signatures:
    - 1-bit bias: need 256 sigs (we have 151 -- marginal)
    - 2-bit bias: need 128 sigs (we have 151 -- SUFFICIENT)
    - 4-bit bias: need 64 sigs  (we have 151 -- plenty)
  
  HOWEVER: We need the message hashes (z values) which require
  computing SIGHASH from the raw transactions.
  
  STATUS: Preparing data structure. Full attack requires:
    1. Raw TX hex for each of the 151 spending TXs
    2. SIGHASH computation for each input
    3. Lattice construction and BKZ reduction (SageMath/fpylll)
""")
    
    if not sig_data:
        out(f"  No signature data to prepare.")
        return
    
    # Save signature data for offline processing
    out(f"  Saving {len(sig_data)} signatures to phase5c_signatures.json...")
    
    sig_export = []
    for s in sig_data:
        sig_export.append({
            'txid': s['txid'],
            'vin_idx': s['vin_idx'],
            'r_hex': hex(s['r']),
            's_hex': hex(s['s']),
            'pubkey': s['pubkey'],
            'sighash_type': s['sighash_type'],
        })
    
    with open('phase5c_signatures.json', 'w') as f:
        json.dump(sig_export, f, indent=2)
    
    out(f"  Saved to phase5c_signatures.json")
    
    # Compute what we CAN without z values:
    # t_i = r_i * s_i^(-1) mod n
    # a_i = -z_i * s_i^(-1) mod n (need z_i for this)
    # Then: k_i = t_i * d + a_i mod n
    
    out(f"\n  Pre-computed t_i = r_i * s_i^(-1) mod n for each signature:")
    out(f"  (These are the HNP coefficients; with z_i, we can build the lattice)")
    
    for i, s in enumerate(sig_data[:10]):
        s_inv = pow(s['s'], N - 2, N)
        t_i = (s['r'] * s_inv) % N
        out(f"    sig[{i:>3d}]: t={hex(t_i)[:20]}... (TX: {s['txid'][:16]}...)")
    
    if len(sig_data) > 10:
        out(f"    ... ({len(sig_data) - 10} more)")
    
    out(f"""
  NEXT STEPS FOR FULL HNP ATTACK:
  
  1. Fetch raw TX hex for each of the {len(sig_data)} spending TXs
  2. For each input, compute SIGHASH_ALL:
     z = SHA256(SHA256(serialized_tx_for_signing))
  3. Build the HNP lattice:
     B = [[n, 0, ..., 0, 0],
          [t_1, 1/2^B, ..., 0, 0],
          [t_2, 0, ..., 0, 0],
          ...
          [a_1, 0, ..., 1/2^B, 0]]
  4. Run BKZ lattice reduction
  5. Check if shortest vector reveals d
  
  This requires SageMath or fpylll for lattice reduction.
  Estimated computation: ~minutes on modern CPU.
  
  CRITICAL NOTE:
  If nonces are truly RFC 6979 (deterministic, no bias),
  HNP attack WILL FAIL regardless of signature count.
  The bias detection in Section 2 should guide whether to proceed.
""")

# ============================================================
# SECTION 6: WALLET TYPE CLASSIFICATION
# ============================================================

def classify_wallet():
    out(f"\n{'='*78}")
    out(f"  6. WALLET TYPE CLASSIFICATION: {UPSTREAM_WALLET}")
    out(f"{'='*78}")
    
    out(f"""
  Evidence analysis:
  
  FOR exchange/service:
    + 10,125 transactions (very high)
    + 1,121,838 BTC total volume (massive)
    + Consistent 5,000 sat fee (automated system)
    + 1 input -> 2 output pattern (standard pay+change)
    + High-frequency activity
  
  AGAINST exchange/service:
    - Single pubkey for ALL signatures (exchanges typically rotate)
    - Version 1 TXs (exchanges usually upgrade)
    - Locktime=0 for all (exchanges use anti-fee-sniping)
  
  FOR creator's personal wallet:
    + Single consistent pubkey (single owner)
    + Sends directly to puzzle funding address
    + Co-outputs in same TX as puzzle funding
    
  AGAINST creator's personal wallet:
    - 10K+ TXs is extremely high for personal use
    - 1.1M BTC volume is implausible for an individual
  
  ASSESSMENT:
    The most likely classification is that 173ujr... is a
    CUSTODIAL SERVICE or EXCHANGE HOT WALLET that the creator
    used to fund the puzzles. The single pubkey is unusual but
    possible for older exchange implementations.
    
    ALTERNATIVELY: This could be a gambling site, mixing service,
    or payment processor. The uniform fee structure (5,000 sat)
    suggests automated batch processing.
    
    Key insight: Even if this is an exchange, the 151 signatures
    are from the EXCHANGE'S key, not the creator's. Recovering
    this key would give us the exchange's hot wallet key, NOT
    the puzzle master key.
    
    The CREATOR's key is the one that signed the funding TX input:
      PubKey: 024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda
      Address: 1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F
    
    THIS key only has 1 known signature (in the funding TX).
    HNP requires multiple signatures from the SAME key.
""")

# ============================================================
# MAIN
# ============================================================

def main():
    out("+" + "="*76 + "+")
    out("|  PHASE 5C: HNP LATTICE ATTACK & ADDRESS TRACING                        |")
    out("|  Bitcoin Puzzle Creator Deep Forensics                                    |")
    out("|  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "                                             |")
    out("+" + "="*76 + "+")
    
    try:
        import requests
    except ImportError:
        out("\n  [!] 'requests' not installed. Run: pip install requests")
        save_output()
        return
    
    # Section 1: Extract signatures
    try:
        sig_data = extract_full_signatures()
    except Exception as e:
        out(f"\n  [!] Error extracting signatures: {e}")
        import traceback; out(traceback.format_exc())
        sig_data = []
    
    # Section 2: Nonce bias detection
    try:
        detect_nonce_bias(sig_data)
    except Exception as e:
        out(f"\n  [!] Error in bias detection: {e}")
        import traceback; out(traceback.format_exc())
    
    # Section 3: Co-output address tracing
    try:
        trace_co_outputs()
    except Exception as e:
        out(f"\n  [!] Error tracing co-outputs: {e}")
        import traceback; out(traceback.format_exc())
    
    # Section 4: 2023 top-up search
    try:
        topup_senders = search_2023_topup()
    except Exception as e:
        out(f"\n  [!] Error searching top-up: {e}")
        import traceback; out(traceback.format_exc())
    
    # Section 5: HNP preparation
    try:
        prepare_hnp_data(sig_data)
    except Exception as e:
        out(f"\n  [!] Error preparing HNP: {e}")
        import traceback; out(traceback.format_exc())
    
    # Section 6: Wallet classification
    classify_wallet()
    
    save_output()

if __name__ == '__main__':
    main()
