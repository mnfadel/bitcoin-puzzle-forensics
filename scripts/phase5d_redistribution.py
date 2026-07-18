#!/usr/bin/env python3
"""
Phase 5D: REDISTRIBUTION TX DEEP FORENSICS
============================================
Analyzes the two critical transactions discovered in Phase 5C:

1. Redistribution TX (5d45587c...): 97 inputs (P161-P256 + whale) → 109 outputs
   - Extracts all 97 signatures and checks for r-value reuse
   - Maps inputs to puzzle numbers
   - Analyzes the uncompressed key whale address

2. Top-Up TX (12f34b58...): 1 SegWit input → 85 puzzle outputs
   - Extracts SegWit witness signature + pubkey
   - Traces the bc1q... sender address backward

3. Cross-references all signatures for forensic patterns

Usage: python3 phase5d_redistribution.py
Output: phase5d_results.txt

Requirements: pip install requests
"""

import json
import hashlib
import sys
import os
import time
from datetime import datetime
from collections import Counter

OUTPUT_FILE = "phase5d_results.txt"
output_lines = []

def out(line=""):
    print(line)
    output_lines.append(line)

def save_output():
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    print(f"\n[+] Results saved to: {os.path.abspath(OUTPUT_FILE)}")

# secp256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Known TXIDs
REDISTRIBUTION_TXID = '5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164'
TOPUP_TXID = '12f34b58b04dfb0233ce889f674781c0e0c7ba95482cca469125af41a78d13b3'
FUNDING_TXID = '08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15'
EXPOSURE_TXID = '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3'

SEGWIT_SENDER = 'bc1quksn4yxlxp80tn929gqnh8xpnngqj0fqr99q4z'
UNCOMPRESSED_ADDR = '1CENDvi6tmKGrR8RxqwURpX9WHbbKip1db'
CREATOR_PUBKEY = '024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda'

# ============================================================
# HELPERS
# ============================================================

def api_get(url, timeout=20):
    import requests
    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            return resp.json()
        else:
            out(f"    [!] HTTP {resp.status_code} from {url[:60]}...")
    except Exception as e:
        out(f"    [!] {str(e)[:80]}")
    return None

def api_text(url, timeout=20):
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
            ln = data[idx]; idx += 1
            elements.append(data[idx:idx+ln]); idx += ln
        elif op == 77:
            ln = int.from_bytes(data[idx:idx+2], 'little'); idx += 2
            elements.append(data[idx:idx+ln]); idx += ln
        else:
            break
    return elements

def parse_der(sig_bytes):
    try:
        idx = 0
        if sig_bytes[idx] != 0x30: return None, None
        idx += 2
        if sig_bytes[idx] != 0x02: return None, None
        idx += 1
        r_len = sig_bytes[idx]; idx += 1
        r = int.from_bytes(sig_bytes[idx:idx+r_len], 'big'); idx += r_len
        if sig_bytes[idx] != 0x02: return None, None
        idx += 1
        s_len = sig_bytes[idx]; idx += 1
        s = int.from_bytes(sig_bytes[idx:idx+s_len], 'big')
        return r, s
    except:
        return None, None

def section(num, title):
    out(f"\n{'='*78}")
    out(f"  {num}. {title}")
    out(f"{'='*78}")

# ============================================================
# SECTION 1: REDISTRIBUTION TX FULL ANALYSIS
# ============================================================

def analyze_redistribution_tx():
    section("1", "REDISTRIBUTION TX DEEP ANALYSIS")
    
    out(f"\n  TXID: {REDISTRIBUTION_TXID}")
    out(f"  This TX spends P161-P256 (the 'throwaway' puzzles) and redistributes")
    out(f"  the funds to lower puzzle addresses as prizes.")
    
    tx = api_get(f"https://mempool.space/api/tx/{REDISTRIBUTION_TXID}")
    if not tx:
        out(f"  [!] Could not fetch redistribution TX")
        return [], None
    
    out(f"\n  TX Structure:")
    out(f"    Version:   {tx.get('version', '?')}")
    out(f"    Locktime:  {tx.get('locktime', '?')}")
    out(f"    Size:      {tx.get('size', '?')} bytes")
    out(f"    Weight:    {tx.get('weight', '?')} WU")
    out(f"    Inputs:    {len(tx.get('vin', []))}")
    out(f"    Outputs:   {len(tx.get('vout', []))}")
    out(f"    Fee:       {tx.get('fee', '?')} sat")
    
    vins = tx.get('vin', [])
    vouts = tx.get('vout', [])
    
    # ---- Extract ALL input signatures ----
    out(f"\n  --- INPUT ANALYSIS ({len(vins)} inputs) ---")
    
    all_sigs = []
    puzzle_inputs = []
    whale_input = None
    
    for i, vin in enumerate(vins):
        prevout = vin.get('prevout', {})
        addr = prevout.get('scriptpubkey_address', '?')
        value = prevout.get('value', 0)
        scriptsig = vin.get('scriptsig', '')
        witness = vin.get('witness', [])
        
        sig_info = {
            'vin_idx': i,
            'address': addr,
            'value': value,
            'r': None, 's': None,
            'pubkey': None,
            'pubkey_type': None,
            'puzzle_num': None,
        }
        
        # Try to map value to puzzle number: P[i] original value = i * 100,000 sat
        puzzle_num = value // 100_000
        if 161 <= puzzle_num <= 256 and value == puzzle_num * 100_000:
            sig_info['puzzle_num'] = puzzle_num
        
        # Extract signature from scriptsig
        if scriptsig:
            elems = parse_scriptsig(scriptsig)
            if len(elems) >= 2:
                sig_bytes = elems[0]
                pk_bytes = elems[1]
                sighash = sig_bytes[-1]
                r, s = parse_der(sig_bytes[:-1])
                
                sig_info['r'] = r
                sig_info['s'] = s
                sig_info['pubkey'] = pk_bytes.hex()
                sig_info['sighash'] = sighash
                
                # Classify pubkey type
                if pk_bytes[0] == 0x04:
                    sig_info['pubkey_type'] = 'UNCOMPRESSED'
                elif pk_bytes[0] in (0x02, 0x03):
                    sig_info['pubkey_type'] = 'compressed'
                else:
                    sig_info['pubkey_type'] = f'unknown(0x{pk_bytes[0]:02x})'
        elif witness:
            # SegWit witness
            sig_info['pubkey_type'] = 'segwit_witness'
            if len(witness) >= 2:
                sig_info['pubkey'] = witness[1]
                # Parse witness signature
                try:
                    wit_sig = bytes.fromhex(witness[0])
                    r, s = parse_der(wit_sig[:-1])
                    sig_info['r'] = r
                    sig_info['s'] = s
                    sig_info['sighash'] = wit_sig[-1]
                except:
                    pass
        
        if sig_info['pubkey_type'] == 'UNCOMPRESSED':
            whale_input = sig_info
        elif sig_info['puzzle_num']:
            puzzle_inputs.append(sig_info)
        
        all_sigs.append(sig_info)
    
    # Print puzzle inputs
    out(f"\n  Puzzle Inputs (P161-P256):")
    out(f"  {'vin':>4s}  {'Puzzle':>6s}  {'Value (sat)':>12s}  {'PK Type':>12s}  {'r bits':>6s}  {'s bits':>6s}  {'Address':>20s}")
    out(f"  {'-'*4}  {'-'*6}  {'-'*12}  {'-'*12}  {'-'*6}  {'-'*6}  {'-'*20}")
    
    for sig in puzzle_inputs:
        r_bits = sig['r'].bit_length() if sig['r'] else 0
        s_bits = sig['s'].bit_length() if sig['s'] else 0
        out(f"  {sig['vin_idx']:>4d}  P{sig['puzzle_num']:>4d}  {sig['value']:>12,}  "
            f"{sig['pubkey_type']:>12s}  {r_bits:>6d}  {s_bits:>6d}  "
            f"{sig['address'][:20]}")
    
    # Print whale input
    if whale_input:
        out(f"\n  WHALE INPUT (uncompressed key):")
        out(f"    vin index:  {whale_input['vin_idx']}")
        out(f"    Address:    {whale_input['address']}")
        out(f"    Value:      {whale_input['value']:,} sat ({whale_input['value']/1e8:.4f} BTC)")
        out(f"    PubKey:     {whale_input['pubkey'][:80]}...")
        out(f"    PK type:    {whale_input['pubkey_type']}")
        out(f"    PK length:  {len(whale_input['pubkey'])//2 if whale_input['pubkey'] else 0} bytes")
        if whale_input['r']:
            out(f"    r bits:     {whale_input['r'].bit_length()}")
            out(f"    s bits:     {whale_input['s'].bit_length()}")
            low_s = whale_input['s'] <= N // 2
            out(f"    Low-s:      {low_s}")
    
    # ---- R-VALUE REUSE CHECK ----
    out(f"\n  --- R-VALUE REUSE CHECK (across all {len(all_sigs)} inputs) ---")
    
    r_values = [(sig['r'], sig['vin_idx'], sig.get('puzzle_num', '?'), sig['address']) 
                for sig in all_sigs if sig['r']]
    
    r_only = [r for r, _, _, _ in r_values]
    r_set = set(r_only)
    out(f"  Total signatures with r-values: {len(r_values)}")
    out(f"  Unique r-values:                {len(r_set)}")
    
    if len(r_set) < len(r_values):
        out(f"\n  *** CRITICAL: R-VALUE REUSE DETECTED! ***")
        r_counts = Counter(r_only)
        for r_val, cnt in r_counts.items():
            if cnt > 1:
                out(f"\n  Reused r = 0x{r_val:064x}")
                matching = [(r, idx, pn, addr) for r, idx, pn, addr in r_values if r == r_val]
                for r, idx, pn, addr in matching:
                    out(f"    vin[{idx}] P{pn} {addr[:30]}")
                
                # NOTE: r-value reuse is only exploitable if the SAME key 
                # signed two messages with the same nonce k.
                # Different keys with same r means k*G happened to match,
                # which is astronomically unlikely but not directly exploitable.
                out(f"\n  Checking if reused r-values come from SAME key...")
                pks = set()
                for r, idx, pn, addr in matching:
                    pk = next(s['pubkey'] for s in all_sigs if s['vin_idx'] == idx)
                    pks.add(pk)
                if len(pks) == 1:
                    out(f"  *** SAME KEY! Private key can be recovered! ***")
                else:
                    out(f"  Different keys ({len(pks)} unique) - coincidental r match")
    else:
        out(f"  No r-value reuse found across redistribution TX inputs.")
    
    # ---- r-value bit length distribution ----
    out(f"\n  --- R-VALUE STATISTICS ---")
    r_bits_list = [r.bit_length() for r in r_only]
    s_bits_list = [sig['s'].bit_length() for sig in all_sigs if sig['s']]
    
    r_dist = Counter(r_bits_list)
    out(f"  r-value bit length distribution:")
    for bits in sorted(r_dist.keys()):
        cnt = r_dist[bits]
        bar = '#' * min(cnt, 50)
        out(f"    {bits:>3d} bits: {cnt:>3d} ({cnt/len(r_bits_list)*100:5.1f}%) {bar}")
    
    # Low-s check
    low_s_count = sum(1 for sig in all_sigs if sig['s'] and sig['s'] <= N // 2)
    high_s_count = sum(1 for sig in all_sigs if sig['s'] and sig['s'] > N // 2)
    out(f"\n  Low-s:  {low_s_count}")
    out(f"  High-s: {high_s_count}")
    if high_s_count > 0:
        out(f"  *** HIGH-S SIGNATURES FOUND! Pre-BIP62 or non-standard! ***")
        for sig in all_sigs:
            if sig['s'] and sig['s'] > N // 2:
                out(f"    vin[{sig['vin_idx']}] P{sig.get('puzzle_num','?')} "
                    f"addr={sig['address'][:20]}")
    
    # ---- OUTPUT ANALYSIS ----
    out(f"\n  --- OUTPUT ANALYSIS ({len(vouts)} outputs) ---")
    out(f"  {'vout':>4s}  {'Value (sat)':>15s}  {'Address':>40s}")
    out(f"  {'-'*4}  {'-'*15}  {'-'*40}")
    
    for i, vout in enumerate(vouts[:20]):
        addr = vout.get('scriptpubkey_address', '?')
        value = vout.get('value', 0)
        out(f"  {i:>4d}  {value:>15,}  {addr}")
    if len(vouts) > 20:
        out(f"  ... ({len(vouts) - 20} more outputs)")
        for i in range(max(0, len(vouts)-5), len(vouts)):
            vout = vouts[i]
            addr = vout.get('scriptpubkey_address', '?')
            value = vout.get('value', 0)
            out(f"  {i:>4d}  {value:>15,}  {addr}")
    
    # Total input/output
    total_in = sum(sig['value'] for sig in all_sigs)
    total_out = sum(vout.get('value', 0) for vout in vouts)
    out(f"\n  Total input:  {total_in:>15,} sat ({total_in/1e8:.4f} BTC)")
    out(f"  Total output: {total_out:>15,} sat ({total_out/1e8:.4f} BTC)")
    out(f"  Fee:          {total_in - total_out:>15,} sat")
    
    return all_sigs, whale_input

# ============================================================
# SECTION 2: TOP-UP TX ANALYSIS
# ============================================================

def analyze_topup_tx():
    section("2", "TOP-UP TX ANALYSIS (2023)")
    
    out(f"\n  TXID: {TOPUP_TXID}")
    out(f"  This TX injected ~870 BTC into puzzle addresses from a SegWit address.")
    
    tx = api_get(f"https://mempool.space/api/tx/{TOPUP_TXID}")
    if not tx:
        out(f"  [!] Could not fetch top-up TX")
        return None
    
    out(f"\n  TX Structure:")
    out(f"    Version:   {tx.get('version', '?')}")
    out(f"    Locktime:  {tx.get('locktime', '?')}")
    out(f"    Size:      {tx.get('size', '?')} bytes")
    out(f"    Weight:    {tx.get('weight', '?')} WU")
    out(f"    Inputs:    {len(tx.get('vin', []))}")
    out(f"    Outputs:   {len(tx.get('vout', []))}")
    out(f"    Fee:       {tx.get('fee', '?')} sat")
    
    # Extract SegWit witness data
    vin = tx['vin'][0]
    prevout = vin.get('prevout', {})
    witness = vin.get('witness', [])
    
    out(f"\n  --- SENDER (SegWit) ---")
    out(f"    Address:    {prevout.get('scriptpubkey_address', '?')}")
    out(f"    Value:      {prevout.get('value', 0):,} sat ({prevout.get('value', 0)/1e8:.4f} BTC)")
    out(f"    ScriptPubKey type: {prevout.get('scriptpubkey_type', '?')}")
    
    segwit_pubkey = None
    segwit_r = None
    segwit_s = None
    
    if witness:
        out(f"    Witness items: {len(witness)}")
        for i, w in enumerate(witness):
            out(f"      witness[{i}]: {w[:60]}... ({len(w)//2} bytes)")
        
        if len(witness) >= 2:
            segwit_pubkey = witness[1]
            out(f"\n    SegWit Public Key: {segwit_pubkey}")
            
            pk_bytes = bytes.fromhex(segwit_pubkey)
            if pk_bytes[0] == 0x02:
                out(f"    PK Type: Compressed (even y)")
            elif pk_bytes[0] == 0x03:
                out(f"    PK Type: Compressed (odd y)")
            elif pk_bytes[0] == 0x04:
                out(f"    PK Type: UNCOMPRESSED")
            out(f"    PK Length: {len(pk_bytes)} bytes")
            
            # Parse signature
            try:
                sig_hex = witness[0]
                sig_bytes = bytes.fromhex(sig_hex)
                sighash = sig_bytes[-1]
                r, s = parse_der(sig_bytes[:-1])
                segwit_r = r
                segwit_s = s
                
                out(f"\n    Signature:")
                out(f"      SIGHASH:  0x{sighash:02x}")
                out(f"      r:        {r.bit_length()} bits")
                out(f"      s:        {s.bit_length()} bits")
                out(f"      r hex:    0x{r:064x}")
                out(f"      s hex:    0x{s:064x}")
                low_s = s <= N // 2
                out(f"      Low-s:    {low_s}")
            except Exception as e:
                out(f"    [!] Could not parse SegWit signature: {e}")
    
    # Analyze output value formula
    vouts = tx.get('vout', [])
    out(f"\n  --- OUTPUT VALUE FORMULA ---")
    
    # Check if V = puzzle_num * 9,000,000
    for i, vout in enumerate(vouts[:10]):
        addr = vout.get('scriptpubkey_address', '?')
        value = vout.get('value', 0)
        implied_puzzle = value // 9_000_000
        out(f"    vout[{i:>2d}]: {value:>13,} sat = {implied_puzzle} * 9M "
            f"(P{implied_puzzle}?) -> {addr[:25]}...")
    
    if len(vouts) > 10:
        out(f"    ... ({len(vouts) - 10} more)")
    
    # Check which puzzles are MISSING (already solved)
    all_puzzle_nums = set()
    for vout in vouts:
        value = vout.get('value', 0)
        pn = value // 9_000_000
        if 1 <= pn <= 256:
            all_puzzle_nums.add(pn)
    
    missing = set(range(1, 161)) - all_puzzle_nums  # Below P161
    present = all_puzzle_nums
    
    # Focus on unsolved range
    unsolved_range = set(range(66, 161))
    unsolved_present = unsolved_range.intersection(present)
    unsolved_missing = unsolved_range - present
    
    out(f"\n  Puzzles funded in this TX: {len(present)}")
    out(f"  Unsolved range (P66-P160) present: {len(unsolved_present)}")
    out(f"  Unsolved range (P66-P160) MISSING: {sorted(unsolved_missing)}")
    out(f"  (Missing = already solved at time of top-up)")
    
    # Compare creator pubkey to segwit pubkey
    out(f"\n  --- PUBKEY COMPARISON ---")
    out(f"    2015 Creator PK: {CREATOR_PUBKEY}")
    out(f"    2023 SegWit PK:  {segwit_pubkey}")
    
    if segwit_pubkey and CREATOR_PUBKEY:
        if segwit_pubkey == CREATOR_PUBKEY:
            out(f"    *** MATCH! Same entity confirmed! ***")
        else:
            out(f"    Different keys (expected if different wallet/HD path)")
    
    return {
        'pubkey': segwit_pubkey,
        'r': segwit_r,
        's': segwit_s,
        'address': SEGWIT_SENDER,
    }

# ============================================================
# SECTION 3: SEGWIT SENDER TRACING
# ============================================================

def trace_segwit_sender():
    section("3", f"SEGWIT SENDER TRACING: {SEGWIT_SENDER}")
    
    out(f"\n  This bc1q... address funded the 2023 top-up with ~872 BTC.")
    out(f"  Tracing it backwards to find its funding source.")
    
    # Get address info
    addr_info = api_get(f"https://mempool.space/api/address/{SEGWIT_SENDER}")
    if addr_info:
        chain = addr_info.get('chain_stats', {})
        out(f"\n  Address Stats:")
        out(f"    TX count:          {chain.get('tx_count', '?')}")
        out(f"    Total received:    {chain.get('funded_txo_sum', 0)/1e8:.4f} BTC")
        out(f"    Total spent:       {chain.get('spent_txo_sum', 0)/1e8:.4f} BTC")
        out(f"    Balance:           {(chain.get('funded_txo_sum', 0) - chain.get('spent_txo_sum', 0))/1e8:.4f} BTC")
        
        tx_count = chain.get('tx_count', 0)
        if tx_count <= 10:
            out(f"    Assessment: VERY LOW tx count -> dedicated funding address")
        elif tx_count <= 100:
            out(f"    Assessment: LOW-MODERATE -> personal or dedicated")
        else:
            out(f"    Assessment: HIGH -> exchange or service")
    
    # Fetch transactions
    txs = api_get(f"https://mempool.space/api/address/{SEGWIT_SENDER}/txs")
    if not txs:
        out(f"  [!] Could not fetch transactions")
        return
    
    out(f"\n  Transactions ({len(txs)} found):")
    
    funding_sources = []
    all_sigs_segwit = []
    
    for tx in txs:
        txid = tx['txid']
        
        is_sender = False
        is_receiver = False
        received_val = 0
        
        for vin in tx.get('vin', []):
            prev = vin.get('prevout', {})
            if prev.get('scriptpubkey_address') == SEGWIT_SENDER:
                is_sender = True
                # Extract witness signature
                witness = vin.get('witness', [])
                if len(witness) >= 2:
                    try:
                        sig_bytes = bytes.fromhex(witness[0])
                        r, s = parse_der(sig_bytes[:-1])
                        if r:
                            all_sigs_segwit.append({
                                'txid': txid, 'r': r, 's': s,
                                'pubkey': witness[1]
                            })
                    except:
                        pass
        
        for vout in tx.get('vout', []):
            if vout.get('scriptpubkey_address') == SEGWIT_SENDER:
                is_receiver = True
                received_val += vout.get('value', 0)
        
        direction = "SEND" if is_sender and not is_receiver else \
                   "RECV" if is_receiver and not is_sender else \
                   "BOTH" if is_sender and is_receiver else "?"
        
        marker = ""
        if txid == TOPUP_TXID:
            marker = " <-- TOP-UP TX"
        
        n_in = len(tx.get('vin', []))
        n_out = len(tx.get('vout', []))
        fee = tx.get('fee', 0)
        
        out(f"\n  TX: {txid[:40]}...")
        out(f"    Dir: {direction}, In: {n_in}, Out: {n_out}, Fee: {fee:,}{marker}")
        
        if is_receiver:
            out(f"    Received: {received_val:,} sat ({received_val/1e8:.4f} BTC)")
            # Find the sender
            for vin in tx.get('vin', []):
                prev = vin.get('prevout', {})
                funder_addr = prev.get('scriptpubkey_address', '?')
                funder_val = prev.get('value', 0)
                out(f"    Funded by: {funder_addr} ({funder_val:,} sat)")
                funding_sources.append({
                    'address': funder_addr,
                    'value': funder_val,
                    'txid': txid,
                })
                
                # Get funder's pubkey
                witness = vin.get('witness', [])
                scriptsig = vin.get('scriptsig', '')
                if witness and len(witness) >= 2:
                    out(f"    Funder PK: {witness[1][:40]}... (SegWit)")
                elif scriptsig:
                    elems = parse_scriptsig(scriptsig)
                    if len(elems) >= 2:
                        out(f"    Funder PK: {elems[1].hex()[:40]}... (P2PKH)")
    
    # R-value check on segwit sender signatures
    if all_sigs_segwit:
        out(f"\n  SegWit sender signatures: {len(all_sigs_segwit)}")
        r_vals = [s['r'] for s in all_sigs_segwit]
        r_unique = len(set(r_vals))
        out(f"  Unique r-values: {r_unique}/{len(r_vals)}")
        if r_unique < len(r_vals):
            out(f"  *** R-VALUE REUSE IN SEGWIT SENDER! ***")
    
    out(f"\n  Funding Sources Summary:")
    for fs in funding_sources:
        out(f"    {fs['address']} -> {fs['value']/1e8:.4f} BTC (TX: {fs['txid'][:20]}...)")

# ============================================================
# SECTION 4: UNCOMPRESSED KEY WHALE ANALYSIS
# ============================================================

def analyze_uncompressed_whale(whale_input):
    section("4", f"UNCOMPRESSED KEY WHALE: {UNCOMPRESSED_ADDR}")
    
    out(f"""
  The redistribution TX contains an input with an UNCOMPRESSED public key
  (0x04 prefix). This is a very old-style Bitcoin practice, common in
  2009-2012 era wallets. This address contributed 83.53 BTC to the
  redistribution — likely the change/fee source.
  
  An uncompressed key from a puzzle-related TX is highly unusual and
  could indicate the creator's original/early wallet.
""")
    
    if whale_input and whale_input.get('pubkey'):
        pk_hex = whale_input['pubkey']
        out(f"  Full Public Key: {pk_hex[:66]}")
        if len(pk_hex) > 66:
            out(f"                   {pk_hex[66:]}")
        out(f"  Key Length: {len(pk_hex)//2} bytes ({'uncompressed' if len(pk_hex)//2 == 65 else 'compressed'})")
        
        # Extract x and y coordinates
        if len(pk_hex) == 130:  # 65 bytes = 04 + 32 + 32
            x_hex = pk_hex[2:66]
            y_hex = pk_hex[66:130]
            x = int(x_hex, 16)
            y = int(y_hex, 16)
            out(f"\n  EC Point:")
            out(f"    x = 0x{x_hex}")
            out(f"    y = 0x{y_hex}")
            out(f"    x bits: {x.bit_length()}")
            out(f"    y bits: {y.bit_length()}")
            out(f"    y parity: {'even' if y % 2 == 0 else 'odd'}")
            
            # Compressed form
            prefix = '02' if y % 2 == 0 else '03'
            compressed = prefix + x_hex
            out(f"\n  Compressed form: {compressed}")
            
            # Check if compressed form matches creator pubkey
            out(f"  Creator PK:      {CREATOR_PUBKEY}")
            if compressed == CREATOR_PUBKEY:
                out(f"  *** MATCH! This is the CREATOR'S KEY (uncompressed form)! ***")
            else:
                out(f"  No match with creator pubkey")
    
    # Fetch address info
    addr_info = api_get(f"https://mempool.space/api/address/{UNCOMPRESSED_ADDR}")
    if addr_info:
        chain = addr_info.get('chain_stats', {})
        out(f"\n  Address Stats:")
        out(f"    TX count:          {chain.get('tx_count', '?')}")
        out(f"    Total received:    {chain.get('funded_txo_sum', 0)/1e8:.4f} BTC")
        out(f"    Total spent:       {chain.get('spent_txo_sum', 0)/1e8:.4f} BTC")
        balance = chain.get('funded_txo_sum', 0) - chain.get('spent_txo_sum', 0)
        out(f"    Balance:           {balance/1e8:.4f} BTC")
        
        if balance > 0:
            out(f"    *** ACTIVE BALANCE: {balance/1e8:.4f} BTC still in this address! ***")
    
    # Fetch transactions
    txs = api_get(f"https://mempool.space/api/address/{UNCOMPRESSED_ADDR}/txs")
    if txs:
        out(f"\n  Transactions ({len(txs)} found):")
        
        whale_sigs = []
        
        for tx in txs:
            txid = tx['txid']
            n_in = len(tx.get('vin', []))
            n_out = len(tx.get('vout', []))
            fee = tx.get('fee', 0)
            
            is_sender = False
            is_receiver = False
            
            for vin in tx.get('vin', []):
                prev = vin.get('prevout', {})
                if prev.get('scriptpubkey_address') == UNCOMPRESSED_ADDR:
                    is_sender = True
                    scriptsig = vin.get('scriptsig', '')
                    if scriptsig:
                        elems = parse_scriptsig(scriptsig)
                        if len(elems) >= 2:
                            sig_bytes = elems[0]
                            r, s = parse_der(sig_bytes[:-1])
                            if r:
                                whale_sigs.append({
                                    'txid': txid, 'r': r, 's': s,
                                    'pubkey': elems[1].hex()
                                })
            
            for vout in tx.get('vout', []):
                if vout.get('scriptpubkey_address') == UNCOMPRESSED_ADDR:
                    is_receiver = True
            
            direction = "SEND" if is_sender and not is_receiver else \
                       "RECV" if is_receiver and not is_sender else \
                       "BOTH" if is_sender and is_receiver else "?"
            
            marker = ""
            if txid == REDISTRIBUTION_TXID:
                marker = " <-- REDISTRIBUTION TX"
            
            out(f"    {txid[:40]}... {direction:>4s} in={n_in:>3d} out={n_out:>4d} fee={fee:>10,}{marker}")
            
            # Show counterparties for non-redistribution TXs
            if txid != REDISTRIBUTION_TXID:
                for vin in tx.get('vin', []):
                    prev = vin.get('prevout', {})
                    a = prev.get('scriptpubkey_address', '')
                    if a and a != UNCOMPRESSED_ADDR:
                        out(f"      From: {a} ({prev.get('value', 0):,} sat)")
                for vout in tx.get('vout', []):
                    a = vout.get('scriptpubkey_address', '')
                    if a and a != UNCOMPRESSED_ADDR:
                        v = vout.get('value', 0)
                        if v > 100_000:
                            out(f"      To:   {a} ({v:,} sat)")
        
        # R-value analysis on whale signatures
        if whale_sigs:
            out(f"\n  Whale address signatures: {len(whale_sigs)}")
            r_vals = [s['r'] for s in whale_sigs]
            r_unique = len(set(r_vals))
            out(f"  Unique r-values: {r_unique}/{len(r_vals)}")
            
            if r_unique < len(r_vals):
                out(f"  *** R-VALUE REUSE IN WHALE ADDRESS! ***")
                r_counts = Counter(r_vals)
                for r_val, cnt in r_counts.items():
                    if cnt > 1:
                        out(f"    r=0x{r_val:064x} used {cnt} times!")
                        matching = [s for s in whale_sigs if s['r'] == r_val]
                        for m in matching:
                            out(f"      TX: {m['txid'][:40]}...")
            else:
                out(f"  No r-value reuse in whale signatures")
            
            # Check for cross-reference with creator funding TX signature
            out(f"\n  Cross-referencing whale r-values with exposure TX...")
            exposure_tx = api_get(f"https://mempool.space/api/tx/{EXPOSURE_TXID}")
            if exposure_tx:
                exposure_rs = set()
                for vin in exposure_tx.get('vin', []):
                    ss = vin.get('scriptsig', '')
                    if ss:
                        elems = parse_scriptsig(ss)
                        if elems:
                            r, s = parse_der(elems[0][:-1])
                            if r: exposure_rs.add(r)
                
                whale_rs = set(r_vals)
                overlap = whale_rs.intersection(exposure_rs)
                out(f"  Whale r-values: {len(whale_rs)}")
                out(f"  Exposure r-values: {len(exposure_rs)}")
                out(f"  Overlap: {len(overlap)}")
                if overlap:
                    out(f"  *** CROSS-TX R-VALUE OVERLAP! ***")

# ============================================================
# SECTION 5: PUBKEY PATTERN ANALYSIS (P161-P256)
# ============================================================

def analyze_pubkey_patterns(all_sigs):
    section("5", "PUBKEY PATTERN ANALYSIS (P161-P256)")
    
    out(f"""
  The redistribution TX exposed public keys for P161-P256.
  These keys were derived from the same HD wallet as P1-P160.
  
  Analysis: Do the exposed pubkeys reveal any derivation pattern?
  - Check compressed prefix distribution (02 vs 03)
  - Check if any pubkeys share x-coordinate (would mean additive inverse)
  - Check if sequential pubkey differences form a pattern
""")
    
    puzzle_sigs = [s for s in all_sigs if s.get('puzzle_num') and s.get('pubkey')]
    puzzle_sigs.sort(key=lambda s: s['puzzle_num'])
    
    if not puzzle_sigs:
        out(f"  No puzzle pubkeys available.")
        return
    
    out(f"  Puzzle pubkeys extracted: {len(puzzle_sigs)}")
    
    # Prefix distribution (02 = even y, 03 = odd y)
    even_y = sum(1 for s in puzzle_sigs if s['pubkey'][:2] == '02')
    odd_y = sum(1 for s in puzzle_sigs if s['pubkey'][:2] == '03')
    out(f"\n  Prefix distribution:")
    out(f"    02 (even y): {even_y} ({even_y/len(puzzle_sigs)*100:.1f}%)")
    out(f"    03 (odd y):  {odd_y} ({odd_y/len(puzzle_sigs)*100:.1f}%)")
    out(f"    Expected for random keys: ~50% each")
    
    # Extract x-coordinates
    x_coords = {}
    for s in puzzle_sigs:
        pk = s['pubkey']
        if len(pk) >= 66:
            x_hex = pk[2:66]
            x = int(x_hex, 16)
            if x in x_coords:
                out(f"\n  *** SHARED X-COORDINATE FOUND! ***")
                out(f"    P{x_coords[x]} and P{s['puzzle_num']} share x = 0x{x_hex[:16]}...")
                out(f"    This means one key is the additive inverse of the other!")
            x_coords[x] = s['puzzle_num']
    
    if len(x_coords) == len(puzzle_sigs):
        out(f"\n  No shared x-coordinates (all pubkeys are independent points)")
    
    # Check if any pubkeys match known solved puzzle pubkeys from exposure TX
    out(f"\n  Cross-referencing with exposure TX pubkeys...")
    exposure_tx = api_get(f"https://mempool.space/api/tx/{EXPOSURE_TXID}")
    if exposure_tx:
        exposure_pks = set()
        for vin in exposure_tx.get('vin', []):
            ss = vin.get('scriptsig', '')
            if ss:
                elems = parse_scriptsig(ss)
                if len(elems) >= 2:
                    exposure_pks.add(elems[1].hex())
        
        redistrib_pks = set(s['pubkey'] for s in puzzle_sigs)
        overlap = redistrib_pks.intersection(exposure_pks)
        out(f"  Exposure TX pubkeys: {len(exposure_pks)}")
        out(f"  Redistribution pubkeys: {len(redistrib_pks)}")
        out(f"  Overlap: {len(overlap)}")
        if overlap:
            out(f"  *** PUBKEY OVERLAP — same key used in both TXs! ***")
            for pk in overlap:
                # Find which puzzles
                exp_puzzles = [s['puzzle_num'] for s in puzzle_sigs if s['pubkey'] == pk]
                out(f"    PK {pk[:20]}... in puzzles: {exp_puzzles}")
    
    # Check byte entropy of pubkeys (looking for patterns in derived keys)
    out(f"\n  Pubkey byte analysis (first 8 bytes of x-coordinate):")
    for s in puzzle_sigs[:10]:
        pk = s['pubkey']
        x_bytes = pk[2:18]  # First 8 bytes of x
        out(f"    P{s['puzzle_num']:>3d}: {pk[:2]}{x_bytes}...")
    if len(puzzle_sigs) > 10:
        out(f"    ... ({len(puzzle_sigs) - 10} more)")

# ============================================================
# SECTION 6: CROSS-ENTITY SIGNATURE COMPARISON
# ============================================================

def cross_entity_analysis(redist_sigs, segwit_info, whale_input):
    section("6", "CROSS-ENTITY SIGNATURE & IDENTITY ANALYSIS")
    
    out(f"""
  We now have signatures/pubkeys from FOUR distinct entities:
  
  1. Creator 2015:  PK = 024b0faa... (1Czoy8..., funding TX)
  2. Creator 2023:  PK = {segwit_info.get('pubkey', '?')[:20] if segwit_info else '?'}... (bc1q..., top-up TX)
  3. Whale:         PK = {whale_input['pubkey'][:20] if whale_input and whale_input.get('pubkey') else '?'}... (1CENDv..., redistribution)
  4. Upstream:      PK = 031c24239a829a89d7e1... (173ujr..., exchange?)
  
  Questions:
  - Are entities 1, 2, and 3 the SAME person (creator)?
  - Is entity 4 the creator or an exchange?
  - Do any r-values cross-correlate?
""")
    
    # Collect all known pubkeys
    entities = {
        'Creator 2015': CREATOR_PUBKEY,
        'Upstream':     '031c24239a829a89d7e1',  # partial from results
    }
    if segwit_info and segwit_info.get('pubkey'):
        entities['Creator 2023 (SegWit)'] = segwit_info['pubkey']
    if whale_input and whale_input.get('pubkey'):
        entities['Whale (Uncompressed)'] = whale_input['pubkey']
    
    out(f"\n  Entity Public Keys:")
    for name, pk in entities.items():
        out(f"    {name:>25s}: {pk[:50]}{'...' if len(pk) > 50 else ''}")
    
    # Check for same-key across entities
    out(f"\n  Same-key checks:")
    pks_norm = {}
    for name, pk in entities.items():
        # Normalize: if uncompressed (04...), compute compressed form
        if pk[:2] == '04' and len(pk) == 130:
            x_hex = pk[2:66]
            y = int(pk[66:130], 16)
            prefix = '02' if y % 2 == 0 else '03'
            compressed = prefix + x_hex
            pks_norm[name] = compressed
            out(f"    {name}: uncompressed -> compressed = {compressed[:30]}...")
        else:
            pks_norm[name] = pk
    
    # Compare all pairs
    names = list(pks_norm.keys())
    for i in range(len(names)):
        for j in range(i+1, len(names)):
            n1, n2 = names[i], names[j]
            pk1, pk2 = pks_norm[n1], pks_norm[n2]
            # Compare (handle partial keys)
            min_len = min(len(pk1), len(pk2))
            if pk1[:min_len] == pk2[:min_len]:
                out(f"    *** MATCH: {n1} == {n2} ***")
            else:
                out(f"    {n1} != {n2}")
    
    # Timeline summary
    out(f"""
  TIMELINE OF CREATOR ACTIVITY:
  
  2015-01-15: Funding TX
    - Withdrew 32.90 BTC from 173ujr... (exchange/service)
    - Signed with PK: 024b0faa...
    - Created 256 puzzle outputs (P1-P256)
    - Software: Bitcoin Core v0.9.x or v0.10.0rc4
    
  2017-07-xx: Redistribution TX
    - Spent P161-P256 (96 puzzle keys) + whale address
    - Redistributed to lower puzzles as prizes
    - Whale address uses UNCOMPRESSED key (very old wallet)
    - 97 signatures in a single TX
    
  2019-06-01: Exposure TX
    - Spent from 20 puzzle addresses (every 5th from P65-P160)
    - Exposed public keys for these puzzles
    - Software: Bitcoin Core v0.13-v0.15
    
  2023-04-xx: Top-Up TX
    - Injected ~872 BTC from bc1q... (SegWit address)
    - Creator upgraded to modern wallet
    - Single SegWit signature
    - Skipped already-solved puzzles in output list
    
  KEY QUESTIONS FOR FURTHER INVESTIGATION:
  
  1. Is the whale address (uncompressed key) the creator's original wallet?
     If YES: It predates the puzzle creation and may reveal identity
     
  2. Where did bc1q... get 872 BTC?
     Tracing backwards could reveal exchange/custodial connections
     
  3. The redistribution TX has 97 unique signatures — even though
     they're from different keys, statistical analysis across all
     97 nonces could reveal systematic bias in the signing implementation
""")

# ============================================================
# MAIN
# ============================================================

def main():
    out("+" + "="*76 + "+")
    out("|  PHASE 5D: REDISTRIBUTION TX DEEP FORENSICS                            |")
    out("|  Bitcoin Puzzle Creator Analysis                                          |")
    out("|  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "                                             |")
    out("+" + "="*76 + "+")
    
    try:
        import requests
    except ImportError:
        out("\n  [!] pip install requests required")
        save_output()
        return
    
    # Section 1: Redistribution TX
    try:
        all_sigs, whale_input = analyze_redistribution_tx()
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
        all_sigs, whale_input = [], None
    
    time.sleep(1)
    
    # Section 2: Top-up TX
    try:
        segwit_info = analyze_topup_tx()
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
        segwit_info = None
    
    time.sleep(1)
    
    # Section 3: SegWit sender tracing
    try:
        trace_segwit_sender()
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
    
    time.sleep(1)
    
    # Section 4: Uncompressed whale
    try:
        analyze_uncompressed_whale(whale_input)
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
    
    time.sleep(1)
    
    # Section 5: Pubkey patterns
    try:
        analyze_pubkey_patterns(all_sigs)
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
    
    # Section 6: Cross-entity
    try:
        cross_entity_analysis(all_sigs, segwit_info, whale_input)
    except Exception as e:
        out(f"\n  [!] Error: {e}")
        import traceback; out(traceback.format_exc())
    
    save_output()

if __name__ == '__main__':
    main()
