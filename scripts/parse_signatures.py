#!/usr/bin/env python3
"""
Bitcoin ECDSA Signature Parser
Parses DER-encoded signatures from Bitcoin scriptSig hex strings.

Usage:
  python parse_signatures.py <scriptsig_hex>
  python parse_signatures.py --file <file_with_scriptsigs>
  python parse_signatures.py --batch  (reads from forensic_findings.md)

Output: r, s, sighash type, and public key for each signature.
"""
import sys
import hashlib

# secp256k1 curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def parse_der_signature(script_hex):
    """
    Parse a Bitcoin P2PKH scriptSig to extract ECDSA signature components.
    
    Args:
        script_hex: Full scriptSig hex string (push_byte + DER_sig + sighash + push_byte + pubkey)
    
    Returns:
        dict with keys: r, s, sighash, pubkey, r_bits, s_bits
    
    Raises:
        ValueError: If parsing fails
    """
    try:
        pos = 0
        # First push byte = length of signature + sighash byte
        push_len = int(script_hex[pos:pos+2], 16)
        pos += 2
        sig_hex = script_hex[pos:pos+push_len*2]
        pos += push_len * 2
        
        # Parse DER structure: 30 <total_len> 02 <r_len> <r> 02 <s_len> <s> <sighash>
        if sig_hex[:2] != '30':
            raise ValueError(f"Expected DER SEQUENCE tag 0x30, got 0x{sig_hex[:2]}")
        
        der_len = int(sig_hex[2:4], 16)
        p = 4  # skip 30 xx
        
        # Parse r
        if sig_hex[p:p+2] != '02':
            raise ValueError(f"Expected INTEGER tag 0x02 for r, got 0x{sig_hex[p:p+2]}")
        p += 2
        r_len = int(sig_hex[p:p+2], 16)
        p += 2
        r_hex = sig_hex[p:p+r_len*2]
        r = int(r_hex, 16)
        p += r_len * 2
        
        # Parse s
        if sig_hex[p:p+2] != '02':
            raise ValueError(f"Expected INTEGER tag 0x02 for s, got 0x{sig_hex[p:p+2]}")
        p += 2
        s_len = int(sig_hex[p:p+2], 16)
        p += 2
        s_hex = sig_hex[p:p+s_len*2]
        s = int(s_hex, 16)
        p += s_len * 2
        
        # SIGHASH type (last byte of signature data)
        sighash = int(sig_hex[p:p+2], 16)
        
        # Extract public key (next push + data)
        pubkey_push = int(script_hex[pos:pos+2], 16)
        pos += 2
        pubkey_hex = script_hex[pos:pos+pubkey_push*2]
        
        return {
            'r': r,
            's': s,
            'r_hex': r_hex,
            's_hex': s_hex,
            'r_bits': r.bit_length(),
            's_bits': s.bit_length(),
            'sighash': sighash,
            'sighash_name': {1: 'ALL', 2: 'NONE', 3: 'SINGLE', 0x81: 'ALL|ANYONECANPAY'}.get(sighash, f'UNKNOWN(0x{sighash:02x})'),
            'pubkey': pubkey_hex,
            'pubkey_type': 'compressed' if pubkey_hex[:2] in ('02', '03') else 'uncompressed',
        }
    except Exception as e:
        raise ValueError(f"Failed to parse scriptSig: {e}")


def check_r_reuse(signatures):
    """Check for r-value reuse across multiple signatures (nonce reuse vulnerability)."""
    r_to_labels = {}
    reuses = []
    for label, sig in signatures.items():
        r_hex = hex(sig['r'])
        if r_hex in r_to_labels:
            reuses.append((r_to_labels[r_hex], label, sig['r']))
        else:
            r_to_labels[r_hex] = label
    return reuses


def analyze_bias(signatures):
    """Analyze r-values and s-values for statistical bias."""
    r_bits = [sig['r_bits'] for sig in signatures.values()]
    s_bits = [sig['s_bits'] for sig in signatures.values()]
    
    # Top bytes of r-values (should be uniform [0,255] for unbiased nonces)
    top_bytes = [(sig['r'] >> 248) & 0xFF for sig in signatures.values()]
    
    results = {
        'r_bit_distribution': {},
        's_bit_distribution': {},
        'r_top_byte_mean': sum(top_bytes) / len(top_bytes) if top_bytes else 0,
        'r_top_byte_range': (min(top_bytes), max(top_bytes)) if top_bytes else (0, 0),
        'expected_top_byte_mean': 127.5,
        'suspicious_short_r': [(l, s['r_bits']) for l, s in signatures.items() if s['r_bits'] < 248],
        'suspicious_short_s': [(l, s['s_bits']) for l, s in signatures.items() if s['s_bits'] < 248],
    }
    
    for b in r_bits:
        results['r_bit_distribution'][b] = results['r_bit_distribution'].get(b, 0) + 1
    for b in s_bits:
        results['s_bit_distribution'][b] = results['s_bit_distribution'].get(b, 0) + 1
    
    return results


def group_by_pubkey(signatures):
    """Group signatures by public key to identify entities."""
    groups = {}
    for label, sig in signatures.items():
        pk = sig['pubkey']
        if pk not in groups:
            groups[pk] = []
        groups[pk].append(label)
    return groups


# Known entity pubkeys
KNOWN_ENTITIES = {
    '024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda': 'CREATOR (Funding Key)',
    '0280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695': 'SOLVER (Entity B)',
    '02280baa4e533e1d1e89a48ff7e1b4e61a6a4a6a3c2c0e8c62f68d2c16af42b3ab': 'UNKNOWN (Entity C)',
}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python parse_signatures.py <scriptsig_hex>")
        print("       python parse_signatures.py --batch")
        sys.exit(1)
    
    if sys.argv[1] == '--batch':
        # Process all known signatures
        from collections import OrderedDict
        sigs_hex = OrderedDict([
            ("creator_funding", "483045022100f5c26eee36e47b5ac824254398e1b82e2baaf53c645366bdd0b359e2cd01c010022067d6e273e289285360d49961152d599581446bbda5286e912073ac5f27ef266e0121024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda"),
            ("P65_spend_0", "47304402205e5915f6e43d5f98f2e08bb7fc1b0976a5fb78d76020e0d97d99d23f629dd10a02206fc85bd87d6c4867f592f26cd04d474812079923874ef92991c33179e0ab6701210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695"),
            ("P70_solve", "483045022100bc6c251b3066f84811bcbe6262ff990e03d8838730cf0698e880e4d18ab85f380220471874c4cc292bf5d990d8069e873a3ca8aa45357b1911c5f93630a6d99101210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695"),
            ("P70_creator_expose", "473044022036729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be022039ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a56823633012102280baa4e533e1d1e89a48ff7e1b4e61a6a4a6a3c2c0e8c62f68d2c16af42b3ab"),
        ])
        
        parsed = {}
        for label, hex_data in sigs_hex.items():
            try:
                result = parse_der_signature(hex_data)
                parsed[label] = result
                entity = KNOWN_ENTITIES.get(result['pubkey'], 'UNKNOWN')
                print(f"{label:25s}: r={result['r_bits']:3d}bit s={result['s_bits']:3d}bit [{entity}]")
            except ValueError as e:
                print(f"{label:25s}: ERROR — {e}")
        
        print()
        
        # Check for reuse
        reuses = check_r_reuse(parsed)
        if reuses:
            for a, b, r in reuses:
                print(f"★★★ NONCE REUSE: {a} and {b} share r={hex(r)[:20]}...")
        else:
            print(f"No r-value reuse found across {len(parsed)} signatures")
        
        print()
        
        # Bias analysis
        bias = analyze_bias(parsed)
        print(f"r-value bit distribution: {bias['r_bit_distribution']}")
        print(f"Top byte mean: {bias['r_top_byte_mean']:.1f} (expected ~127.5)")
        
        # Entity grouping
        groups = group_by_pubkey(parsed)
        print(f"\n{len(groups)} distinct signing entities found")
    else:
        # Parse single scriptSig
        script_hex = sys.argv[1]
        try:
            result = parse_der_signature(script_hex)
            print(f"r = 0x{result['r_hex']}")
            print(f"s = 0x{result['s_hex']}")
            print(f"r bit length: {result['r_bits']}")
            print(f"s bit length: {result['s_bits']}")
            print(f"SIGHASH: {result['sighash_name']}")
            print(f"PubKey: {result['pubkey']}")
            print(f"PubKey type: {result['pubkey_type']}")
            entity = KNOWN_ENTITIES.get(result['pubkey'], 'UNKNOWN')
            print(f"Entity: {entity}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
