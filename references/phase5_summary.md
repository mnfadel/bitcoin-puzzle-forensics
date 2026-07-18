# Phase 5 Complete Forensics Summary

## Phase 5A: Software Fingerprinting & Funding TX Analysis

### Funding TX (08389f34...)
- **Block:** 338479 (2015-01-15 18:07 UTC)
- **Version:** 1, **Locktime:** 0
- **Structure:** 1 input → 256 outputs
- **Size:** ~8.9 KB, **Fee:** 400,000 sat (45 sat/byte, 4.5× default)
- **Output formula:** P[i] = i × 100,000 sat (linear)
- **BIP 69:** Values sorted ascending, scriptPubKeys NOT lexicographically sorted
- **Software:** Bitcoin Core v0.9.x or v0.10.0rc4 (pre-BIP 125 anti-fee-sniping)

### Upstream TX (9b11b90a212c27c982013bafe1d4a0730e01357245f0d074051a988e4bba1662)
- **Structure:** 1 input from 173ujr... → 5 outputs
- **Outputs:**
  - vout[0]: 1.50 BTC → 1Aru8MzMVyWHxdCXN1p7e66jLKHCFUu3ZM
  - vout[1]: 2.00 BTC → 19gpJ5ry1EDppuvP9Hi43x4EX89stj8U77
  - vout[2]: 100.00 BTC → 3NTKgoHrYuktTXczxYfhLifTzfuNKcEc9B (P2SH)
  - vout[3]: 45.48 BTC → 173ujr... (change)
  - vout[4]: 32.90 BTC → 1Czoy8... (CREATOR)

---

## Phase 5B: Upstream Wallet Analysis

### Address: 173ujrhEVGqaZvPHXLqwXiSmPVMo225cqT
- **TX count:** 10,125
- **Total volume:** 1,121,838.90 BTC
- **Funded TXO:** 10,126 outputs, 112,183,890,346,683 sat
- **Spent TXO:** 10,125 outputs, 112,183,890,345,819 sat
- **Single PubKey:** 031c24239a829a89d7e12a0a5b1456ce60168c2c... (all 226 sigs)

### Signature Analysis (226 signatures)
- **Unique r-values:** 226/226 (zero reuse)
- **Cross-wallet overlap with exposure TX:** 0
- **All low-s compliant (BIP 62)**

### Nonce Bias Tests (7 tests — ALL PASSED)
1. **Bit length distribution:** r min=249, max=256, mean=255.1 (expected for uniform)
2. **MSB analysis:** 149 unique top bytes / 226 sigs (no concentration)
3. **LSB analysis:** 113 even (50.0%), 113 odd (50.0%) — perfect
4. **Small nonce detection:** 1/226 with <250 bits (expected ~0-1)
5. **Sequential correlation:** |r[i+1]-r[i]| mean=254.2 bits (independent)
6. **Clustering:** No r-values within 2^200 of each other
7. **BIP 62 low-s:** 0 high-s values

### Key Derivation Analysis (70+ solved keys)
- k_unmasked[i] = k_puzzle[i] & ((1 << (i-1)) - 1) — lower bits
- SHA256 chain: 2/69 matches (noise)
- HMAC-SHA256 with trivial keys: max 4/64 (noise)
- Consecutive XOR: full entropy
- Log-space position: random within ranges
- Modular residues: 63 unique diffs (no arithmetic progression)
- **Conclusion:** BIP32 hardened derivation. No shortcut without master key + chain code.

---

## Phase 5C: HNP, Co-Outputs, Top-Up, Redistribution Discovery

### HNP Lattice Attack Assessment
- 226 signatures available from upstream (single key)
- With 1-bit bias: need 256 sigs (marginal)
- With 2-bit bias: need 128 sigs (sufficient)
- **BUT: No bias detected → HNP WILL FAIL**
- **AND: Even if successful, recovers EXCHANGE key, not creator key**

### Co-Output Address Assessment
| Address | TX Count | Volume (BTC) | Assessment |
|---------|----------|-------------|------------|
| 1Aru8MzMVyWHxdCXN1p7e66jLKHCFUu3ZM | 2,760 | 11,870 | Exchange/service |
| 19gpJ5ry1EDppuvP9Hi43x4EX89stj8U77 | 2,039 | 1,935 | Exchange/service |
| 3NTKgoHrYuktTXczxYfhLifTzfuNKcEc9B | 500 | 18,016 | P2SH cold wallet |

### 2023 Top-Up TX (12f34b58...)
- **Sender:** bc1quksn4yxlxp80tn929gqnh8xpnngqj0fqr99q4z
- **PubKey:** 02c584e2cb49a5aabd9ceb1e5128cecd0a7ca96628e76b1491950f021a4852d8ec
- **Value:** 87,220,000,000 sat (872.20 BTC)
- **Type:** v0_p2wpkh (SegWit)
- **Structure:** 1 input → 85 outputs
- **Formula:** V[i] = puzzle_num × 9,000,000 sat
- **Missing puzzles (solved by 2023):** P70, P75, P80, P85, P90, P95, P100, P105, P110, P115, P120
- **Signature:** r=255 bits, s=252 bits, low-s, SIGHASH_ALL

### Redistribution TX (5d45587c...)
- **Structure:** 97 inputs → 109 outputs
- **Inputs:** 96 puzzle keys (P161-P256) + 1 whale uncompressed key
- **Version:** 2, **Locktime:** 0, **Fee:** 2,000,000 sat
- **Total input:** 103.5470 BTC
- **Total output:** 103.5270 BTC

---

## Phase 5D: Redistribution Deep Forensics

### Redistribution Signature Analysis
- **97 signatures total:** 96 from puzzle keys + 1 from whale
- **Unique r-values:** 97/97 (zero reuse)
- **All low-s:** 97/97
- **All compressed keys** (except whale)
- **r-bit distribution:** 248(2), 251(3), 252(3), 253(9), 254(10), 255(21), 256(49) — textbook uniform

### Whale Address: 1CENDvi6tmKGrR8RxqwURpX9WHbbKip1db
- **PubKey (uncompressed):** 047a0e5ead1210acebb8bcc1243cdc4d0d8bd3080116a1785af87dc064050f6aeb960d49694b1230854a84f9a8d51756aa3d53346717081d5ec6d59326b9eecb77
- **Compressed form:** 037a0e5ead1210acebb8bcc1243cdc4d0d8bd3080116a1785af87dc064050f6aeb
- **EC Point x:** 0x7a0e5ead1210acebb8bcc1243cdc4d0d8bd3080116a1785af87dc064050f6aeb (255 bits)
- **EC Point y:** 0x960d49694b1230854a84f9a8d51756aa3d53346717081d5ec6d59326b9eecb77 (256 bits, odd)
- **Does NOT match creator PK** (024b0faa... ≠ 037a0e5e...)
- **TX count:** 2 (received 83.53 BTC, spent all)
- **Funded by:** 14axvQP57cHGdUTK7xtoGk5CcTefk7fqpY (84 BTC)
- **Change to:** 18BoDiLDJrN96AkBswzMkm5hmM4DRrRxJ (0.468 BTC)

### SegWit Sender Trace: bc1quksn4yxlxp80tn929gqnh8xpnngqj0fqr99q4z
- **TX count:** 12
- **Total received:** 872.2003 BTC
- **Total spent:** 872.2000 BTC
- **Balance:** 0.0003 BTC (dust remnant)
- **Assessment:** Dedicated funding address (low TX count)
- **Signatures:** 1 (from top-up TX only)
- **Funding TX (308fd7b9...):** 10 inputs → 2 outputs

#### Funding Sources (872.20 BTC)
| Address | Amount (BTC) | PK Prefix |
|---------|-------------|-----------|
| bc1ql5tf824vk6dejg8pwkqugpdlzp93d3j6ume56e | 415.09 | 03dfcdc8... |
| bc1qpgf7usrugzxllvydvrnngpsw3rlewelk3qfjg4 | 284.33 (2 inputs) | 0322d014... |
| bc1q9e8hc4p5lf677p3jsmwl36hgq84x4wwhdrundc | 132.47 (2 inputs) | 0236d3a2... |
| bc1q0ndfr0pfmxdf40rcj5z6a59pfzrfacdnt38cee | 47.59 | 0393297d... |
| bc1qrm6wtwc9vu9rzsdt3hf6rat40hdndrt2tjyxd0 | 24.93 | 03673ce0... |
| bc1q63d2dwevz8kz44x5fm9lacsgptm87eqm8ah4a5 | 20.70 | 02c101c1... |
| bc1qs3rr75n56vx7dpl9jwkm4khtap236wnxh8dc47 | 37.50 (2 inputs) | 023b74bf... |

#### Dust Tracking Attacks (9 detected)
- 9 separate 300-sat deposits from different bc1q/bc1p addresses
- Third-party de-anonymization attempts on creator's SegWit address

### P161-P256 Pubkey Analysis
- **96 unique compressed public keys**
- **Prefix distribution:** 51 even-y (02) = 53.1%, 45 odd-y (03) = 46.9%
- **Expected for random:** ~50% each — consistent
- **Shared x-coordinates:** None (all independent EC points)
- **Overlap with exposure TX pubkeys:** 0 (different puzzle ranges)

### Cross-Entity Comparison
| Entity | Compressed PK | Address | Sigs | Era |
|--------|--------------|---------|------|-----|
| Creator 2015 | 024b0faa9624763002e963816b2f6774df0dedd7... | 1Czoy8... | 1 | 2015 |
| Creator 2023 | 02c584e2cb49a5aabd9ceb1e5128cecd0a7ca966... | bc1quksn4... | 1 | 2023 |
| Whale | 037a0e5ead1210acebb8bcc1243cdc4d0d8bd308... | 1CENDvi6... | 1 | 2017 |
| Upstream | 031c24239a829a89d7e12a0a5b1456ce60168c2c... | 173ujr... | 226 | 2015 |

**All keys are DIFFERENT.** Entities 1-3 assumed same person (creator), Entity 4 confirmed exchange.

---

## Final Conclusion

**All cryptographic attack vectors against Bitcoin puzzle keys are CLOSED.** The creator used proper ECDSA implementation (RFC 6979), proper key management (unique keys per era), and standard Bitcoin Core software across all transaction eras. No shortcut exists via blockchain forensics. The only remaining path to solving unsolved puzzles is computational brute force (see puzzle71-analysis skill).
