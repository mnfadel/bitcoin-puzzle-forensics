# Blockchain Data — Raw Transaction Records

## Overview
This file stores raw blockchain transaction data collected from APIs.
**STATUS: FULLY POPULATED** — Data collected 2026-02-28 via blockstream.info API.

## Data Sources
- blockstream.info API: `https://blockstream.info/api` (primary, used for collection)
- mempool.space API: `https://mempool.space/api` (fallback)
- Local Bitcoin Core: `bitcoin-cli getrawtransaction {txid} true`

---

## Raw Transaction Data

### Creator Funding TX (COLLECTED)
```
TX Hash: 08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15
Block: 339085
Date: 2015-01-15 18:07:14 UTC
Structure: 1 input → 256 outputs
Total Input: 3,290,000,000 sat (32.90 BTC)
Total Output: 3,289,600,000 sat
Fee: 400,000 sat

Upstream TX: 9b11b90a212c27c982013bafe1d4a0730e01357245f0d074051a988e4bba1662
Upstream vout: 4
Creator Address: 1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F
Creator PubKey: 024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda

Signature:
  r = 0xf5c26eee36e47b5ac824254398e1b82e2baaf53c645366bdd0b359e2cd01c010 (256 bits)
  s = 0x67d6e273e289285360d49961152d599581446bbda5286e912073ac5f27ef266e (255 bits)

Status: PARSED — see forensic_findings.md for full analysis
```

---

### 2019 Exposure Transaction (COLLECTED — SINGLE TX FOR ALL 20 PUZZLES)

```
TX Hash: 17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3
Block: 578732
Date: 2019-06-01 02:07:26 UTC
Structure: 21 inputs → 1 output (1000 sat)
Version: 2
Locktime: 0
All sequences: 0xFFFFFFFF
Output: P2PKH to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH (1000 sat)

Input mapping:
  Index 0:  P65  (18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe)
  Index 1:  P70  (19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR)
  Index 2:  P75  (1J36UjUByGroXcCvmj13U6uwaVv9caEeAt)
  Index 3:  P80  (1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe)
  Index 4:  P85  (1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr)
  Index 5:  P90  (1L12FHH2FHjvTviyanuiFVfmzCy46RRATU)
  Index 6:  P95  (19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC)
  Index 7:  P100 (1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F)
  Index 8:  P105 (1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib)
  Index 9:  P110 (12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg)
  Index 10: P115 (1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv)
  Index 11: P120 (17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT)
  Index 12: P125 (1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5)
  Index 13: P130 (1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua)
  Index 14: P135 (16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v)
  Index 15: P140 (1KBR6oGMnHkjwKBRaSfm1OF2bJHESe85Dq)
  Index 16: P145 (1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps)
  Index 17: P150 (1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy)
  Index 18: P155 (1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ)
  Index 19: P160 (1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv)
  Index 20: Funding input (from separate UTXO)

NOTE: Raw TX hex is 3,698 bytes. Available in forensics_results.json.
```

---

## Compact RSZ Table (All 20 Exposure Signatures)

| Puzzle | Input | r (hex) | s (hex) | z (hex) | k (hex) | k bits |
|--------|-------|---------|---------|---------|---------|--------|
| P65 | 0 | 5546e2ea...deb10a | 3e94a323...6fe98d | 339207a2...f182a2 | 68592d1a...27c05d | 255 |
| P70 | 1 | 36729851...3842be | 39ecf6ab...36330c | fb3fbd8f...6b2c31 | 79577177...cad08e | 255 |
| P75 | 2 | 1a35a040...b0852d | 3ee9d3f0...05bcc4 | f88b9f85...e25447 | 123503c4...a72e7f | 253 |
| P80 | 3 | 8317c7f4...809d40 | 2a7c0685...15b2d4 | 42b44688...7b39d9 | 93c7e4ce...24e886 | 256 |
| P85 | 4 | 0d027227...1a427 | 766b5813...5ea4e7 | 4b026928...a2e8a0 | 18fbd627...a24710 | 253 |
| P90 | 5 | 089214e7...72e36 | 73eb3423...2ff7cc | b79f283c...7c5c11 | 0640c641...4936c9 | 251 |
| P95 | 6 | df359e57...94498a | 392816fd...8826ce | 6c441855...2cfb8f | b3591ed9...c46930 | 256 |
| P100 | 7 | 537b3bab...6c7fdc | 4fb4d9ee...b06d0c | 1ced6233...c13c82 | 1ac46997...c79c1f | 253 |
| P105 | 8 | 1e8ad374...193d3a | 2f66ac26...b3c99f | 9c4c95b2...cddb18 | 01295436...2142af | 249 |
| P110 | 9 | 2ce84174...99b860 | 3329eb23...5717ed | 0573b73c...04ae17 | caf9bf64...c4bcba | 256 |
| P115 | 10 | 988f9aea...31f3f2 | 10c20972...54c69a | 016cc9c9...b67f6b | 9dd8dc8f...3a2fea | 256 |
| P120 | 11 | a285a915...45420a | 1844883e...384f58 | 7e17cf7c...31ade5 | 1e028312...1bd9fb | 253 |
| P125 | 12 | 1699b85f...ff7b64 | 6db25855...8285eb | 5e39fb8e...aaeb0 | 8edf4133...c98ca2 | 256 |
| P130 | 13 | 9fca00d2...26e580 | 1f5ff382...bf5483 | 8d9ac8a5...8c57ce | 48b29e35...8f19b2 | 255 |
| P135 | 14 | c86bec9f...db9650 | 224a322e...4931fa | 92886faa...e00fc7 | ? | ? |
| P140 | 15 | e41046e4...d03d68 | 21339637...2451a3 | fc51df80...3427ce | ? | ? |
| P145 | 16 | 975bf9ee...4464bb | 13ca9514...ea1e2f | 100cd5c5...93eed | ? | ? |
| P150 | 17 | f9746fbc...fec6ef | 2db803a9...41ac20 | b02bee27...79541 | ? | ? |
| P155 | 18 | f09bcda8...65cd5c | 19fb464a...3257c9 | 84fdc53f...febfd | ? | ? |
| P160 | 19 | 59b07103...4f8824 | 2cb23088...2c425f | aa9b5f47...0d1154 | ? | ? |

---

## Solver Claim Transactions (COLLECTED — partial)

### P65 Claims
```
Address: 18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe
Total TXs: 11
Spending TXs:
  2024-11-06 block 869154: c1829f5f2c0cdd8c54ce47ff698b4f9078bb74cc4cc4b2c77b9b404b70073de2
  2022-03-31 block 729858: 65c7e5cbff719ff7fd32645b777cb20b69db513f1cd6a064dfcc95b69ad77acc
  2021-10-11 block 704581: 5f5a35c937c2e6cf47774024b826f4f30212e860ed606dc7787438ca7c5a88cf
  2019-06-07 block 579693: 43bb89f7d16fb47fee3eaeee0fa26aa2d0d6874c8907b2eca4ec2420bf4a9dc3
  2019-06-01 block 578732: 17e4e323... (exposure TX)
```

### P70 Claims
```
Address: 19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR
Total TXs: 7
Spending TXs:
  2021-06-24 block 688683: 7b77a599c534fba5049bc63f26edf36825cfdceb4758ea5f4f649665ecc11e9e
  2019-06-09 block 579978: 482232a3d21b7062d1aaf88a63466fd00eabcb248ae8b92aae82e4bb833afcd7
  2019-06-01 block 578732: 17e4e323... (exposure TX)
```

### P130 Claims
```
Address: 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua
Total TXs: 15
Spending TXs:
  2025-07-09 block 904689: 36c5c57527f25f26c0f74dc8baada911fa0e5f339e61bca6c095f325a1fda5ae
  2025-05-30 block 899063: 0720904719c18f1f716de32e5ed0a1264ead4f900d0dbbfc4f842008b122c3f0
  2025-01-29 block 881282: 77a962826c52d63797a59f89bf505bda655363d8a2107c4115f49c82442dba4f
  2024-12-15 block 874924: 5624d6219b20b452b0a9544d47cca03b25956ec43b38cdbc6cd5427603e4152e
  2024-09-23 block 862493: 91ec88f5d6d6cc727e0205d3aa3709fee507df05140d187846cf22aef784621a
  2019-06-01 block 578732: 17e4e323... (exposure TX)
```

---

## P71 Transaction Data
```
Address: 1BDyrQ6WoF8VN3g9SAS1iKZcPzFQnPMXs7
Balance: 710,043,657 sat (7.10043657 BTC)
TX Count: 24 (ALL incoming, ZERO outgoing)
Public Key: NOT EXPOSED

Key Incoming TXs:
  2015-01-15: 7,100,000 sat (original puzzle funding TX 08389f34...)
  2017-07-11: 63,900,000 sat (5d45587cfd1d5b0fb826805541da7d94c61fe432...)
  2023-04-16: 639,000,000 sat (12f34b58b04dfb0233ce889f674781c0e0c7ba95...)
  Various dust: 600-8,880 sat deposits
```

---

## Known Data Discrepancies (FIXED)

The following errors existed in the original skill files:

1. **P130 Address** in forensic_findings.md:
   - WRONG: `1Fo47CkGKfJ3GTHeJfRnBRAfpnjxuKE8LH`
   - CORRECT: `1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua` (from known_data.md line 169)

2. **P130 Private Key** in forensic_findings.md:
   - WRONG: `0x3e65cb5e09770e3cb8e2e0e7355e3db78e8cec18` (160 bits — invalid!)
   - CORRECT: `0x33e7665705359f04f28b88cf897c603c9` (131 bits — correct range)

3. **P130 in nonce_recovery.py**: Missing from SOLVED_KEYS dict (was commented out)

4. **Creator Funding TX block height**: Was listed as 338479 in old file, actual is 339085

All discrepancies have been corrected in the updated forensic_findings.md.
