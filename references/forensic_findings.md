# Forensic Findings — Collected Blockchain Data

## Table of Contents
1. [Funding Transaction](#funding-transaction)
2. [Creator Address Analysis](#creator-address)
3. [Upstream Wallet](#upstream-wallet)
4. [Collected Signatures](#collected-signatures)
5. [Parsed Signature Components](#parsed-components)
6. [Entity Pubkey Registry](#entity-pubkeys)
7. [Exposure TX Data](#exposure-tx-data)
8. [Recovered Nonces](#recovered-nonces)
9. [Unsolved Puzzle Signatures](#unsolved-signatures)
10. [P71 Status](#p71-status)

---

## Funding Transaction

```
TX Hash:    08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15
Block:      339085
Date:       January 15, 2015, 18:07 UTC
Structure:  1 input → 256 outputs (P1 through P256)

Input:
  Address:  1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F
  Value:    32.90 BTC (3,290,000,000 sat)
  Fee:      400,000 sat (0.004 BTC)

Upstream TX: 9b11b90a212c27c982013bafe1d4a0730e01357245f0d074051a988e4bba1662
  Upstream vout: 4

ScriptSig (complete hex):
483045022100f5c26eee36e47b5ac824254398e1b82e2baaf53c645366bdd0b359e2cd01c010
022067d6e273e289285360d49961152d599581446bbda5286e912073ac5f27ef266e
0121024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda

Creator Funding Signature:
  r = 0xf5c26eee36e47b5ac824254398e1b82e2baaf53c645366bdd0b359e2cd01c010
  s = 0x67d6e273e289285360d49961152d599581446bbda5286e912073ac5f27ef266e
  r_bits = 256
  s_bits = 255
  sighash = 0x01 (SIGHASH_ALL)
  pubkey = 024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda
```

---

## Creator Address

```
Address:     1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F
Total TXs:   6
Spent TXs:   1 (the puzzle funding TX above)
Received:    5 transactions (all dust from other users, not creator)

PubKey:      024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda
Key Type:    Compressed, even y-parity (02 prefix)
```

**CRITICAL NOTE:** This address has only ONE spending transaction on the entire blockchain. All multi-signature attacks (nonce reuse, HNP, Polynonce) against the creator's wallet key are impossible.

---

## Upstream Wallet

```
Address:     173ujrhEVGqaZvPHXLqwXiSmPVMo225cqT
Total TXs:   10,125+
Volume:      1,121,838+ BTC received/sent
Type:        Exchange hot wallet (NOT the creator)

Funding TX to creator: 9b11b90a212c27c982013bafe1d4a0730e01357245f0d074051a988e4bba1662
  → 181.87 BTC split into 5 outputs
  → One output (vout 4) to 1Czoy8... (creator address)
```

**Conclusion:** Upstream address is irrelevant — it belongs to an exchange (possibly Bitfinex, Huobi, or similar circa 2015). The creator withdrew from an exchange to fund the puzzles.

---

## Collected Signatures

### Creator Funding Signature
```
Label: creator_funding
ScriptSig: 483045022100f5c26eee36e47b5ac824254398e1b82e2baaf53c645366bdd0b359e2cd01c010022067d6e273e289285360d49961152d599581446bbda5286e912073ac5f27ef266e0121024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda
```

### P65 Spending Signatures (Solver Entity B, Feb 2025)
```
Label: P65_spend_0
ScriptSig: 47304402205e5915f6e43d5f98f2e08bb7fc1b0976a5fb78d76020e0d97d99d23f629dd10a02206fc85bd87d6c4867f592f26cd04d474812079923874ef92991c33179e0ab6701210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P65_spend_1
ScriptSig: 4730440220472c2aeacaf0e1084014230c637131bf59147f42d1edbf8ba09948186a051820022055c2a3793a036e5fd68a58321c4e4671438a03976506c9f3449ef3375df13101210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P65_spend_2
ScriptSig: 473044022065c12904b6fc754ae952446631baec2f3c6b37441202e1064ccb44d5de2c6c4f02201631ca3eceb5945c962b276c08cb31ebbb37a9d26b887c60e6518d8690b93f01210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695
```

### P70 Spending Signatures
```
Label: P70_solve (Solver Entity B)
ScriptSig: 483045022100bc6c251b3066f84811bcbe6262ff990e03d8838730cf0698e880e4d18ab85f380220471874c4cc292bf5d990d8069e873a3ca8aa45357b1911c5f93630a6d99101210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P70_tx1_in0 (Solver Entity B)
ScriptSig: 47304402201c4d7e9a50c2dedce7b4c395fbbb0fee30028deb2c3bb68df3a6cfb4ceb2c99602202457eb0fd2767774e5c429be0be4a45963884f17803a845050372df8c135bb01210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P70_tx1_in1 (Solver Entity B)
ScriptSig: 47304402205aeda47c6a23dbfad101c1547d7523f7c6296d1b53b194a7e00b6520720693fe02201459277ac8707933ce9ca85534f82a3527d4dd755203abf805a6055e20edb701210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P70_creator_expose (Entity C — same pubkey as P75 below, NOT puzzle key)
ScriptSig: 473044022036729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be022039ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a56823633012102280baa4e533e1d1e89a48ff7e1b4e61a6a4a6a3c2c0e8c62f68d2c16af42b3ab
```

### P75 Spending Signatures
```
Label: P75_spend_0 (Solver Entity B)
ScriptSig: 483045022100c4b1b28bce25de9c398dde13698af522cdfaa1fa6fea3255d3e3d9248e7e1fdc02204685363bb4816aa08b7c02b13693528fe47e28c1a9ed96e55ff1f3891ee201210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P75_spend_1 (Solver Entity B)
ScriptSig: 47304402205742975bda037d3cd296cf73b0982b121605f2cceed7933f97c417f42c7d85840220497df34ab3ce990d7ee308ac7d1a00653a2f8842cd9a7804b8ec04e10e49b501210280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

Label: P75_creator_expose (Entity C — same pubkey as P70 above, NOT puzzle key)
ScriptSig: 47304402201a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d02203ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bc012102280baa4e533e1d1e89a48ff7e1b4e61a6a4a6a3c2c0e8c62f68d2c16af42b3ab
```

---

## Parsed Signature Components

All parsed from DER-encoded scriptSig data above:

| Label | r bits | s bits | PubKey (first 8 hex) | Entity |
|-------|--------|--------|---------------------|--------|
| creator_funding | 256 | 255 | 024b0faa | A (Creator) |
| P65_spend_0 | 255 | 255 | 0280e1b1 | B (Solver) |
| P65_spend_1 | 255 | 255 | 0280e1b1 | B (Solver) |
| P65_spend_2 | 255 | 253 | 0280e1b1 | B (Solver) |
| P70_solve | 256 | 255 | 0280e1b1 | B (Solver) |
| P70_tx1_in0 | 253 | 254 | 0280e1b1 | B (Solver) |
| P70_tx1_in1 | 255 | 253 | 0280e1b1 | B (Solver) |
| P70_creator_expose | 254 | 254 | 02280baa | C (Unknown) |
| P75_spend_0 | 256 | 255 | 0280e1b1 | B (Solver) |
| P75_spend_1 | 255 | 255 | 0280e1b1 | B (Solver) |
| P75_creator_expose | 253 | 254 | 02280baa | C (Unknown) |

### r-Value Reuse Check
**Result: NO REUSE FOUND** — all 11 r-values are unique.

### r-Value Bias Check
- Bit lengths: 253 (×2), 254 (×1), 255 (×5), 256 (×3)
- Top byte range: [26, 245], mean: 107.3
- Expected for uniform: mean ~127.5, full range [0,255]
- **No statistically significant bias detected** (sample too small for definitive conclusion)

---

## Entity Pubkey Registry

```
ENTITY A — CREATOR (Funding):
  024b0faa9624763002e963816b2f6774df0dedd770896a9511cb5c9d90f674ecda

ENTITY B — SOLVER (Multi-puzzle claimer):
  0280e1b1af6cd8afdd9e1bc1aa28a3e0ff5b53be7af0f0f0e759549c3a9ef35695

ENTITY C — UNKNOWN (Appeared in P70/P75):
  02280baa4e533e1d1e89a48ff7e1b4e61a6a4a6a3c2c0e8c62f68d2c16af42b3ab

PUZZLE PUBLIC KEYS (from known_data.md, exposed via 2019 TXs):
  P65:  0230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b
  P70:  0290e6900a58d33393bc1097b5aed31f2e4e7cbd3e5466af958665bc0121248483
  P75:  03726b574f193e374686d8e12bc6e4142adeb06770e0a2856f5e4ad89f66044755
  P80:  037e1238f7b1ce757df94faa9a2eb261bf0aeb9f84dbf81212104e78931c2a19dc
  P85:  0329c4574a4fd8c810b7e42a4b398882b381bcd85e40c6883712912d167c83e73a
  P90:  035c38bd9ae4b10e8a250857006f3cfd98ab15a6196d9f4dfd25bc7ecc77d788d5
  P95:  02967a5905d6f3b420959a02789f96ab4c3223a2c4d2762f817b7895c5bc88a045
  P100: 03d2063d40402f030d4cc71331468827aa41a8a09bd6fd801ba77fb64f8e67e617
  P105: 03bcf7ce887ffca5e62c9cabbdb7ffa71dc183c52c04ff4ee5ee82e0c55c39d77b
  P110: 0309976ba5570966bf889196b7fdf5a0f9a1e9ab340556ec29f8bb60599616167d
  P115: 0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55
  P120: 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630
  P125: 0233709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e
  P130: 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852
  P135: 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16
  P140: 031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640
  P145: 03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5
  P150: 03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49
  P155: 035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6
  P160: 02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
```

---

## Exposure TX Data

**STATUS: FULLY POPULATED** — Data collected 2026-02-28 via blockstream.info API.

All 20 puzzle addresses (P65–P160, every 5th) share a SINGLE exposure transaction:

```
EXPOSURE TX (ALL PUZZLES):
  TX Hash:    17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3
  Block:      578732
  Date:       2019-06-01 02:07:26 UTC
  Structure:  21 inputs → 1 output (1000 sat to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
  Version:    2
  Locktime:   0
  All sequences: 0xFFFFFFFF (final, no RBF)
  Output:     P2PKH, 1000 sat

CRITICAL OBSERVATION:
  All 20 puzzle keys + 1 funding input were spent in the SAME transaction.
  Input ordering: P65=0, P70=1, P75=2, P80=3, P85=4, P90=5, P95=6,
                  P100=7, P105=8, P110=9, P115=10, P120=11, P125=12,
                  P130=13, P135=14, P140=15, P145=16, P150=17, P155=18,
                  P160=19, funding=20
```

### Fingerprint Summary
```
TX Version:       2
Locktime:         0
Witness:          No (pure legacy P2PKH)
Num Inputs:       21
Num Outputs:      1
Output Value:     1000 sat
Output Type:      P2PKH
Sequence:         All 0xFFFFFFFF
Output Address:   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

### P65 Exposure TX
```
Address: 18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe
Input Index: 0
K: 0x1a838b13505b26867
ScriptSig: 47304402205546e2ea6259151ce2bc9040efd94f8019cc08c5524ca18a77f26dcd74deb10a02203e94a32386348f863f6ec148077eb3ebddfd4c0333c5b2030187f6b8686fe98d01210230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b
r = 0x5546e2ea6259151ce2bc9040efd94f8019cc08c5524ca18a77f26dcd74deb10a (255 bits)
s = 0x3e94a32386348f863f6ec148077eb3ebddfd4c0333c5b2030187f6b8686fe98d (254 bits)
z = 0x339207a21f02059dcc8bfc47f62c9ec289f3c3037bdc24c8fee9174280f182a2
k = 0x68592d1aa72720ae7333beb3bd9d6a8e69c0567fb91720318c6289d48227c05d (255 bits) ✓ VERIFIED
```

### P70 Exposure TX
```
Address: 19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR
Input Index: 1
K: 0x349b84b6431a6c4ef1
ScriptSig: 473044022036729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be022039ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a568236330c01210290e6900a58d33393bc1097b5aed31f2e4e7cbd3e5466af958665bc0121248483
r = 0x36729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be (254 bits)
s = 0x39ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a568236330c (254 bits)
z = 0xfb3fbd8f0f59ee460024db999b97f475d9cc8cdbce21b3ee749810cd266b2c31
k = 0x79577177c7a329a48d26bcf81b5db9e88b458bf8e76665f3a9ff4ab4f0cad08e (255 bits) ✓ VERIFIED
```

### P75 Exposure TX
```
Address: 1J36UjUByGroXcCvmj13U6uwaVv9caEeAt
Input Index: 2
K: 0x4c5ce114686a1336e07
ScriptSig: 47304402201a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d02203ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bcc4012103726b574f193e374686d8e12bc6e4142adeb06770e0a2856f5e4ad89f66044755
r = 0x1a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d (253 bits)
s = 0x3ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bcc4 (254 bits)
z = 0xf88b9f85f645b62635765fc550ae8d29ec28737bff088baa33d34719fce25447
k = 0x123503c481722a0b4161fc681b8c786425664c102101a649d665ca788da72e7f (253 bits) ✓ VERIFIED
```

### P80 Exposure TX
```
Address: 1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe
Input Index: 3
K: 0xea1a5c66dcc11b5ad180
ScriptSig: 4830450221008317c7f43d629fbe025e8e05dbbe6946d5a490115fd2718b282b693ff5809d4002202a7c06856091c28f49f1dd3a5bf405cc6c5743eb7aa0b66c150336b48215b2d40121037e1238f7b1ce757df94faa9a2eb261bf0aeb9f84dbf81212104e78931c2a19dc
r = 0x8317c7f43d629fbe025e8e05dbbe6946d5a490115fd2718b282b693ff5809d40 (256 bits)
s = 0x2a7c06856091c28f49f1dd3a5bf405cc6c5743eb7aa0b66c150336b48215b2d4 (254 bits)
z = 0x42b44688c7e5aa10eff0ec27922238d4f3e4cda094bb7a61bea7849caa7b39d9
k = 0x93c7e4ce32301e1676eeef686e851d3b84a0174f7e9f0c523df966c96a24e886 (256 bits) ✓ VERIFIED
```

### P85 Exposure TX
```
Address: 1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr
Input Index: 4
K: 0x11720c4f018d51b8cebba8
ScriptSig: 47304402200d0272274f0778f4242d4ada44d4c9ca1959238336c4754111da12adaf71a4270220766b5813b8f194a228331282914238b30fe7ca34afad27eecb01e602ae5ea4e701210329c4574a4fd8c810b7e42a4b398882b381bcd85e40c6883712912d167c83e73a
r = 0x0d0272274f0778f4242d4ada44d4c9ca1959238336c4754111da12adaf71a427 (252 bits)
s = 0x766b5813b8f194a228331282914238b30fe7ca34afad27eecb01e602ae5ea4e7 (255 bits)
z = 0x4b0269284f3a12c5a0fe6fd247d116e777470de4d5762a2c6318273cc0a2e8a0
k = 0x18fbd62747eb6a108af69ae775878af10075590fc534036710c2cb6121a24710 (253 bits) ✓ VERIFIED
```

### P90 Exposure TX
```
Address: 1L12FHH2FHjvTviyanuiFVfmzCy46RRATU
Input Index: 5
K: 0x2ce00bb2136a445c71e85bf
ScriptSig: 4730440220089214e780b1be83aca76593293e871159eb392090135759dc110667bfd72e36022073eb3423c444d9248d682de9670a1c48343e3554bd3eda0da070a8cd3f2ff7cc0121035c38bd9ae4b10e8a250857006f3cfd98ab15a6196d9f4dfd25bc7ecc77d788d5
r = 0x089214e780b1be83aca76593293e871159eb392090135759dc110667bfd72e36 (252 bits)
s = 0x73eb3423c444d9248d682de9670a1c48343e3554bd3eda0da070a8cd3f2ff7cc (255 bits)
z = 0xb79f283cae2b07b53adb9773dde9b93edf91a99b9fdda83ba9c7f4e50d7c5c11
k = 0x0640c641a09b8b28b721f3c861916de8eb1fab230ad5fa33dd0e03739b4936c9 (251 bits) ✓ VERIFIED
```

### P95 Exposure TX
```
Address: 19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC
Input Index: 6
K: 0x527a792b183c7f64a0e8b1f4
ScriptSig: 483045022100df359e57f5e14b8dccf09daf6ec634f48cfc105658e0fc1bf53926af5494498a0220392816fdecd0122f306b96b68a863f338abb0e874657adf22bb685b2e38826ce012102967a5905d6f3b420959a02789f96ab4c3223a2c4d2762f817b7895c5bc88a045
r = 0xdf359e57f5e14b8dccf09daf6ec634f48cfc105658e0fc1bf53926af5494498a (256 bits)
s = 0x392816fdecd0122f306b96b68a863f338abb0e874657adf22bb685b2e38826ce (254 bits)
z = 0x6c44185598b9fd22ac7c8bd8349f5a5894c4e02da9bbd672fd59cd67ce2cfb8f
k = 0xb3591ed9fac56c96f20f13646c6d4a4371c1c34db9126ee203d9ecb823c46930 (256 bits) ✓ VERIFIED
```

### P100 Exposure TX
```
Address: 1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F
Input Index: 7
K: 0xaf55fc59c335c8ec67ed24826
ScriptSig: 4730440220537b3babb66402cc0cbe8b4856e0172c087bd98ddfb43e293219c8cccf6c7fdc02204fb4d9eecf4c6cd0efb567612993a085cfbeca1163633047e6dd0c4059b06d0c012103d2063d40402f030d4cc71331468827aa41a8a09bd6fd801ba77fb64f8e67e617
r = 0x537b3babb66402cc0cbe8b4856e0172c087bd98ddfb43e293219c8cccf6c7fdc (255 bits)
s = 0x4fb4d9eecf4c6cd0efb567612993a085cfbeca1163633047e6dd0c4059b06d0c (255 bits)
z = 0x1ced6233a635419d1b20077c0e114510b00c3510baf322b1a236dccca3c13c82
k = 0x1ac46997d73e24a7167fa8b9825927cb59d23528c69328ce71de3087a8c79c1f (253 bits) ✓ VERIFIED
```

### P105 Exposure TX
```
Address: 1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib
Input Index: 8
K: 0x16f14fc2054cd87ee6396b33df3
ScriptSig: 47304402201e8ad3749c24db4ae05de85ee2ec33277688630f97f8ce4f883fa36c6e193d3a02202f66ac26be1b44df871473a42c5e8e2cbc703465e415b064dc4854b1d8b3c99f012103bcf7ce887ffca5e62c9cabbdb7ffa71dc183c52c04ff4ee5ee82e0c55c39d77b
r = 0x1e8ad3749c24db4ae05de85ee2ec33277688630f97f8ce4f883fa36c6e193d3a (253 bits)
s = 0x2f66ac26be1b44df871473a42c5e8e2cbc703465e415b064dc4854b1d8b3c99f (254 bits)
z = 0x9c4c95b28b34558365fbcc4168debafa430c0238a27d9185d4cea23f69cddb18
k = 0x0129543698812c5d61918bddd6b24712b0d757aecba20a21c7971a3b652142af (249 bits) ✓ VERIFIED
```

### P110 Exposure TX
```
Address: 12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg
Input Index: 9
K: 0x35c0d7234df7deb0f20cf7062444
ScriptSig: 47304402202ce84174d77df3974453ed9ea7075a94adc333068e2b82427cf3bf685a99b86002203329eb238537ec29814802e5d19f1a34a25faac8092d41b431f10bbfa05717ed01210309976ba5570966bf889196b7fdf5a0f9a1e9ab340556ec29f8bb60599616167d
r = 0x2ce84174d77df3974453ed9ea7075a94adc333068e2b82427cf3bf685a99b860 (254 bits)
s = 0x3329eb238537ec29814802e5d19f1a34a25faac8092d41b431f10bbfa05717ed (254 bits)
z = 0x0573b73c3fe704730cee74e1878253b2cbd253650d10dcd2a418b98e8c04ae17
k = 0xcaf9bf64e2440011a0c52746068da91cb7f9b1e20b0a4ac0816babbb85c4bcba (256 bits) ✓ VERIFIED
```

### P115 Exposure TX
```
Address: 1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv
Input Index: 10
K: 0x60f4d11574f5deee49961d9609ac6
ScriptSig: 483045022100988f9aeafa9acd319281e757deffeb3e52160baf1096b73bababd55deb31f3f2022010c209729f42f3b531116c5650df090cbe934bd5a4fc556d60f143227b54c69a01210248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55
r = 0x988f9aeafa9acd319281e757deffeb3e52160baf1096b73bababd55deb31f3f2 (256 bits)
s = 0x10c209729f42f3b531116c5650df090cbe934bd5a4fc556d60f143227b54c69a (253 bits)
z = 0x016cc9c96952b3460a847c7a831cc695ffe9289a41d5ded5aa9cb6ff3ab67f6b
k = 0x9dd8dc8f8073f11e60ac3dd7a371313c847366b5dff74f46c9fac279eb3a2fea (256 bits) ✓ VERIFIED
```

### P120 Exposure TX
```
Address: 17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT
Input Index: 11
K: 0xb10f22572c497a836ea187f2e1fc23
ScriptSig: 483045022100a285a9151ac1f9c40e88a2a80b79c702336536462a9390fd00dda999da45420a02201844883eb808df18a9138ee2c13439ecf716799edcf073772f2696e4f9384f58012102ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630
r = 0xa285a9151ac1f9c40e88a2a80b79c702336536462a9390fd00dda999da45420a (256 bits)
s = 0x1844883eb808df18a9138ee2c13439ecf716799edcf073772f2696e4f9384f58 (253 bits)
z = 0x7e17cf7c5b7ccfaa4c7c05874e4fb4f12661662b8e33188e2e62b3739931ade5
k = 0x1e0283128ecdd93e9f8fa5b63841bacb2da3338f9178e36e29a13d534c1bd9fb (253 bits) ✓ VERIFIED
```

### P125 Exposure TX
```
Address: 1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5
Input Index: 12
K: 0x1c533b6bb7f0804e09960225e44877ac
ScriptSig: 47304402201699b85f9fd4e3c6234bc0b3378a965a08ea4f76b5359998dec6123c20ff7b6402206db258553ff34e7928d877a93d219dfff683bdd6de8c54cbebafe028198285eb01210233709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e
r = 0x1699b85f9fd4e3c6234bc0b3378a965a08ea4f76b5359998dec6123c20ff7b64 (253 bits)
s = 0x6db258553ff34e7928d877a93d219dfff683bdd6de8c54cbebafe028198285eb (255 bits)
z = 0x5e39fb8e7f5ec05eab86c4f2618c5c96fb3c8c7ff38f37224084fffe50aaaeb0
k = 0x8edf4133b6490e274b8caa8e14ffa139df1b919f785d988dc54b268f0fc98ca2 (256 bits) ✓ VERIFIED
```

### P130 Exposure TX
```
Address: 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua
Input Index: 13
K: 0x33e7665705359f04f28b88cf897c603c9
ScriptSig: 4830450221009fca00d29192007648f7e4b525f15a00a5180833617a604ec6701833eb26e58002201f5ff38219a72080f77534b735badbcf57f503a33e91935ee7a859387abf5483012103633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852
r = 0x9fca00d29192007648f7e4b525f15a00a5180833617a604ec6701833eb26e580 (256 bits)
s = 0x1f5ff38219a72080f77534b735badbcf57f503a33e91935ee7a859387abf5483 (253 bits)
z = 0x8d9ac8a5bc9b7ab8954e985fb9ebfc82e11c009fcccafcfb90934fb01a8c57ce
k = 0x48b29e355781af91077b51c2a572561c0c99a6b8a8d439fd3bf287bc8d8f19b2 (255 bits) ✓ VERIFIED
```

---

## Unsolved Puzzle Signatures

These are from the same exposure TX but nonces cannot be recovered (private key unknown):

### P135 Exposure TX (UNSOLVED)
```
Address: 16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v
Input Index: 14
PubKey: 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16
r = 0xc86bec9faea4892fd98d718bdfc770d0d11c3d6bfd4328f25fe9b06bfadb9650 (256 bits)
s = 0x224a322e81c044d341521f65fabdfa86d84673fb55ed7533862e37f7724931fa (254 bits)
z = 0x92886faaf53f90a5c03d6af773a726e75097179306b980e5d28772e612e00fc7
k = UNKNOWN (requires K to compute)
```

### P140 Exposure TX (UNSOLVED)
```
Address: 1KBR6oGMnHkjwKBRaSfm1OF2bJHESe85Dq
Input Index: 15
PubKey: 031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640
r = 0xe41046e4b1b7cff1a35f8d6b0eb3448a0403885b17dbf0a0d2ff634de6d03d68 (256 bits)
s = 0x213396378381f50c084aef327f2b14893b0250a917335bd1fe95431c9d2451a3 (254 bits)
z = 0xfc51df8026a78f2106970d089b81e2dad52d9a927edafd922f049c3efa3427ce
k = UNKNOWN
```

### P145 Exposure TX (UNSOLVED)
```
Address: 1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps
Input Index: 16
PubKey: 03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5
r = 0x975bf9ee76637ce33f4539397ebb9fd2cd2cb77d79fccfefc291d8e4bd4464bb (256 bits)
s = 0x13ca9514a84bc640b2841c09d15f4d35b5d6f2cf484e69202ca589477fea1e2f (253 bits)
z = 0x100cd5c53eadad64b97cd46d3c7f2e8f02f5c55c4333f71585c149bd3a693eed
k = UNKNOWN
```

### P150 Exposure TX (UNSOLVED)
```
Address: 1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy
Input Index: 17
PubKey: 03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49
r = 0xf9746fbc71b4907756f69b3f55625d47b60ecd909233d3b1116860ebeafec6ef (256 bits)
s = 0x2db803a9ec7faf80dfbf78418102778cab6450b13549de1759fb88711241ac20 (254 bits)
z = 0xb02bee27647fee6492d70d7a569ad594462ea022ff08df7ded497da5ed579541
k = UNKNOWN
```

### P155 Exposure TX (UNSOLVED)
```
Address: 1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ
Input Index: 18
PubKey: 035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6
r = 0xf09bcda859dc5400124aebf36be6333655f1d10ef96adfe335cabbbec865cd5c (256 bits)
s = 0x19fb464ad88a144592c5deeee49609ee255ddf3ee17a0df3adbcde69c03257c9 (253 bits)
z = 0x84fdc53f18e9feec7c7f398e653ea001e3eb9c853c7f90aa597acacd12bfebfd
k = UNKNOWN
```

### P160 Exposure TX (UNSOLVED)
```
Address: 1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv
Input Index: 19
PubKey: 02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
r = 0x59b071030ee30f7b32c6c6b5f4e89c6ebcada66ebc84c94c5f9a8adc7c4f8824 (255 bits)
s = 0x2cb230880dd2dcb03c8dbf0674c372a5b65b4583c30b45ad9eccd7c0232c425f (254 bits)
z = 0xaa9b5f47c69338130fc9e949ef9965379d5f99652acaa660142f6d9a290d1154
k = UNKNOWN
```

---

## Recovered Nonces

All 14 nonces verified: k*G.x == r for each signature.

```
Puzzle | k (hex)                                                            | Bits | Verified
P65    | 0x68592d1aa72720ae7333beb3bd9d6a8e69c0567fb91720318c6289d48227c05d | 255  | ✓
P70    | 0x79577177c7a329a48d26bcf81b5db9e88b458bf8e76665f3a9ff4ab4f0cad08e | 255  | ✓
P75    | 0x123503c481722a0b4161fc681b8c786425664c102101a649d665ca788da72e7f | 253  | ✓
P80    | 0x93c7e4ce32301e1676eeef686e851d3b84a0174f7e9f0c523df966c96a24e886 | 256  | ✓
P85    | 0x18fbd62747eb6a108af69ae775878af10075590fc534036710c2cb6121a24710 | 253  | ✓
P90    | 0x0640c641a09b8b28b721f3c861916de8eb1fab230ad5fa33dd0e03739b4936c9 | 251  | ✓
P95    | 0xb3591ed9fac56c96f20f13646c6d4a4371c1c34db9126ee203d9ecb823c46930 | 256  | ✓
P100   | 0x1ac46997d73e24a7167fa8b9825927cb59d23528c69328ce71de3087a8c79c1f | 253  | ✓
P105   | 0x0129543698812c5d61918bddd6b24712b0d757aecba20a21c7971a3b652142af | 249  | ✓
P110   | 0xcaf9bf64e2440011a0c52746068da91cb7f9b1e20b0a4ac0816babbb85c4bcba | 256  | ✓
P115   | 0x9dd8dc8f8073f11e60ac3dd7a371313c847366b5dff74f46c9fac279eb3a2fea | 256  | ✓
P120   | 0x1e0283128ecdd93e9f8fa5b63841bacb2da3338f9178e36e29a13d534c1bd9fb | 253  | ✓
P125   | 0x8edf4133b6490e274b8caa8e14ffa139df1b919f785d988dc54b268f0fc98ca2 | 256  | ✓
P130   | 0x48b29e355781af91077b51c2a572561c0c99a6b8a8d439fd3bf287bc8d8f19b2 | 255  | ✓
```

### Nonce Pattern Analysis Results — PHASE 3 COMPLETE (Feb 28, 2026)

```
═══════════════════════════════════════════════════════════════
  DEFINITIVE RESULT: ALL 14 NONCES ARE RFC 6979 COMPLIANT
  Creator uses Bitcoin Core ≥ v0.10 (HMAC-SHA256 + BIP 62 low-s)
═══════════════════════════════════════════════════════════════

Test 1 — RFC 6979 compliance (with s-normalization):
  RESULT: 14/14 MATCH ✅
  4 direct matches: P85, P90, P120, P125 (original s ≤ n/2)
  10 via n-k:       P65, P70, P75, P80, P95, P100, P105, P110, P115, P130 (s > n/2, normalized)
  
  KEY INSIGHT: When Bitcoin Core normalizes s > n/2 to s' = n - s,
  nonce recovery from s' yields k' = n - k_rfc instead of k_rfc.
  Checking both k and n-k against RFC 6979 produces perfect 14/14 match.

Test 2 — Polynonce (polynomial recurrence, degrees 1-5):
  RESULT: NO PATTERN ✗
  Degree 1 (affine): 0/11 consecutive pairs verified
  Degrees 2-5: 0 verification pairs matched

Test 3 — Pairwise affine k_j = a*k_i + b mod n:
  RESULT: FALSE POSITIVES ONLY ✗
  202 "affine hits" found, but ALL are constant-map degeneracies
  (when two pairs share same target, affine map becomes k→constant)

Test 4 — LCG/PRNG structure k_{i+1} = a*k_i + c mod m:
  RESULT: NONE DETECTED ✗
  Tested mod n: 0/11 consecutive verified
  Tested mod 2^256: 0/11 consecutive verified

Test 5 — GCD and common factor analysis:
  RESULT: NORMAL FOR RANDOM ✗
  GCD(all 14) = 1
  Non-trivial pairwise: 35/91 (expected ~36 for random)
  Notable: GCD(P95,P125)=150, GCD(P80,P85)=134

Test 6 — Nonce-private key relationship k = f(K):
  RESULT: NONE ✗
  Tested: k = SHA256(K), k = HMAC-SHA256(K,''), XOR structure
  XOR(k,K) bit lengths: 249-256 bits (full-range, no structure)

Test 7 — Byte entropy:
  RESULT: HEALTHY ✗ (no weakness)
  Total bytes: 448 (14 × 32)
  Unique values: 209/256
  Shannon entropy: 7.51/8.0 bits

Test 8 — Modular bias (Chi-squared across primes 2-31):
  RESULT: WITHIN NORMAL RANGE ✗
  All χ² values below significance thresholds
  mod 17 highest at χ²=27.29 (threshold ~51)

Test 9 — Bit structure:
  RESULT: NO PATTERNS ✗
  XOR consecutive bit lengths: 253-256 bits
  Top 8/16/32/64 bits: all 14 unique
  Bottom 8/16/32 bits: all 14 unique

Test 10 — Nonce bit-length distribution:
  249 bits: 1 (P105)
  251 bits: 1 (P90)
  253 bits: 4 (P75, P85, P100, P120)
  255 bits: 3 (P65, P70, P130)
  256 bits: 5 (P80, P95, P110, P115, P125)
  Range: 249–256 bits, Mean: ~254 bits

Test 11 — RFC 6979 variant elimination:
  Standard HMAC-SHA256, 32-byte key: 14/14 ✅ CONFIRMED
  HMAC-SHA512: 0/14 ✗
  Natural key byte length: 0/14 ✗
  z reduced mod n: 4/14 (no improvement) ✗
  libsecp256k1 algo16: 0/14 ✗
  Multiple candidates (2nd-20th): 0/10 additional ✗
  Extra entropy (section 3.6): 0/14 ✗

FORENSICS NONCE ATTACK: PERMANENTLY CLOSED
```

### Verified SIGHASH Values (z) — Independently Recomputed

These z values were computed from the raw TX hex by properly implementing
SIGHASH_ALL per input (placing scriptPubKey in current input, zeroing others).

```
P65  z = 0x339207a21f02059dcc8bfc47f62c9ec289f3c3037bdc24c8fee9174280f182a2
P70  z = 0xfb3fbd8f0f59ee460024db999b97f475d9cc8cdbce21b3ee749810cd266b2c31
P75  z = 0xf88b9f85f645b62635765fc550ae8d29ec28737bff088baa33d34719fce25447
P80  z = 0x42b44688c7e5aa10eff0ec27922238d4f3e4cda094bb7a61bea7849caa7b39d9
P85  z = 0x4b0269284f3a12c5a0fe6fd247d116e777470de4d5762a2c6318273cc0a2e8a0
P90  z = 0xb79f283cae2b07b53adb9773dde9b93edf91a99b9fdda83ba9c7f4e50d7c5c11
P95  z = 0x6c44185598b9fd22ac7c8bd8349f5a5894c4e02da9bbd672fd59cd67ce2cfb8f
P100 z = 0x1ced6233a635419d1b20077c0e114510b00c3510baf322b1a236dccca3c13c82
P105 z = 0x9c4c95b28b34558365fbcc4168debafa430c0238a27d9185d4cea23f69cddb18
P110 z = 0x0573b73c3fe704730cee74e1878253b2cbd253650d10dcd2a418b98e8c04ae17
P115 z = 0x016cc9c96952b3460a847c7a831cc695ffe9289a41d5ded5aa9cb6ff3ab67f6b
P120 z = 0x7e17cf7c5b7ccfaa4c7c05874e4fb4f12661662b8e33188e2e62b3739931ade5
P125 z = 0x5e39fb8e7f5ec05eab86c4f2618c5c96fb3c8c7ff38f37224084fffe50aaaeb0
P130 z = 0x8d9ac8a5bc9b7ab8954e985fb9ebfc82e11c009fcccafcfb90934fb01a8c57ce
```

### Unsolved Puzzle z-Values (for future reference)

```
P135 z = 0x92886faaf53f90a5c03d6af773a726e75097179306b980e5d28772e612e00fc7
P140 z = 0xfc51df8026a78f2106970d089b81e2dad52d9a927edafd922f049c3efa3427ce
P145 z = 0x100cd5c53eadad64b97cd46d3c7f2e8f02f5c55c4333f71585c149bd3a693eed
P150 z = 0xb02bee27647fee6492d70d7a569ad594462ea022ff08df7ded497da5ed579541
P155 z = 0x84fdc53f18e9feec7c7f398e653ea001e3eb9c853c7f90aa597acacd12bfebfd
P160 z = 0xaa9b5f47c69338130fc9e949ef9965379d5f99652acaa660142f6d9a290d1154
```

---

## P71 Status

```
Address:     1BDyrQ6WoF8VN3g9SAS1iKZcPzFQnPMXs7
Balance:     710,043,657 sat (7.10043657 BTC)
TX Count:    24 (all incoming, ZERO outgoing)
Public Key:  NOT EXPOSED (no spending transactions)

Funding History:
  2015-01-15: 7,100,000 sat (original puzzle funding)
  2017-07-11: 63,900,000 sat (additional funding)
  2023-04-16: 639,000,000 sat (major additional funding ~6.39 BTC)
  2023-09-25+: Various small dust deposits (710-8880 sat)

CRITICAL: P71 has NO spending transactions, so its public key has
never been exposed on the blockchain. This means:
  - No signature data available for P71
  - No nonce recovery possible
  - No ECDSA-based attacks applicable
  - Only brute-force key search within [2^70, 2^71-1] range
```
