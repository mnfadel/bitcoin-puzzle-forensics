#!/usr/bin/env python3
"""
Bitcoin Puzzle Nonce Recovery & Pattern Analysis

Given solved puzzle private keys and their exposure TX signatures,
this script recovers the exact ECDSA nonces and tests for patterns
that could reveal the creator's PRNG weakness.

STATUS: FULLY POPULATED — All data collected 2026-02-28 from blockstream.info API.
        14 nonces recovered and verified. All pattern tests ready to run.

Usage:
  python nonce_recovery.py                    # Run on all available data
  python nonce_recovery.py --test-all         # Run all pattern tests
"""
import sys
import hashlib
import hmac

# ═══════════════════════════════════════════════════════════════
# secp256k1 parameters
# ═══════════════════════════════════════════════════════════════
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def modinv(a, m=N):
    return pow(a, -1, m)


def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
    elif x1 == x2:
        return None
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, point=(Gx, Gy)):
    result = None
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


# ═══════════════════════════════════════════════════════════════
# Known private keys for solved puzzles with exposure TXs
# ═══════════════════════════════════════════════════════════════
SOLVED_KEYS = {
    65: 0x1a838b13505b26867,
    70: 0x349b84b6431a6c4ef1,
    75: 0x4c5ce114686a1336e07,
    80: 0xea1a5c66dcc11b5ad180,
    85: 0x11720c4f018d51b8cebba8,
    90: 0x2ce00bb2136a445c71e85bf,
    95: 0x527a792b183c7f64a0e8b1f4,
    100: 0xaf55fc59c335c8ec67ed24826,
    105: 0x16f14fc2054cd87ee6396b33df3,
    110: 0x35c0d7234df7deb0f20cf7062444,
    115: 0x60f4d11574f5deee49961d9609ac6,
    120: 0xb10f22572c497a836ea187f2e1fc23,
    125: 0x1c533b6bb7f0804e09960225e44877ac,
    130: 0x33e7665705359f04f28b88cf897c603c9,
}

# Puzzle addresses for exposure TX lookup
PUZZLE_ADDRESSES = {
    65: "18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe",
    70: "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    75: "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt",
    80: "1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe",
    85: "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr",
    90: "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU",
    95: "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC",
    100: "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F",
    105: "1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib",
    110: "12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg",
    115: "1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv",
    120: "17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT",
    125: "1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5",
    130: "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua",
    135: "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v",
    140: "1KBR6oGMnHkjwKBRaSfm1OF2bJHESe85Dq",
    145: "1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps",
    150: "1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy",
    155: "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ",
    160: "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv",
}

# ═══════════════════════════════════════════════════════════════
# Exposure TX signature data — FULLY POPULATED
# All from TX 17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3
# Block 578732, 2019-06-01 02:07:26 UTC
# ═══════════════════════════════════════════════════════════════
EXPOSURE_TX_DATA = {
    65: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 0,
        'r': 0x5546e2ea6259151ce2bc9040efd94f8019cc08c5524ca18a77f26dcd74deb10a,
        's': 0x3e94a32386348f863f6ec148077eb3ebddfd4c0333c5b2030187f6b8686fe98d,
        'z': 0x339207a21f02059dcc8bfc47f62c9ec289f3c3037bdc24c8fee9174280f182a2,
    },
    70: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 1,
        'r': 0x36729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be,
        's': 0x39ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a568236330c,
        'z': 0xfb3fbd8f0f59ee460024db999b97f475d9cc8cdbce21b3ee749810cd266b2c31,
    },
    75: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 2,
        'r': 0x1a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d,
        's': 0x3ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bcc4,
        'z': 0xf88b9f85f645b62635765fc550ae8d29ec28737bff088baa33d34719fce25447,
    },
    80: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 3,
        'r': 0x8317c7f43d629fbe025e8e05dbbe6946d5a490115fd2718b282b693ff5809d40,
        's': 0x2a7c06856091c28f49f1dd3a5bf405cc6c5743eb7aa0b66c150336b48215b2d4,
        'z': 0x42b44688c7e5aa10eff0ec27922238d4f3e4cda094bb7a61bea7849caa7b39d9,
    },
    85: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 4,
        'r': 0x0d0272274f0778f4242d4ada44d4c9ca1959238336c4754111da12adaf71a427,
        's': 0x766b5813b8f194a228331282914238b30fe7ca34afad27eecb01e602ae5ea4e7,
        'z': 0x4b0269284f3a12c5a0fe6fd247d116e777470de4d5762a2c6318273cc0a2e8a0,
    },
    90: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 5,
        'r': 0x089214e780b1be83aca76593293e871159eb392090135759dc110667bfd72e36,
        's': 0x73eb3423c444d9248d682de9670a1c48343e3554bd3eda0da070a8cd3f2ff7cc,
        'z': 0xb79f283cae2b07b53adb9773dde9b93edf91a99b9fdda83ba9c7f4e50d7c5c11,
    },
    95: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 6,
        'r': 0xdf359e57f5e14b8dccf09daf6ec634f48cfc105658e0fc1bf53926af5494498a,
        's': 0x392816fdecd0122f306b96b68a863f338abb0e874657adf22bb685b2e38826ce,
        'z': 0x6c44185598b9fd22ac7c8bd8349f5a5894c4e02da9bbd672fd59cd67ce2cfb8f,
    },
    100: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 7,
        'r': 0x537b3babb66402cc0cbe8b4856e0172c087bd98ddfb43e293219c8cccf6c7fdc,
        's': 0x4fb4d9eecf4c6cd0efb567612993a085cfbeca1163633047e6dd0c4059b06d0c,
        'z': 0x1ced6233a635419d1b20077c0e114510b00c3510baf322b1a236dccca3c13c82,
    },
    105: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 8,
        'r': 0x1e8ad3749c24db4ae05de85ee2ec33277688630f97f8ce4f883fa36c6e193d3a,
        's': 0x2f66ac26be1b44df871473a42c5e8e2cbc703465e415b064dc4854b1d8b3c99f,
        'z': 0x9c4c95b28b34558365fbcc4168debafa430c0238a27d9185d4cea23f69cddb18,
    },
    110: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 9,
        'r': 0x2ce84174d77df3974453ed9ea7075a94adc333068e2b82427cf3bf685a99b860,
        's': 0x3329eb238537ec29814802e5d19f1a34a25faac8092d41b431f10bbfa05717ed,
        'z': 0x0573b73c3fe704730cee74e1878253b2cbd253650d10dcd2a418b98e8c04ae17,
    },
    115: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 10,
        'r': 0x988f9aeafa9acd319281e757deffeb3e52160baf1096b73bababd55deb31f3f2,
        's': 0x10c209729f42f3b531116c5650df090cbe934bd5a4fc556d60f143227b54c69a,
        'z': 0x016cc9c96952b3460a847c7a831cc695ffe9289a41d5ded5aa9cb6ff3ab67f6b,
    },
    120: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 11,
        'r': 0xa285a9151ac1f9c40e88a2a80b79c702336536462a9390fd00dda999da45420a,
        's': 0x1844883eb808df18a9138ee2c13439ecf716799edcf073772f2696e4f9384f58,
        'z': 0x7e17cf7c5b7ccfaa4c7c05874e4fb4f12661662b8e33188e2e62b3739931ade5,
    },
    125: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 12,
        'r': 0x1699b85f9fd4e3c6234bc0b3378a965a08ea4f76b5359998dec6123c20ff7b64,
        's': 0x6db258553ff34e7928d877a93d219dfff683bdd6de8c54cbebafe028198285eb,
        'z': 0x5e39fb8e7f5ec05eab86c4f2618c5c96fb3c8c7ff38f37224084fffe50aaaeb0,
    },
    130: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 13,
        'r': 0x9fca00d29192007648f7e4b525f15a00a5180833617a604ec6701833eb26e580,
        's': 0x1f5ff38219a72080f77534b735badbcf57f503a33e91935ee7a859387abf5483,
        'z': 0x8d9ac8a5bc9b7ab8954e985fb9ebfc82e11c009fcccafcfb90934fb01a8c57ce,
    },
    # === UNSOLVED PUZZLES (no private key, cannot recover nonce) ===
    135: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 14,
        'r': 0xc86bec9faea4892fd98d718bdfc770d0d11c3d6bfd4328f25fe9b06bfadb9650,
        's': 0x224a322e81c044d341521f65fabdfa86d84673fb55ed7533862e37f7724931fa,
        'z': 0x92886faaf53f90a5c03d6af773a726e75097179306b980e5d28772e612e00fc7,
    },
    140: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 15,
        'r': 0xe41046e4b1b7cff1a35f8d6b0eb3448a0403885b17dbf0a0d2ff634de6d03d68,
        's': 0x213396378381f50c084aef327f2b14893b0250a917335bd1fe95431c9d2451a3,
        'z': 0xfc51df8026a78f2106970d089b81e2dad52d9a927edafd922f049c3efa3427ce,
    },
    145: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 16,
        'r': 0x975bf9ee76637ce33f4539397ebb9fd2cd2cb77d79fccfefc291d8e4bd4464bb,
        's': 0x13ca9514a84bc640b2841c09d15f4d35b5d6f2cf484e69202ca589477fea1e2f,
        'z': 0x100cd5c53eadad64b97cd46d3c7f2e8f02f5c55c4333f71585c149bd3a693eed,
    },
    150: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 17,
        'r': 0xf9746fbc71b4907756f69b3f55625d47b60ecd909233d3b1116860ebeafec6ef,
        's': 0x2db803a9ec7faf80dfbf78418102778cab6450b13549de1759fb88711241ac20,
        'z': 0xb02bee27647fee6492d70d7a569ad594462ea022ff08df7ded497da5ed579541,
    },
    155: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 18,
        'r': 0xf09bcda859dc5400124aebf36be6333655f1d10ef96adfe335cabbbec865cd5c,
        's': 0x19fb464ad88a144592c5deeee49609ee255ddf3ee17a0df3adbcde69c03257c9,
        'z': 0x84fdc53f18e9feec7c7f398e653ea001e3eb9c853c7f90aa597acacd12bfebfd,
    },
    160: {
        'tx_hash': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 19,
        'r': 0x59b071030ee30f7b32c6c6b5f4e89c6ebcada66ebc84c94c5f9a8adc7c4f8824,
        's': 0x2cb230880dd2dcb03c8dbf0674c372a5b65b4583c30b45ad9eccd7c0232c425f,
        'z': 0xaa9b5f47c69338130fc9e949ef9965379d5f99652acaa660142f6d9a290d1154,
    },
}

# Pre-computed verified nonces (from forensics_results.json, 2026-02-28)
VERIFIED_NONCES = {
    65:  0x68592d1aa72720ae7333beb3bd9d6a8e69c0567fb91720318c6289d48227c05d,
    70:  0x79577177c7a329a48d26bcf81b5db9e88b458bf8e76665f3a9ff4ab4f0cad08e,
    75:  0x123503c481722a0b4161fc681b8c786425664c102101a649d665ca788da72e7f,
    80:  0x93c7e4ce32301e1676eeef686e851d3b84a0174f7e9f0c523df966c96a24e886,
    85:  0x18fbd62747eb6a108af69ae775878af10075590fc534036710c2cb6121a24710,
    90:  0x0640c641a09b8b28b721f3c861916de8eb1fab230ad5fa33dd0e03739b4936c9,
    95:  0xb3591ed9fac56c96f20f13646c6d4a4371c1c34db9126ee203d9ecb823c46930,
    100: 0x1ac46997d73e24a7167fa8b9825927cb59d23528c69328ce71de3087a8c79c1f,
    105: 0x0129543698812c5d61918bddd6b24712b0d757aecba20a21c7971a3b652142af,
    110: 0xcaf9bf64e2440011a0c52746068da91cb7f9b1e20b0a4ac0816babbb85c4bcba,
    115: 0x9dd8dc8f8073f11e60ac3dd7a371313c847366b5dff74f46c9fac279eb3a2fea,
    120: 0x1e0283128ecdd93e9f8fa5b63841bacb2da3338f9178e36e29a13d534c1bd9fb,
    125: 0x8edf4133b6490e274b8caa8e14ffa139df1b919f785d988dc54b268f0fc98ca2,
    130: 0x48b29e355781af91077b51c2a572561c0c99a6b8a8d439fd3bf287bc8d8f19b2,
}


# ═══════════════════════════════════════════════════════════════
# Core Functions
# ═══════════════════════════════════════════════════════════════

def recover_nonce(K, r, s, z, n=N):
    """
    Recover exact ECDSA nonce k from known private key.
    
    From ECDSA: s = k^(-1) * (z + r*K) mod n
    Therefore:  k = (z + r*K) * s^(-1) mod n
    """
    s_inv = modinv(s, n)
    k = ((z + r * K) * s_inv) % n
    return k


def verify_nonce(k, r):
    """Verify k*G has x-coordinate matching r."""
    point = ec_mul(k)
    return point[0] % N == r


def recover_all_nonces():
    """Recover nonces for all puzzles with available data."""
    recovered = {}
    
    if not EXPOSURE_TX_DATA:
        print("  ⚠ No exposure TX data available yet!")
        print("  Fill in EXPOSURE_TX_DATA dictionary with blockchain data.")
        print("  See references/forensic_findings.md for instructions.")
        return recovered
    
    for puzzle_num in sorted(EXPOSURE_TX_DATA.keys()):
        tx_data = EXPOSURE_TX_DATA[puzzle_num]
        
        if puzzle_num not in SOLVED_KEYS:
            print(f"  P{puzzle_num}: Unsolved — cannot recover nonce (this is our TARGET)")
            continue
        
        K = SOLVED_KEYS[puzzle_num]
        r, s, z = tx_data['r'], tx_data['s'], tx_data['z']
        
        k = recover_nonce(K, r, s, z)
        is_valid = verify_nonce(k, r)
        
        status = "✓ VERIFIED" if is_valid else "✗ FAILED"
        print(f"  P{puzzle_num:3d}: k = 0x{k:064x} ({k.bit_length():3d} bits) [{status}]")
        
        if is_valid:
            recovered[puzzle_num] = k
        else:
            # Try with negated s (signature normalization)
            s_neg = N - s
            k2 = recover_nonce(K, r, s_neg, z)
            is_valid2 = verify_nonce(k2, r)
            if is_valid2:
                print(f"         (recovered with negated s)")
                recovered[puzzle_num] = k2
            else:
                print(f"    ⚠ Verification failed — check r,s,z extraction!")
    
    return recovered


# ═══════════════════════════════════════════════════════════════
# Pattern Analysis Tests
# ═══════════════════════════════════════════════════════════════

def test_linear_recurrence(nonces):
    """
    Test: k_{i+1} = a*k_i + b mod n (LCG-like)
    If found, predicts all future nonces.
    """
    print("\n═══ TEST 1: Linear Recurrence (k_{i+1} = a*k_i + b) ═══")
    
    sorted_keys = sorted(nonces.keys())
    k_vals = [nonces[p] for p in sorted_keys]
    
    if len(k_vals) < 3:
        print(f"  Need ≥3 nonces, have {len(k_vals)}. Skipping.")
        return None
    
    found_any = False
    for i in range(len(k_vals) - 2):
        k0, k1, k2 = k_vals[i], k_vals[i+1], k_vals[i+2]
        denom = (k1 - k0) % N
        if denom == 0:
            continue
        
        a = ((k2 - k1) * modinv(denom, N)) % N
        b = (k1 - a * k0) % N
        
        # Check ALL pairs
        all_match = True
        for j in range(len(k_vals) - 1):
            predicted = (a * k_vals[j] + b) % N
            if predicted != k_vals[j+1]:
                all_match = False
                break
        
        if all_match:
            print(f"  ★★★ LINEAR RECURRENCE FOUND!")
            print(f"  a = 0x{a:064x}")
            print(f"  b = 0x{b:064x}")
            found_any = True
            return {'type': 'linear', 'a': a, 'b': b}
    
    if not found_any:
        print(f"  No consistent linear recurrence across {len(k_vals)} nonces.")
    return None


def test_affine_pairs(nonces):
    """
    Test: k_j = a*k_i + b for each pair (i,j).
    Even non-consecutive affine relationships are exploitable.
    (See: arxiv 2504.13737)
    """
    print("\n═══ TEST 2: Affine Pair Relations (k_j = a*k_i + b) ═══")
    
    sorted_keys = sorted(nonces.keys())
    k_vals = [(p, nonces[p]) for p in sorted_keys]
    
    if len(k_vals) < 3:
        print(f"  Need ≥3 nonces. Skipping.")
        return None
    
    # For each triple, test if consistent affine relation exists
    found = []
    for i in range(len(k_vals)):
        for j in range(i+1, len(k_vals)):
            pi, ki = k_vals[i]
            pj, kj = k_vals[j]
            
            # Try small multipliers: k_j = c * k_i + d for c in {1,2,...,256}
            for c in range(1, 257):
                d = (kj - c * ki) % N
                
                # Verify on all other pairs with same stride
                stride = pj - pi
                matches = 2  # (i,j) match by construction
                for m in range(len(k_vals)):
                    if m == i or m == j:
                        continue
                    pm, km = k_vals[m]
                    # Find if pm has a pair at pm+stride
                    target_p = pm + stride
                    for n_idx in range(len(k_vals)):
                        if k_vals[n_idx][0] == target_p:
                            predicted = (c * km + d) % N
                            if predicted == k_vals[n_idx][1]:
                                matches += 1
                
                if matches >= 3:
                    print(f"  ★ Affine relation: k(P{pj}) = {c} * k(P{pi}) + 0x{d:064x}")
                    print(f"    Verified on {matches} pairs")
                    found.append({'c': c, 'd': d, 'p_i': pi, 'p_j': pj})
    
    if not found:
        print(f"  No affine relations found (tested c=1..256 for all pairs)")
    return found if found else None


def test_bit_structure(nonces):
    """
    Test for structural patterns in nonce bits:
    - Common MSBs/LSBs across nonces
    - Half-half structure (k = hash_msb || privkey_lsb)
    - Truncated nonces (many leading zeros)
    - XOR patterns
    """
    print("\n═══ TEST 3: Bit Structure Analysis ═══")
    
    sorted_keys = sorted(nonces.keys())
    k_vals = [nonces[p] for p in sorted_keys]
    
    # Bit length distribution
    print(f"\n  Nonce bit lengths:")
    for p, k in zip(sorted_keys, k_vals):
        print(f"    P{p:3d}: {k.bit_length():3d} bits")
    
    # Check for common prefix (MSBs)
    if len(k_vals) >= 2:
        print(f"\n  Common MSB analysis:")
        for bit_pos in range(256, 200, -1):
            mask = (1 << 256) - (1 << bit_pos)
            masked_vals = set((k & mask) for k in k_vals)
            if len(masked_vals) == 1:
                common = masked_vals.pop()
                print(f"    Top {256-bit_pos} bits are identical: 0x{common >> bit_pos:x}")
            else:
                print(f"    First divergence at bit {bit_pos} (top {256-bit_pos} bits)")
                break
    
    # Check for common suffix (LSBs)
    if len(k_vals) >= 2:
        print(f"\n  Common LSB analysis:")
        for num_bits in range(1, 65):
            mask = (1 << num_bits) - 1
            masked_vals = set(k & mask for k in k_vals)
            if len(masked_vals) == 1:
                common = masked_vals.pop()
                if num_bits <= 64:
                    continue  # Keep looking for longer common suffix
            else:
                if num_bits > 1:
                    print(f"    Bottom {num_bits-1} bits are identical: 0x{k_vals[0] & ((1<<(num_bits-1))-1):x}")
                else:
                    print(f"    No common LSBs")
                break
    
    # Half-half test: is upper half = hash(something)?
    # is lower half = portion of private key?
    print(f"\n  Half-half structure test:")
    for p, k in zip(sorted_keys, k_vals):
        if p in SOLVED_KEYS:
            priv = SOLVED_KEYS[p]
            k_lower = k & ((1 << 128) - 1)
            priv_lower = priv & ((1 << 128) - 1)
            # Check if lower 128 bits of k match lower bits of private key
            match_bits = 0
            for b in range(128):
                if ((k_lower >> b) & 1) == ((priv_lower >> b) & 1):
                    match_bits += 1
                else:
                    break
            if match_bits > 16:
                print(f"    ★ P{p}: k shares {match_bits} LSBs with private key!")
            else:
                print(f"    P{p}: k shares {match_bits} LSBs with private key (expected ~1 by chance)")
    
    # XOR analysis between consecutive nonces
    if len(k_vals) >= 2:
        print(f"\n  XOR pattern (consecutive nonces):")
        for i in range(len(k_vals) - 1):
            xor_val = k_vals[i] ^ k_vals[i+1]
            print(f"    P{sorted_keys[i]}⊕P{sorted_keys[i+1]}: {xor_val.bit_length():3d} bits, hw={bin(xor_val).count('1')}")


def test_rfc6979(nonces):
    """
    Test if nonces comply with RFC 6979 (deterministic ECDSA).
    
    RFC 6979: k = HMAC_DRBG(private_key, message_hash)
    If nonces are RFC 6979 compliant, they're deterministic and
    there's no PRNG weakness to exploit.
    """
    print("\n═══ TEST 4: RFC 6979 Compliance ═══")
    
    if not EXPOSURE_TX_DATA:
        print("  Need exposure TX data (r,s,z) to test RFC 6979. Skipping.")
        return None
    
    print("  Testing if k = HMAC_DRBG(K, z) per RFC 6979...")
    
    matches = 0
    tested = 0
    
    for puzzle_num in sorted(nonces.keys()):
        if puzzle_num not in SOLVED_KEYS or puzzle_num not in EXPOSURE_TX_DATA:
            continue
        
        K = SOLVED_KEYS[puzzle_num]
        z = EXPOSURE_TX_DATA[puzzle_num]['z']
        actual_k = nonces[puzzle_num]
        
        # Compute RFC 6979 deterministic k
        rfc_k = rfc6979_generate_k(K, z)
        
        tested += 1
        if rfc_k == actual_k:
            matches += 1
            print(f"    P{puzzle_num}: ✓ RFC 6979 MATCH")
        else:
            print(f"    P{puzzle_num}: ✗ NOT RFC 6979")
            print(f"      Expected: 0x{rfc_k:064x}")
            print(f"      Actual:   0x{actual_k:064x}")
    
    if tested > 0:
        print(f"\n  Result: {matches}/{tested} nonces match RFC 6979")
        if matches == tested:
            print("  ★ All nonces are RFC 6979 deterministic → NO PRNG weakness")
            print("  The creator used a compliant wallet (Bitcoin Core ≥0.9, Electrum ≥2.0)")
            return True
        elif matches > 0:
            print("  ⚠ Mixed results — some RFC 6979, some not (unusual!)")
        else:
            print("  Nonces are NOT RFC 6979 → custom/non-standard nonce generation")
            print("  ★ This increases probability of exploitable weakness!")
    
    return False


def rfc6979_generate_k(private_key, message_hash, curve_order=N):
    """
    Generate deterministic k per RFC 6979 Section 3.2.
    Uses HMAC-SHA256 as the HMAC_DRBG.
    """
    # Convert to byte arrays
    qlen = (curve_order.bit_length() + 7) // 8  # 32 for secp256k1
    
    x = private_key.to_bytes(qlen, 'big')
    h1 = message_hash.to_bytes(qlen, 'big')
    
    # Step b: V = 0x01 * 32
    V = b'\x01' * 32
    # Step c: K = 0x00 * 32
    K = b'\x00' * 32
    
    # Step d: K = HMAC_K(V || 0x00 || x || h1)
    K = hmac.new(K, V + b'\x00' + x + h1, hashlib.sha256).digest()
    # Step e: V = HMAC_K(V)
    V = hmac.new(K, V, hashlib.sha256).digest()
    # Step f: K = HMAC_K(V || 0x01 || x || h1)
    K = hmac.new(K, V + b'\x01' + x + h1, hashlib.sha256).digest()
    # Step g: V = HMAC_K(V)
    V = hmac.new(K, V, hashlib.sha256).digest()
    
    # Step h: Generate k
    while True:
        T = b''
        while len(T) < qlen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        
        k = int.from_bytes(T[:qlen], 'big')
        if 1 <= k < curve_order:
            return k
        
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def test_entropy(nonces):
    """Basic entropy analysis of recovered nonces."""
    print("\n═══ TEST 5: Entropy Analysis ═══")
    
    k_vals = [nonces[p] for p in sorted(nonces.keys())]
    
    if len(k_vals) < 3:
        print(f"  Need ≥3 nonces. Have {len(k_vals)}.")
        return
    
    # Bit frequency across all nonces
    bit_counts = [0] * 256
    for k in k_vals:
        for bit_pos in range(256):
            if (k >> bit_pos) & 1:
                bit_counts[bit_pos] += 1
    
    n_nonces = len(k_vals)
    print(f"  Analyzing {n_nonces} nonces ({n_nonces * 256} total bits)")
    
    # Check each bit position for bias
    biased_positions = []
    for pos in range(256):
        ratio = bit_counts[pos] / n_nonces
        if ratio < 0.1 or ratio > 0.9:
            biased_positions.append((pos, ratio))
    
    if biased_positions:
        print(f"  ★ Found {len(biased_positions)} biased bit positions:")
        for pos, ratio in biased_positions[:10]:
            print(f"    Bit {pos}: {ratio:.2f} (expected ~0.50)")
    else:
        print(f"  No significantly biased bit positions (all within [0.1, 0.9])")
    
    # Byte-level analysis
    print(f"\n  Top byte values:")
    top_bytes = [(k >> 248) & 0xFF for k in k_vals]
    mean_top = sum(top_bytes) / len(top_bytes)
    print(f"    Mean: {mean_top:.1f} (expected ~127.5)")
    print(f"    Range: [{min(top_bytes)}, {max(top_bytes)}]")
    print(f"    Values: {top_bytes}")
    
    # Hamming weight distribution
    print(f"\n  Hamming weight (number of 1-bits):")
    for p, k in zip(sorted(nonces.keys()), k_vals):
        hw = bin(k).count('1')
        print(f"    P{p:3d}: hw={hw:3d}/256 (expected ~128)")


def test_predict_target(nonces, pattern, target_puzzle=135):
    """
    If a pattern was found, predict a target puzzle nonce and attempt key recovery.
    Works for any unsolved puzzle (135, 140, 145, 150, 155, 160).
    """
    print(f"\n═══ EXPLOITATION: Predict P{target_puzzle} Nonce ═══")
    
    if pattern is None:
        print(f"  No pattern found — cannot predict P{target_puzzle} nonce.")
        return None
    
    if target_puzzle not in EXPOSURE_TX_DATA:
        print(f"  ⚠ P{target_puzzle} exposure TX data not available!")
        return None
    
    r_target = EXPOSURE_TX_DATA[target_puzzle]['r']
    s_target = EXPOSURE_TX_DATA[target_puzzle]['s']
    z_target = EXPOSURE_TX_DATA[target_puzzle]['z']
    
    if pattern['type'] == 'linear':
        # Predict k using linear recurrence
        a, b = pattern['a'], pattern['b']
        sorted_keys = sorted(nonces.keys())
        last_k = nonces[sorted_keys[-1]]
        
        k_predicted = (a * last_k + b) % N
        print(f"  Predicted k_{target_puzzle} = 0x{k_predicted:064x}")
        
        # Recover private key: K = (s*k - z) * r^-1
        K_target = ((s_target * k_predicted - z_target) * modinv(r_target, N)) % N
        
        print(f"  Recovered K_{target_puzzle} = 0x{K_target:064x}")
        print(f"  K bit length: {K_target.bit_length()}")
        
        # Sanity check: K should be in valid range
        if 2**(target_puzzle-1) <= K_target < 2**target_puzzle:
            print(f"  ★★★ KEY IS IN VALID RANGE FOR P{target_puzzle}!")
            pub = ec_mul(K_target)
            print(f"  Computed pubkey x: 0x{pub[0]:064x}")
            return K_target
        else:
            print(f"  ✗ Key NOT in P{target_puzzle} range — prediction likely wrong")
    
    return None


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("BITCOIN PUZZLE NONCE RECOVERY & PATTERN ANALYSIS")
    print("=" * 70)
    
    # Option: use pre-computed nonces for speed
    use_precomputed = '--fast' in sys.argv
    
    if use_precomputed:
        print("\n[STEP 1] Using pre-computed verified nonces...")
        nonces = dict(VERIFIED_NONCES)
        print(f"  Loaded {len(nonces)} pre-verified nonces")
    else:
        # Step 1: Recover nonces from scratch
        print("\n[STEP 1] Recovering ECDSA nonces from exposure TX signatures...")
        nonces = recover_all_nonces()
    
    if not nonces:
        print("\n" + "=" * 70)
        print("NO NONCES RECOVERED")
        print("=" * 70)
        return
    
    print(f"\n  Successfully recovered {len(nonces)} nonces")
    
    # Step 2: Run all pattern tests
    print("\n[STEP 2] Running pattern analysis tests...")
    
    pattern = test_linear_recurrence(nonces)
    affine = test_affine_pairs(nonces)
    test_bit_structure(nonces)
    rfc_result = test_rfc6979(nonces)
    test_entropy(nonces)
    
    # Step 3: Attempt exploitation on all unsolved puzzles
    best_pattern = pattern or (affine[0] if affine else None)
    for target in [135, 140, 145, 150, 155, 160]:
        test_predict_target(nonces, best_pattern, target)
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Nonces recovered: {len(nonces)}")
    print(f"  Linear recurrence: {'FOUND' if pattern else 'NOT FOUND'}")
    print(f"  Affine relations: {'FOUND' if affine else 'NOT FOUND'}")
    print(f"  RFC 6979 compliant: {'YES' if rfc_result is True else 'NO' if rfc_result is False else 'PENDING'}")
    print(f"  Unsolved puzzles with RSZ: {sum(1 for p in EXPOSURE_TX_DATA if p not in SOLVED_KEYS)}")


if __name__ == '__main__':
    main()
