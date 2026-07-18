"""
Extracted signature data from the exposure transaction - reference dataset.
==========================================================================

The (r, s) pairs and message hashes parsed out of the 21 inputs of exposure
transaction 17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3,
kept as a module so the analysis scripts can import them without re-fetching
from a block explorer on every run.

Each value is annotated with its source transaction and originating address.
Regenerate with forensics_fetcher.py + parse_signatures.py if you would rather
derive them yourself than trust this file - everything here is public chain data.
"""

COMPLETE_R_VALUES = [
    0x975bf9ee76637ce33f4539397ebb9fd2cd2cb77d79fccfefc291d8e4bd4464bb,  # 17e4e323cfbc68d7... from 19GpszRNUe...
    0xdbe3c94527070a4d76be9f2d3fb54dba3b5dcf520d19c444f4d46bc753204c41,  # 17e4e323cfbc68d7... from 1PvaqLqRAi...
    0xf9746fbc71b4907756f69b3f55625d47b60ecd909233d3b1116860ebeafec6ef,  # 17e4e323cfbc68d7... from 1MUJSJYtGP...
    0x988f9aeafa9acd319281e757deffeb3e52160baf1096b73bababd55deb31f3f2,  # 17e4e323cfbc68d7... from 1NLbHuJebV...
    0xd0272274f0778f4242d4ada44d4c9ca1959238336c4754111da12adaf71a427,  # 17e4e323cfbc68d7... from 1Kh22PvXER...
    0x89214e780b1be83aca76593293e871159eb392090135759dc110667bfd72e36,  # 17e4e323cfbc68d7... from 1L12FHH2FH...
    0x2ce84174d77df3974453ed9ea7075a94adc333068e2b82427cf3bf685a99b860,  # 17e4e323cfbc68d7... from 12JzYkkN76...
    0x8317c7f43d629fbe025e8e05dbbe6946d5a490115fd2718b282b693ff5809d40,  # 17e4e323cfbc68d7... from 1BCf6rHUW6...
    0x36729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be,  # 17e4e323cfbc68d7... from 19YZECXj3S...
    0xa285a9151ac1f9c40e88a2a80b79c702336536462a9390fd00dda999da45420a,  # 17e4e323cfbc68d7... from 17s2b9ksz5...
    0xc86bec9faea4892fd98d718bdfc770d0d11c3d6bfd4328f25fe9b06bfadb9650,  # 17e4e323cfbc68d7... from 16RGFo6hjq...
    0x1e8ad3749c24db4ae05de85ee2ec33277688630f97f8ce4f883fa36c6e193d3a,  # 17e4e323cfbc68d7... from 1CMjscKB3Q...
    0x537b3babb66402cc0cbe8b4856e0172c087bd98ddfb43e293219c8cccf6c7fdc,  # 17e4e323cfbc68d7... from 1KCgMv8fo2...
    0x1699b85f9fd4e3c6234bc0b3378a965a08ea4f76b5359998dec6123c20ff7b64,  # 17e4e323cfbc68d7... from 1PXAyUB8Zo...
    0xdf359e57f5e14b8dccf09daf6ec634f48cfc105658e0fc1bf53926af5494498a,  # 17e4e323cfbc68d7... from 19eVSDuizy...
    0x1a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d,  # 17e4e323cfbc68d7... from 1J36UjUByG...
    0xf09bcda859dc5400124aebf36be6333655f1d10ef96adfe335cabbbec865cd5c,  # 17e4e323cfbc68d7... from 1AoeP37TmH...
    0x9fca00d29192007648f7e4b525f15a00a5180833617a604ec6701833eb26e580,  # 17e4e323cfbc68d7... from 1Fo65aKq8s...
    0x59b071030ee30f7b32c6c6b5f4e89c6ebcada66ebc84c94c5f9a8adc7c4f8824,  # 17e4e323cfbc68d7... from 1NBC8uXJy1...
    0xe41046e4b1b7cff1a35f8d6b0eb3448a0403885b17dbf0a0d2ff634de6d03d68,  # 17e4e323cfbc68d7... from 1QKBaU6WAe...
    0x5546e2ea6259151ce2bc9040efd94f8019cc08c5524ca18a77f26dcd74deb10a,  # 17e4e323cfbc68d7... from 18ZMbwUFLM...
]

COMPLETE_S_VALUES = [
    0x13ca9514a84bc640b2841c09d15f4d35b5d6f2cf484e69202ca589477fea1e2f,  # 17e4e323cfbc68d7...
    0x21b568c27fdde319211b8a5f13d990dc7234b3d28e6e4095900b03ef2aa4488c,  # 17e4e323cfbc68d7...
    0x2db803a9ec7faf80dfbf78418102778cab6450b13549de1759fb88711241ac20,  # 17e4e323cfbc68d7...
    0x10c209729f42f3b531116c5650df090cbe934bd5a4fc556d60f143227b54c69a,  # 17e4e323cfbc68d7...
    0x766b5813b8f194a228331282914238b30fe7ca34afad27eecb01e602ae5ea4e7,  # 17e4e323cfbc68d7...
    0x73eb3423c444d9248d682de9670a1c48343e3554bd3eda0da070a8cd3f2ff7cc,  # 17e4e323cfbc68d7...
    0x3329eb238537ec29814802e5d19f1a34a25faac8092d41b431f10bbfa05717ed,  # 17e4e323cfbc68d7...
    0x2a7c06856091c28f49f1dd3a5bf405cc6c5743eb7aa0b66c150336b48215b2d4,  # 17e4e323cfbc68d7...
    0x39ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a568236330c,  # 17e4e323cfbc68d7...
    0x1844883eb808df18a9138ee2c13439ecf716799edcf073772f2696e4f9384f58,  # 17e4e323cfbc68d7...
    0x224a322e81c044d341521f65fabdfa86d84673fb55ed7533862e37f7724931fa,  # 17e4e323cfbc68d7...
    0x2f66ac26be1b44df871473a42c5e8e2cbc703465e415b064dc4854b1d8b3c99f,  # 17e4e323cfbc68d7...
    0x4fb4d9eecf4c6cd0efb567612993a085cfbeca1163633047e6dd0c4059b06d0c,  # 17e4e323cfbc68d7...
    0x6db258553ff34e7928d877a93d219dfff683bdd6de8c54cbebafe028198285eb,  # 17e4e323cfbc68d7...
    0x392816fdecd0122f306b96b68a863f338abb0e874657adf22bb685b2e38826ce,  # 17e4e323cfbc68d7...
    0x3ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bcc4,  # 17e4e323cfbc68d7...
    0x19fb464ad88a144592c5deeee49609ee255ddf3ee17a0df3adbcde69c03257c9,  # 17e4e323cfbc68d7...
    0x1f5ff38219a72080f77534b735badbcf57f503a33e91935ee7a859387abf5483,  # 17e4e323cfbc68d7...
    0x2cb230880dd2dcb03c8dbf0674c372a5b65b4583c30b45ad9eccd7c0232c425f,  # 17e4e323cfbc68d7...
    0x213396378381f50c084aef327f2b14893b0250a917335bd1fe95431c9d2451a3,  # 17e4e323cfbc68d7...
    0x3e94a32386348f863f6ec148077eb3ebddfd4c0333c5b2030187f6b8686fe98d,  # 17e4e323cfbc68d7...
]

SIGNATURE_DETAILS = [
    {
        'address': '19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 16,
        'r': 0x975bf9ee76637ce33f4539397ebb9fd2cd2cb77d79fccfefc291d8e4bd4464bb,
        's': 0x13ca9514a84bc640b2841c09d15f4d35b5d6f2cf484e69202ca589477fea1e2f,
    },
    {
        'address': '1PvaqLqRAivje7CactLR55xQBYvBeaDrXN',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 20,
        'r': 0xdbe3c94527070a4d76be9f2d3fb54dba3b5dcf520d19c444f4d46bc753204c41,
        's': 0x21b568c27fdde319211b8a5f13d990dc7234b3d28e6e4095900b03ef2aa4488c,
    },
    {
        'address': '1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 17,
        'r': 0xf9746fbc71b4907756f69b3f55625d47b60ecd909233d3b1116860ebeafec6ef,
        's': 0x2db803a9ec7faf80dfbf78418102778cab6450b13549de1759fb88711241ac20,
    },
    {
        'address': '1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 10,
        'r': 0x988f9aeafa9acd319281e757deffeb3e52160baf1096b73bababd55deb31f3f2,
        's': 0x10c209729f42f3b531116c5650df090cbe934bd5a4fc556d60f143227b54c69a,
    },
    {
        'address': '1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 4,
        'r': 0xd0272274f0778f4242d4ada44d4c9ca1959238336c4754111da12adaf71a427,
        's': 0x766b5813b8f194a228331282914238b30fe7ca34afad27eecb01e602ae5ea4e7,
    },
    {
        'address': '1L12FHH2FHjvTviyanuiFVfmzCy46RRATU',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 5,
        'r': 0x89214e780b1be83aca76593293e871159eb392090135759dc110667bfd72e36,
        's': 0x73eb3423c444d9248d682de9670a1c48343e3554bd3eda0da070a8cd3f2ff7cc,
    },
    {
        'address': '12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 9,
        'r': 0x2ce84174d77df3974453ed9ea7075a94adc333068e2b82427cf3bf685a99b860,
        's': 0x3329eb238537ec29814802e5d19f1a34a25faac8092d41b431f10bbfa05717ed,
    },
    {
        'address': '1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 3,
        'r': 0x8317c7f43d629fbe025e8e05dbbe6946d5a490115fd2718b282b693ff5809d40,
        's': 0x2a7c06856091c28f49f1dd3a5bf405cc6c5743eb7aa0b66c150336b48215b2d4,
    },
    {
        'address': '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 1,
        'r': 0x36729851ae5082e0d70786af455cd47fa29162c459f73c1041f2663c783842be,
        's': 0x39ecf6abb2c43d62bce1d9cf77d3bbabb5ccad0f87399990f6ba2a568236330c,
    },
    {
        'address': '17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 11,
        'r': 0xa285a9151ac1f9c40e88a2a80b79c702336536462a9390fd00dda999da45420a,
        's': 0x1844883eb808df18a9138ee2c13439ecf716799edcf073772f2696e4f9384f58,
    },
    {
        'address': '16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 14,
        'r': 0xc86bec9faea4892fd98d718bdfc770d0d11c3d6bfd4328f25fe9b06bfadb9650,
        's': 0x224a322e81c044d341521f65fabdfa86d84673fb55ed7533862e37f7724931fa,
    },
    {
        'address': '1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 8,
        'r': 0x1e8ad3749c24db4ae05de85ee2ec33277688630f97f8ce4f883fa36c6e193d3a,
        's': 0x2f66ac26be1b44df871473a42c5e8e2cbc703465e415b064dc4854b1d8b3c99f,
    },
    {
        'address': '1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 7,
        'r': 0x537b3babb66402cc0cbe8b4856e0172c087bd98ddfb43e293219c8cccf6c7fdc,
        's': 0x4fb4d9eecf4c6cd0efb567612993a085cfbeca1163633047e6dd0c4059b06d0c,
    },
    {
        'address': '1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 12,
        'r': 0x1699b85f9fd4e3c6234bc0b3378a965a08ea4f76b5359998dec6123c20ff7b64,
        's': 0x6db258553ff34e7928d877a93d219dfff683bdd6de8c54cbebafe028198285eb,
    },
    {
        'address': '19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 6,
        'r': 0xdf359e57f5e14b8dccf09daf6ec634f48cfc105658e0fc1bf53926af5494498a,
        's': 0x392816fdecd0122f306b96b68a863f338abb0e874657adf22bb685b2e38826ce,
    },
    {
        'address': '1J36UjUByGroXcCvmj13U6uwaVv9caEeAt',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 2,
        'r': 0x1a35a0409ba510b8055ab7767a06952783f3ec175c7f089cbad402a682b0852d,
        's': 0x3ee9d3f06eeadc7ccae821ac4d9f16c0df1ac5e977c9d1bceac968ed9f05bcc4,
    },
    {
        'address': '1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 18,
        'r': 0xf09bcda859dc5400124aebf36be6333655f1d10ef96adfe335cabbbec865cd5c,
        's': 0x19fb464ad88a144592c5deeee49609ee255ddf3ee17a0df3adbcde69c03257c9,
    },
    {
        'address': '1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 13,
        'r': 0x9fca00d29192007648f7e4b525f15a00a5180833617a604ec6701833eb26e580,
        's': 0x1f5ff38219a72080f77534b735badbcf57f503a33e91935ee7a859387abf5483,
    },
    {
        'address': '1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 19,
        'r': 0x59b071030ee30f7b32c6c6b5f4e89c6ebcada66ebc84c94c5f9a8adc7c4f8824,
        's': 0x2cb230880dd2dcb03c8dbf0674c372a5b65b4583c30b45ad9eccd7c0232c425f,
    },
    {
        'address': '1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 15,
        'r': 0xe41046e4b1b7cff1a35f8d6b0eb3448a0403885b17dbf0a0d2ff634de6d03d68,
        's': 0x213396378381f50c084aef327f2b14893b0250a917335bd1fe95431c9d2451a3,
    },
    {
        'address': '18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe',
        'txid': '17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3',
        'input_index': 0,
        'r': 0x5546e2ea6259151ce2bc9040efd94f8019cc08c5524ca18a77f26dcd74deb10a,
        's': 0x3e94a32386348f863f6ec148077eb3ebddfd4c0333c5b2030187f6b8686fe98d,
    },
]
