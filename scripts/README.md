# Pipeline

The scripts are ordered. Later stages consume what earlier ones produce, so
running them out of order will mostly work but will re-query block explorers
unnecessarily.

If you only want to understand the method, read `verify_sighash_rfc6979.py` —
it contains the core argument and depends on nothing else conceptually.

## Order

| # | Script | Produces | Notes |
|---|--------|----------|-------|
| 1 | `forensics_fetcher.py` | JSON dataset | Multi-explorer ingestion with failover. Run once; everything downstream works offline against its output. |
| 2 | `parse_signatures.py` | `(r, s, sighash_type, pubkey)` | DER decoding from raw `scriptSig` hex. Usable standalone on any Bitcoin signature. |
| 3 | `complete_signatures.py` | *(data module)* | Cached signature set from the 21-input exposure transaction, so analysis doesn't re-fetch. |
| 4 | `verify_sighash_rfc6979.py` | Nonces + compliance verdict | **The centrepiece.** Rebuilds `SIGHASH_ALL` preimages, recovers `k`, checks each against RFC 6979. |
| 5 | `nonce_recovery.py` | Recovered nonces + pattern tests | Broader statistical tests over the recovered nonce set. |
| 6 | `final_rng_attack.py` | *(negative result)* | RNG-weakness probe. **Hypothesis rejected** — kept as evidence, see its header. |
| 7 | `phase5_fingerprint.py` | Core version range | Attribution from fee policy, UTXO selection, script types. |
| 8 | `phase5b_master_key.py` | *(negative result)* | Key-derivation hypothesis testing (BIP32-like masking). No shortcut found. |
| 9 | `phase5c_hnp_trace.py` | *(negative result)* | Hidden Number Problem lattice attack over 151 same-key signatures, plus co-output tracing. |
| 10 | `phase5d_redistribution.py` | r-reuse verdict | Redistribution (97 inputs) and SegWit top-up transaction forensics. |

## Why so many negative results

Four of these stages conclude "no". That is the finding, not a failure of the
pipeline: each one closes a specific key-recovery vector, and together they
establish that the remaining puzzle outputs are not cryptographically
recoverable. Closing a vector cheaply is worth more than leaving it open and
spending GPU time on the assumption that it might pay.

## Running them

```bash
pip install requests          # stages 1-10
pip install fpylll            # stage 9 only, for lattice reduction
python forensics_fetcher.py
python verify_sighash_rfc6979.py
```

Every script writes a `*_results.txt` or `*_results.json` alongside itself.
Those are gitignored — regenerate rather than commit them.

## A note on the data

Every private key referenced anywhere in this repository belongs to an
**already-solved** puzzle and is public knowledge. No key for an unsolved
output appears here. All transaction IDs are public mainnet data and can be
checked against any block explorer.
