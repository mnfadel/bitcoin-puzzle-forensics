# Bitcoin Puzzle Transactions — Cryptographic Forensic Analysis

> **Self-directed research.** Not a client engagement. Every transaction ID, address and figure
> below is public on-chain data and independently reproducible with the scripts in this repository.

A full-stack forensic review of the signature material the "1,000 BTC puzzle" creator left on-chain,
testing whether any unsolved output is recoverable through a **cryptographic weakness** rather than
brute force.

**Headline finding: the attack surface is closed.** Nonces are RFC 6979-compliant, no r-value reuse
or exploitable nonce bias exists across the analyzed signature set, and a Hidden Number Problem
lattice attack over 151 same-key signatures yields no private key. The unsolved outputs are **not
cryptographically recoverable**.

---

## Why this matters

The puzzle transactions are among the most-attacked UTXOs in Bitcoin. Most public effort goes into
brute-forcing the key ranges — an approach whose cost grows as `O(2^(n-1))` and is infeasible for the
remaining targets. The far cheaper question is whether the *creator* made an implementation mistake.

ECDSA is unforgiving here. If a signer reuses a nonce `k` across two signatures, or generates `k`
with a biased RNG, the private key falls out with algebra, not compute. Establishing whether that
door is open or shut is the first gate of any real key-recovery investigation — and it is worth
doing *before* spending money on GPUs.

This repository documents that gate being closed, with evidence.

---

## Scope

**Question:** Can any unsolved puzzle output be recovered via a flaw in the signatures, rather than
by searching the key range?

**Corpus:** four public transactions spanning the creator's activity —

| Role | TXID |
|---|---|
| Funding | `08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15` |
| Exposure (21 inputs) | `17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3` |
| Redistribution (97 inputs) | `5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164` |
| Top-up (SegWit) | `12f34b58b04dfb0233ce889f674781c0e0c7ba95482cca469125af41a78d13b3` |

---

## Method

Everything is implemented from first principles — raw transaction parsing, DER decoding and
`SIGHASH` reconstruction are done by hand rather than delegated to a signing library, so each step
is auditable.

### 1. Transaction reconstruction and SIGHASH recomputation
Fetch each raw transaction from multiple independent explorers, strip the `scriptSig` from every
input to rebuild the exact preimage that was signed, and recompute `SIGHASH_ALL` (double-SHA256)
per input. Without this step, no nonce claim can be trusted — the message hash `z` must be derived,
not assumed.

### 2. Nonce recovery and RFC 6979 verification
For the **14 inputs of the 21-input exposure transaction whose private keys are publicly known**,
recover the nonce directly:

```
k = s⁻¹ · (z + r·d)  mod n
```

then independently compute the nonce RFC 6979 *mandates* for that `(d, z)` pair via HMAC-SHA256 and
compare. Agreement proves deterministic nonce generation; disagreement would indicate an external
RNG and justify a full RNG investigation.

### 3. r-value reuse and bias analysis
Extract and cross-reference every signature in the corpus — including **97 signatures from the
redistribution transaction** and the broader upstream set — looking for repeated `r` values (which
would immediately leak a key) and for statistical bias in the nonce distribution.

### 4. Hidden Number Problem lattice attack
Assemble **151 signatures sharing a single private key**, model the partially-known-nonce problem
as a Hidden Number Problem, and attempt lattice reduction (via `fpylll`) to recover the key. This is
the strongest available attack when nonces are merely *slightly* biased rather than reused outright.

### 5. Fund tracing and software fingerprinting
Trace the flow funding → exposure → redistribution → top-up, map inputs back to puzzle indices,
analyze the uncompressed-key whale address, and fingerprint the signing software from fee policy,
UTXO selection, script types and encoding conventions.

---

## Findings

| Attack vector | Result | Implication |
|---|---|---|
| Nonce reuse (duplicate `r`) | **Not found** | No algebraic key recovery |
| RFC 6979 compliance | **Compliant** (all 14 verified inputs) | Nonces are deterministic — no RNG surface |
| Nonce bias | **Not detected** | Lattice approach has nothing to exploit |
| HNP lattice attack (151 sigs) | **No key recovered** | Confirms absence of exploitable bias |
| Signing software | Fingerprinted to a **Bitcoin Core version range** | Consistent, standard, correct signer |

**Conclusion.** There is no cryptographic shortcut. Any solution to the remaining outputs requires
brute-force search of the key range, which is computationally infeasible at these bit lengths.

A negative result, rigorously established, is the most valuable output an investigation can produce
when the alternative is burning five or six figures of GPU time chasing a door that was never open.

---

## Repository layout

```
scripts/
  forensics_fetcher.py         Multi-provider blockchain ingestion (explorer failover)
  complete_signatures.py       Signature extraction and normalization
  verify_sighash_rfc6979.py    SIGHASH reconstruction, nonce recovery, RFC 6979 verification
  final_rng_attack.py          RNG-weakness probes against the recovered nonce set
  phase5_fingerprint.py        Signing-software fingerprinting from TX structure
  phase5b_master_key.py        Key-derivation hypothesis testing
  phase5c_hnp_trace.py         HNP lattice attack + co-output address tracing
  phase5d_redistribution.py    Redistribution/top-up TX forensics, r-reuse cross-check
examples/
  rfc6979_check.py             Self-contained, runnable demo of the core compliance check
```

## Reproducing

```bash
pip install requests          # core
pip install fpylll            # optional: lattice reduction for the HNP attack

python examples/rfc6979_check.py        # start here — no network required
python scripts/verify_sighash_rfc6979.py
```

`examples/rfc6979_check.py` implements secp256k1 and RFC 6979 from scratch in ~120 lines with no
cryptographic dependencies, and demonstrates the check on both a compliant signer and a deliberately
non-compliant one.

---

## Techniques demonstrated

`secp256k1` · `ECDSA nonce recovery` · `RFC 6979` · `Hidden Number Problem` · `lattice reduction`
· `raw transaction / DER / SegWit witness parsing` · `SIGHASH reconstruction` · `transaction-graph
tracing` · `signing-software fingerprinting`

## License

MIT — see [LICENSE](LICENSE).
