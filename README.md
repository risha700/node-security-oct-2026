# Node.js October 2026 Security — reproducible differential PoC

Original advisory: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases

This standalone harness checks **all 10 CVEs** disclosed in the 21 October 2026
Node.js security release. It includes local regression fixtures for the
Brotli, HTTP Agent, and ZIP cases. Everything runs against the *Node.js binary
used to invoke the harness*, with no npm dependencies.

## Quick start

```sh
node probe.mjs
node probe.mjs --json > security-evidence.json
node probe.mjs --scan-root=/path/to/app --json > app-evidence.json
node --test test/smoke.mjs
./matrix.sh 22.23.3 22.23.4 24.22.0 24.22.1 26.12.0 26.12.1
```

Exit status: `2` = at least one vulnerable behavior reproduced, `0` = none
reproduced, `1` = harness error. `rejected` means this specific regression
input was rejected, **not** that the entire vulnerability class is impossible.
`not-applicable` denotes a Node major *not listed in the advisory*, not a
validated security guarantee. `inconclusive` means the harness cannot determine
an outcome.

### What the three added fixtures prove

| CVE | Fixture | Positive finding | Patch regression expectation |
| --- | --- | --- | --- |
| CVE-2026-111497 | `fixtures/brotli.mjs` — 22-byte **upstream Node.js regression vector** | Legacy invalid-block-switch error (`errno=-9`) in synchronous and streaming Brotli decoder | `ERR__ERROR_FORMAT_BLOCK_SWITCH`, `errno=-17` on both paths |
| CVE-2026-105481 | `fixtures/http.mjs` and `fixtures/http-peer.mjs` — loopback HTTP peer running in a worker | HTTP Agent accepts an **unsolicited response** delivered into a keep-alive socket *before* its next request (free-pool and queued-request paths) | Agent discards the poisoned socket; receives correct `/request2` response from a fresh socket |
| CVE-2026-106070 | `fixtures/zip.mjs` and `fixtures/zip-fixture.mjs` — locally crafted CRC-inconsistent stored ZIP | Built-in `node:zlib.ZipFile` returns `SCANNER-SEES-BENIGN!!` from archive prefix after failed header validation | Every repeated sync/async content read, iterator and compaction rejects with `ERR_ZIP_INVALID_ARCHIVE` |

**Brotli scope:** The small upstream invalid-block-switch input is a
*non-weaponized fix-detection regression*, **not** a proof of native memory
corruption or remote code execution. The native corruption path is dangerous
to exercise on production runtimes. For independent verification of an
out-of-bounds write, use a separate disposable ASan-instrumented build with
resource limits and controlled input. The vulnerable error signature here
shows the flawed parser behavior the upstream fix corrects.

**HTTP scope:** The peer only listens on `127.0.0.1`. It runs in another worker
thread, writes a forged response into the idle connection, and notifies the
client through `SharedArrayBuffer` while the client is blocked in
`Atomics.wait`; thus the client event loop cannot poll the pending bytes before
reassigning the connection. Both free-socket and queued-request paths are
checked. A fixture timeout or unobserved queued bytes is **inconclusive**.
The test exercises the standard `node:http` Agent, not an unrelated HTTP client.

**ZIP scope:** `node:zlib.ZipFile` is available only on the affected 26.x line.
The 158-byte ZIP file (also included as `fixtures/mismatched-header.zip`)
contains an initial decoy, a local header for `UNZIP-SEES-PAYLOAD!!!`, and a
central CRC for the *decoy*. Its conflicting local/central headers intentionally
violate ZIP consistency. Unlike normal ZIP scanners, vulnerable `ZipFile`
can accidentally return prefix bytes after it caches invalid header state.
The harness uses a temporary copy, never writes extracted ZIP content to disk,
and does not invoke system `unzip`.

References:
- Brotli regression: https://github.com/nodejs/node/commit/0392385841
- HTTP Agent regression: https://github.com/nodejs/node/commit/0683ee5f7d
- ZIP regression: https://github.com/nodejs/node/commit/745ad77156

## Matrix: vulnerable vs patched releases

The bundled `matrix.sh` automates the comparison and writes one JSON report
per version into `evidence/`. It uses the same Docker isolation as the
manual example below.

Pre-pull the images you are authorized to test. Each run is network-isolated
(no external networking, but Docker's loopback interface remains available).
For locally sourced images verify their digest, provenance, and actual `node`
binary. Running the harness as an unprivileged user with a read-only rootfs is
recommended. Our permission probes may require access to the temporary
sentinel paths they create.

```bash
for v in 22.23.3 22.23.4 24.22.0 24.22.1 26.12.0 26.12.1; do
  docker pull "node:$v"
done

mkdir -p evidence
for v in 22.23.3 22.23.4 24.22.0 24.22.1 26.12.0 26.12.1; do
  echo "Testing node:$v"
  docker run --rm --network none --cap-drop ALL \
    --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 \
    --memory 512m --pids-limit 128 \
    -v "$PWD:/harness:ro" "node:$v" \
    node /harness/probe.mjs --json > "evidence/node-$v.json"
  rc=$?
  echo "node:$v exit=$rc (2 = reproduced; 0 = none; 1 = harness error)"
done
```

Use the final **deployed** image/runtime for application inventory. Distroless
images or custom runtimes may need a separate debug container or copied Node
binary, with the same OS/runtime libraries. `node --version` alone doesn't
prove a vendor backport absent; use a vendor advisory if versions are patched
out-of-band.

## All CVEs and coverage

| CVE | Probe | Applicability | Limitations |
| --- | --- | --- | --- |
| 2026-105482 | Controlled loopback DNS NUL truncation | 22/24/26 | Checks `dns.resolve4`, not all resolver APIs |
| 2026-105483 | TLS identity synthetic SAN | 24/26 | No real handshake |
| 2026-106069 | TLS identity synthetic SAN | 22/24/26 | Resolver divergence is platform-dependent |
| 2026-111497 | **Brotli sync and streaming invariant** | 22/24/26 | Does not demonstrate native OOB/RCE |
| 2026-105481 | **HTTP Agent free and queued socket poisoning** | 22/24/26 | Local deterministic scheduling; some platforms may be inconclusive |
| 2026-106072 | TLS identity synthetic SAN | 22/24/26 | No trusted numeric-SAN handshake |
| 2026-106074 | Snapshot two-process entropy duplication | 22/24/26 | Startup-snapshot scenario only; not every SEA build |
| 2026-106070 | **ZIP local/central header mismatch** | 26 | Built-in `ZipFile`, not third-party ZIP parsers |
| 2026-106071 | Permission wildcard sentinel | 26 | One wildcard scenario |
| 2026-106073 | Permission `realpathSync` sentinel | 22/24/26 | Path metadata disclosure, not full file read |

## Reporting and remediation

1. Collect the real Node binary version, deployment image digest, platform,
   `process.versions.brotli`, `process.versions.undici`, CLI flags, and
   relevant runtime exposure paths.
2. Run the harness on the affected runtime **outside production**. Compare the
   JSON `checks[].outcome` before and after applying the security release.
3. Review hits from `--scan-root` (the scanner deliberately skips dependencies,
   secrets and generated files). A hit only identifies code to inspect; no hit
   does not establish absence of exploitation paths.
4. Upgrade an affected runtime even if a single probe says `rejected` or
   `inconclusive`. Initial fixed baselines: **22.23.4**, **24.22.1**,
   **26.12.1**. Prefer newer, supported and fully validated releases.
5. Re-run application integration tests and capture a deployment-specific
   attestation. External Brotli libraries and application-installed `undici`
   packages require separate inventory/remediation.

**Never run the malicious-stream or poisoned-socket regressions directly inside
client production processes.** They are subprocess-bound but may still crash
on certain runtimes. Use disposable test images and a resource-limited sandbox.
