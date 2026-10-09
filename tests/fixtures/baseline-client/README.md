# Frozen baseline browser compatibility fixture

`api.ts` and `ScanForm.tsx` are byte-for-byte copies from commit
`8abb3078c01ce26e605c9129d48484c770b574e7`, respectively:

- `mobileshield-web/lib/api.ts`
- `mobileshield-web/app/components/ScanForm.tsx`

They are test inputs, not shipped frontend code. Do not fix their known benign
fallback: the test must demonstrate that the real old client rejects a new
backend's HTTP failure before reaching that fallback.

`check-rejection.cjs` transpiles the complete frozen API module with the currently
installed TypeScript compiler and extracts/transpiles the exact `mapStatus`
declaration from the frozen form using the TypeScript syntax tree. It needs no
old frontend packages, React rendering, running server or destination access.
The ASGI test supplies actual new-backend response status and JSON through stdin.
The fetch substitute only supplies these responses; it does not implement the
old API client's error handling or mapping.

Three real 409 responses must throw the old `ApiError`, with zero JSON result
reads and zero result mappings. HTTP 200 positive controls deliberately reach
the old `BENIGN` result for `phishing` and `unknown`, showing the harness can
detect the original defect. Those controls characterize the old client; they
are not a running old-backend or browser test. Root owns browser mismatch QA.

Run `.venv/bin/python -m pytest tests/test_rollout_compatibility.py -q` from the
repository root, with the current frontend dependencies already installed.
