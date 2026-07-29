# Source

- Project: [Babeltrace 2](https://github.com/efficios/babeltrace)
- Pinned upstream directory:
  [`tests/data/ctf-traces/2/succeed/smalltrace`](https://github.com/efficios/babeltrace/tree/e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5/tests/data/ctf-traces/2/succeed/smalltrace)
- Pinned commit: `e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5`
- License: CC0-1.0
  ([`tests/data/*` in the pinned `.reuse/dep5`](https://github.com/efficios/babeltrace/blob/e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5/.reuse/dep5))
- Fetch and integrity checks:
  [`scripts/fetch_babeltrace_sample.py`](../../../scripts/fetch_babeltrace_sample.py)

The `metadata` and `dummystream` files are downloaded rather than manually
reproduced so their binary representation stays identical to the upstream test.

| File | Bytes | SHA-256 |
|---|---:|---|
| `metadata` | 1,195 | `476e8f7afb93e2cbe1f908733291f54e181a03b255ee1077823e8a3c8ffb0130` |
| `dummystream` | 69 | `a5329aa463617c9d780578bf6ef97994e6d702213834f10f7002ffbfbd571e3c` |

From the repository root, refetch both files and verify these pinned sizes and
digests with:

```powershell
python .\scripts\fetch_babeltrace_sample.py
```

The sample is a decoder seed. Router State Lab does not include a built-in CTF
decoder; a device plug-in must provide the corresponding trace decoder before
this input can become normalized router events.
