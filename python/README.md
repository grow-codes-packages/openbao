# grow-openbao (Python)

Python SDK for [OpenBao](https://grow-codes-packages.github.io/openbao/) by Grow Codes.
Unofficial and community maintained; "OpenBao" is a trademark of OpenBao a Series of LF Projects, LLC.

```bash
pip install grow-openbao
```

```python
from grow_openbao import OpenBaoClient, OpenBaoConfig

# Reads GROW_OPENBAO_URL, GROW_OPENBAO_TOKEN, ... from the environment.
with OpenBaoClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_openbao import AsyncOpenBaoClient

async def main() -> None:
    async with AsyncOpenBaoClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_openbao`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_openbao.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/openbao/ ·
Source: https://github.com/grow-codes-packages/openbao · Licence: Apache-2.0
