# @grow-codes/openbao

TypeScript SDK for [OpenBao](https://grow-codes-packages.github.io/openbao/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/openbao
```

```ts
import { OpenBaoClient } from "@grow-codes/openbao";

// Reads GROW_OPENBAO_URL, GROW_OPENBAO_TOKEN, timeouts, TLS and proxy settings.
const client = OpenBaoClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `OpenBaoError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/openbao/testing`.

Documentation: https://grow-codes-packages.github.io/openbao/ · Licence: Apache-2.0.
OpenBao is a trademark of OpenBao a Series of LF Projects, LLC; this package is not affiliated with or endorsed by it.
