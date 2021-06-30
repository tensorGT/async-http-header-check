# async-http-header-check

trying `asyncio` and `httpx` in python for check security headers and misconfigurations on my local test server.
by default it only allow `localhost` and `127.0.0.1` so it dont scan random websites by accident.

## features
- concurrency limit with `asyncio.Semaphore` + random jitter delay
- timeout + retry when connection fail
- scope allowlist check (`--allow-host`)
- checks missing security headers (CSP, HSTS, X-Frame-Options, etc.), CORS reflection, open redirect param, and cookie flags
- saves report in JSON and Markdown
