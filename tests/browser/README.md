# Admin browser smoke test

Optional development tooling; these dependencies are not needed to build or run
Sagittarius. The test uses the vendored frontend libraries and the real Rust
server, with a disposable SQLite database and unprivileged loopback ports.

```sh
cargo build
npm ci --prefix tests/browser
npm test --prefix tests/browser
```

Google Chrome must be installed. To use Playwright's Chromium instead, install
it with `cd tests/browser && npx playwright install chromium` and run with
`BROWSER_CHANNEL=chromium npm test --prefix tests/browser` from the repo root.

The test creates a temporary admin account, issues blocked DNS queries, and
checks streamed counters and rows, filter state across inserts, history
pagination, one-click actions with CSRF, SSE reconnection, conditional settings,
mobile navigation, and timers. It closes the server and deletes its temporary
database afterward. Screenshots are saved under `target/browser-smoke/`.
