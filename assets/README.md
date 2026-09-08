# Embedded frontend libraries

All assets are served locally and compiled into the Rust binary. No CDN is
contacted by the admin interface, and no Node build step is required.

| File | Version | Source |
| --- | --- | --- |
| `htmx.js` | 4.0.0 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.0/dist/htmx.min.js |
| `hx-sse.js` | 4.0.0 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.0/dist/ext/hx-sse.js |
| `hx-alpine-compat.js` | 4.0.0 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.0/dist/ext/hx-alpine-compat.js |
| `alpine.js` | 3.17.2 | https://cdn.jsdelivr.net/npm/alpinejs@3.17.2/dist/cdn.min.js |

htmx is distributed under the Zero-Clause BSD license; Alpine uses MIT. The
upstream license texts are included alongside these files.

Update htmx and both extensions together, update the version constants in
`src/web/assets.rs`, and run the Rust tests and browser smoke test described in
`tests/browser/README.md`. The asset fingerprint automatically changes when any
embedded script changes.

`app.js` registers Alpine timer components and attaches the session CSRF token
to htmx requests. Load htmx, its extensions, and `app.js` before Alpine, using
ordered deferred scripts. Alpine's `x-data` scopes must enclose the controls and
rows that use them, and timer components must clear their intervals on destroy.
