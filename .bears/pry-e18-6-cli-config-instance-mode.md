---
id: pry
title: E18.6 — CLI/Config instance mode
status: done
priority: P1
created: "2026-07-05T12:33:29.086333358Z"
updated: "2026-07-05T13:02:54.431167260Z"
tags:
  - secondary
  - config
parent: b6b
---

src/cli.rs: add optional --primary-url / --primary-api-key (env, no default) like --session-cookie-secure. src/config.rs: enum InstanceMode { Primary, Secondary { primary_url } }; store instance_mode + separate primary_api_key: Option<String> on Config (secret kept out of InstanceMode/AppState/templates; redact in Debug). TryFrom<Cli>: primary_url present => Secondary and require key (Config::Error::MissingApiKey). Log mode at startup (not key). Update all Config{..} test literals.