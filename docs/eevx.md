# Eevx adapter

This fork adds `/eevx` (linked from Settings). It manages already-enrolled Eevx
scanners through the existing Mapping owner API; it does not install a scanner
engine, modify Android encrypted preferences, or require Protomines for Eevx.
Unclassified devices continue to use upstream MapWorld behavior.

## Setup

1. Set `ROTOMINA_SESSION_SECRET` to a persistent random secret on the server.
   The insecure upstream default was removed. Without this variable, a random
   per-process secret is used and sessions expire on restart; use one server
   process or configure the same secret for all processes.
2. Set `EEVX_OWNER_TOKEN_FILE` to an absolute file path containing a current
   **authenticated Mapping user access JWT**, with permissions `0600` or `0400`.
   Mount this file read-only for Docker. Keep it outside this repository.
   Obtain it through the existing Eevx account login/session flow; never use a
   service-role key, phone agent credential, Rotom secret, or refresh token.
   The file is reread per request, so an external authenticated session helper
   can rotate it atomically. Automatic login/refresh is not implemented here.
   Expired credentials fail closed. Never paste credentials into command lines,
   Rotomina device configuration, or browser forms.
3. Optional: set `EEVX_MAPPING_API_URL` to another trusted HTTPS Mapping owner
   API base URL. The default is the existing Eevx `/functions/v1/store` endpoint.
   Redirects and environment HTTP proxies are disabled for credential requests.
4. Log into Rotomina, open Settings → Eevx scanners, and link an ADB serial or
   host:port to its exact Mapping device UUID. This verifies account visibility
   and records the binding without ADB setup, installation or scanner start.
   Bare IPv4 addresses normalize to port 5555. Do not enroll the same hardware
   under both its USB serial and network alias.
5. Refresh the selected device before sending a command. Save worker count,
   optionally change its name / saved Rotom connection UUID, or Start / Stop.
   Create saved Rotom connections and secrets through the Mapping dashboard.

For existing MapWorld entries, stop Rotomina first and set `scanner_type` to
`eevx` in the entry before restarting and completing the link. This prevents a
live conversion while upstream installation/setup tasks may already be active.
Back up config.json first. The adapter never detects scanner type by display
name. Configure Eevx before enabling any legacy fleet automation.

All Rotomina users share this server's Mapping owner access. Use a trusted
single-owner deployment behind HTTPS; this is not per-user delegated OAuth.
The owner token has the account's existing scope, not a newly invented scoped
API credential. The adapter exposes only linked device operations and never
retrieves Rotom tokens or agent credentials. A future scoped integration token
would require backend support.

## Behavior

- GET `/mapping` finds exactly one UUID. Status exposes an allowlist of fields,
  desired/observed state, revisions, workers and existing RPC counters. Samples
  older than 30 seconds are `unknown`. Connected is not proof of useful scanning.
- POST `/mapping/devices/{uuid}` uses the page's expected revision. Configuration
  preserves the latest desired-running state. The server revision check resolves
  races after the adapter's preflight read. Conflicts and uncertain/time-out
  responses are never automatically retried. A duplicate command using an old
  revision is rejected. Refresh before retrying.
- An accepted revision is not observed completion. Refresh after the scanner's
  next heartbeat to compare applied revision and observed state. Existing API
  semantics apply: Stop does not permanently prohibit a later explicit Start.
- Rotom online/memory retains upstream ingestion, but Eevx uses an exact control
  origin (`LocalScanner-<Mapping name>`). Duplicate origins are unknown. A status
  refresh resynchronizes the origin after a Mapping rename. Management identity
  always uses UUID; Rotom does not expose that UUID in its existing origin.
- Version probing uses `com.eevx.scanner`. Existing MapWorld config writes,
  authorization, setup, UI automation, APK/game/module installs, cache clearing,
  reboots and restart paths reject Eevx devices before executing device commands.
  MapWorld's low-memory/offline restart loop skips Eevx. Local Eevx recovery stays
  in charge. The legacy restart button is explicitly unavailable for Eevx.
- New web mutations require both the Rotomina session and a CSRF token. Owner
  credentials stay server-side; backend error bodies are not echoed.

## Deliberate capability limits

Coordinated Restart, APK/game updates, maintenance/drain, external recovery and
performance switches are **not implemented**. The current Mapping API has no
atomic maintenance transaction or guarded resume primitive. Implementing these
as ordinary Stop/install/Start calls could override newer owner intent. Use the
existing Eevx verified updater until that backend contract exists; do not use
Rotomina's MapWorld updater. No weaker APK installation path was added.

The adapter does not claim CPU/PSS, APK/runtime version, valid maps, or last-good
RPC age in Mapping status: these fields are not currently exposed by that API.
Rotomina's existing ADB version and Rotom memory reporting remain separate.

## Validation

Run `python -m pip install -r requirements.txt pytest`, then
`python -m pytest -q` and `python -m compileall -q main.py scanner_adapters`.
Tests use HTTP fixtures and isolated legacy functions; they do not contact a
Mapping server or phones. Coverage includes revision races, stopped-intent
preservation, invalid controls, identity mismatch, stale status, secret
redaction, timeouts, CSRF/login checks, binding and legacy side-effect guards.
No fleet deployment or live device commands were performed for this change.
