# Eevx management adapter

The `/eevx` page manages enrolled Eevx scanners through the Mapping owner API.
Eevx remains independent of Rotomina and owns local scanner recovery. Devices
without `scanner_type: eevx` keep upstream MapWorld behavior.

## Renewable account connection

Configure these server variables and mount a **private writable directory** for
session storage (not a single bind-mounted file; rotation uses atomic rename):

- `ROTOMINA_SESSION_SECRET`: persistent random session signing secret.
- `EEVX_OWNER_SESSION_FILE`: e.g. `/run/eevx-session/owner.json`.
- `EEVX_SUPABASE_ANON_KEY`: the public key from the Eevx site's `/api/config`.
- `EEVX_SUPABASE_URL`: optional; defaults to the existing Eevx Supabase origin.
- `EEVX_MAPPING_API_URL`: optional; defaults to the existing Mapping owner API.

Log into Rotomina, open Settings → Eevx scanners, then Connect account using the
same verified Eevx email/password accepted by the APK. Passwords are transient.
The server stores only the access and refresh tokens, with mode 0600. It renews
on demand before expiry, serializes rotation across threads/processes using a
sidecar lock, and atomically persists the replacement tokens. A lost refresh
response or crash during rotation requires sign-in again, rather than blindly
replaying an old refresh token. Revocation and account errors fail closed.

Use HTTPS or the private Tailscale deployment. All Rotomina admins share this
owner session; this is not per-user delegated OAuth or a narrowly scoped service
token. Never supply a service-role key or phone agent token. Legacy
`EEVX_OWNER_TOKEN_FILE` remains supported when no session file is configured, but
that access-token-only mode cannot renew itself.

## Device setup and controls

Link an ADB serial/host:port to its exact Mapping UUID on `/eevx`. Linking verifies
account visibility without installing, connecting ADB, or starting the scanner.
Bare IPv4 addresses normalize to port 5555. Do not register the same hardware
under both its USB and network aliases. For an existing MapWorld entry, stop
Rotomina and change its `scanner_type` to `eevx` before restarting and linking;
this prevents migration during an in-flight legacy setup/install task.

Refresh before Start, Stop, or configuration. Worker changes preserve current
owner intent. Names and saved Rotom connection UUIDs are supported; create Rotom
connections/secrets in the Mapping dashboard. Server revision checks reject stale
commands. Accepted revisions are separate from observed completion. Unknown or
older-than-30-second telemetry is shown explicitly.

Restart and Update require backend migration `202609200001_mapping_management`
and an APK reporting `managementProtocol: 1` (Scanner 0.5.3+). Older APKs retain
normal controls and are rejected for management operations.

- **Restart:** allowed only when desired-running is true. The APK pauses, waits
  for the scanner to stop and a 40-second cleanup grace, reports completion, then
  obeys a fresh Mapping response. Rotomina never sends an independent Start.
- **Update:** enter the exact version code published in the signed Eevx Scanner
  release channel. The APK drains, downloads, and verifies the release signature,
  APK SHA-256/size/package/version/signing certificate/min SDK and current game
  compatibility before installation. Compatibility metadata comes from inside
  the signed target APK. Root is required for unattended installation; generic
  ADB APK installation and Android installer click automation are not used.
- Each operation carries a client UUID and expected device revision. Duplicate
  IDs are deduplicated by the database; newer owner commands cancel older work.
  Installation is claimed once after fresh stopped/ready telemetry. Lost
  responses are never automatically replayed. A dispatched package replacement
  cannot be undone by Stop; Stop still cancels any subsequent resume.
- Package replacement restarts the Mapping connection, not scanning directly.
  The installed version confirms success. Failed, expired, unsupported or
  incompatible updates stop owner intent and require an explicit decision.
  The server never returns scanner credentials to the adapter.

Use Operation status to inspect pending/draining/downloading/ready/installing/
complete/failed/cancelled. Completion proves the requested restart drain or APK
installation, not sustained scanning health. Confirm fresh observed state and
useful RPC activity afterwards. No staged fleet rollout is automatic.

Game updates and performance switches remain outside this adapter. MapWorld
configuration, token distribution, APK/game/module installation, reboot and
restart paths reject Eevx devices. The low-memory/offline watchdog leaves Eevx
recovery in charge. Rotom online/memory uses an exact control origin; duplicate
origins are unknown. Management always uses the stable Mapping UUID.

## Validation

`python -m pip install -r requirements.txt pytest`

`python -m pytest -q`

`python -m compileall -q main.py scanner_adapters`

Tests cover owner-session rotation/concurrency, uncertain refresh responses,
secret redaction, session/CSRF protection, revision conflicts, capability gating,
operation request identity and legacy side-effect guards. Backend transaction
and APK verification tests live in their respective repositories. Configure the
backend and bootstrap APK before using new controls in production.
