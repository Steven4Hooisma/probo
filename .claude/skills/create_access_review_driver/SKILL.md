---
name: Create_Access_Review_Driver
description: Creates a new access review driver (connector provider + driver + tests + registration surface) for a third-party system in Probo, following the conventions shared by all existing drivers. Use when asked to add an access review integration/connector/driver for a new provider.
---

# Create an access review driver

An access review driver answers one question for a third-party system: **who actually has access right now**. Adding one touches a fixed set of backend and frontend files. The most recent complete example is UniFi (API key + extra setting); GitHub is the clearest OAuth + API key hybrid. Read the reference files before writing code — the house style (rationale-first comments, error wrapping, security posture) is load-bearing and reviewed.

## Step 0 — Gather inputs

Before writing anything, establish:

1. **Provider name** — display name, enum value (`SCREAMING_SNAKE`), Go identifier.
2. **API documentation** — if the user attached an OpenAPI spec, **use exactly the endpoints it defines**; do not invent paths. Otherwise research the provider's public API docs for: the user/member listing endpoint, auth mechanism, pagination style, and any account-status / MFA / last-login / role fields.
3. **Authentication method** — in order of preference:
   - **OAuth 2.0 (preferred)**: use when the provider runs an OAuth app/partner program covering the needed read scopes.
   - **API key (acceptable fallback)**: only when OAuth is not available. Record *why* in the registration's doc comment (e.g. "X runs no partner OAuth program for this API").
   - Note how the credential is sent: `Authorization: Bearer` (default), a custom header (`APIKeyHeader`), Basic auth (`APIKeyBasicAuth` / `APIKeyBasicAuthUserPass`), or a scheme like Okta's `SSWS` (`APIKeyAuthScheme`). These modes are mutually exclusive — `Register` enforces it.
4. **Extra settings** — does the API need a per-customer identifier that the credential does not carry (org slug, console ID, region, base URL)? Each becomes an `ExtraSetting` + GraphQL input field + frontend mapping.
5. **Endpoints** — the API base URL. If the host itself comes from customer settings (self-hosted products like Grafana/Okta), leave `Endpoints.APIBase` empty and build URLs from validated settings instead.

## Step 1 — Study the reference implementations

Read these before coding (do not skip):

- `pkg/accessreview/drivers/driver.go` — `Driver` interface, `AccountRecord`, shared helpers (`retryRoundTripper`, `maxPaginationPages`, `parseRFC3339Ptr`, `activeFromStatus`, `sameHostNextPageURL`).
- `pkg/accessreview/drivers/unifi.go` + `unifi_test.go` — most recent API-key driver with extra setting, offset pagination, name resolver.
- `pkg/connector/provider/github.go` — OAuth + API-key hybrid registration.
- `pkg/connector/provider/types.go` — full `Registration` struct with field docs.
- `contrib/claude/go-style.md`, `contrib/claude/go-testing.md`, `contrib/claude/httpclient.md`, `contrib/claude/license.md`.

Every new file starts with the MIT license header (see `contrib/claude/license.md`; copy it from any sibling file, matching comment syntax).

## Step 2 — File checklist

Backend:

| File | What to add |
|---|---|
| `pkg/accessreview/drivers/<provider>.go` | The driver, URL builders, and name resolver |
| `pkg/accessreview/drivers/<provider>_test.go` | Driver tests (cassette + stubbed transports) |
| `pkg/accessreview/drivers/testdata/<provider>.yaml` | VCR cassette |
| `pkg/connector/provider/<provider>.go` | `<provider>Registration()` |
| `pkg/connector/provider/<provider>_test.go` | Registration metadata + factory tests |
| `pkg/connector/provider/builtin.go` | Add `<provider>Registration()` to the list (alphabetical) |
| `pkg/connector/provider/probe.go` | `build<Provider>ProbeURL` only if the probe URL depends on connector settings; otherwise set `Endpoints.Probe` |
| `pkg/connector/provider/probe_test.go` | A case in `TestBuildProbeURLFromAPIBase` (or a dedicated probe test) |
| `pkg/coredata/connector_provider.go` | Const + `ConnectorProviders()` + `IsValid()` switch — all three |
| `pkg/coredata/connector_settings.go` | `<Provider>ConnectorSettings` struct, only if extra settings exist |
| `pkg/coredata/migrations/<UTC timestamp>Z.sql` | `ALTER TYPE connector_provider ADD VALUE IF NOT EXISTS '<ENUM>';` (with license header) |
| `pkg/server/api/console/v1/graphql/connector.graphql` | Enum value with `@goEnum`; a `CreateAPIKeyConnectorInput` field only if extra settings exist |
| `pkg/server/api/console/v1/connector_settings.go` | A case in `apiKeyConnectorSettings` validating + persisting extra settings |
| `pkg/server/api/console/v1/connector_settings_test.go` | Tests for that case |

Frontend (the provider card, dialogs, and generic API-key fields render automatically from `ConnectorProviderInfo`; only these need edits):

| File | What to add |
|---|---|
| `packages/ui/src/Atoms/ThirdParties/<Provider>.tsx` | Brand SVG logo (`viewBox="0 0 24 24"`, spread `props`) |
| `packages/ui/src/Atoms/ThirdParties/ThirdPartyLogo.tsx` | Import + entry in the `thirdParties` map (key = enum value) |
| `packages/ui/src/Atoms/ThirdParties/index.ts` | Export |
| `apps/console/src/pages/organizations/access-reviews/dialogs/_lib/connectorSettings.ts` | A `case` in `mapAPIKeyExtraSettingToField` mapping each `ExtraSetting.Key` to the GraphQL input field — only if extra settings exist. **Without this the dialog silently submits nothing for the setting.** |

After editing the `.graphql` schema, run codegen (`make generate`) so gqlgen and Relay artifacts pick up the enum/input changes.

## Step 3 — The driver (`pkg/accessreview/drivers/<provider>.go`)

Contract: `ListAccounts(ctx) ([]AccountRecord, error)` returns **ALL** accounts the source exposes — including suspended/deactivated/deleted ones. Classification is the reviewer's job, never the fetcher's.

`AccountRecord` semantics (all best-effort; populate what the API actually states):

- `ExternalID` — required, stable, unique across the whole driver output. Entries key on it: a collision merges two grants into one row; an unstable ID marks real accounts "removed" next campaign. Scope IDs when resources nest (e.g. `site/<id>/user/<id>`). Normalize case/format so the same identity keys identically across runs.
- `Active *bool` — three-valued. `nil` means the API exposes no explicit status signal; **never fabricate a value**. Map fully-enumerated status enums explicitly so an unrecognized value stays `nil`, not `false`. `activeFromStatus` helps for literal-`"active"` APIs.
- `MFAStatus` — `ENABLED` / `DISABLED` / `UNKNOWN`. `AuthMethod` — `SSO` / `PASSWORD` / `API_KEY` / `SERVICE_ACCOUNT` / `UNKNOWN`. `AccountType` — `USER` / `SERVICE_ACCOUNT`.
- `LastLogin` / `CreatedAt` — `parseRFC3339Ptr` (returns `nil` on empty/unparseable, never errors).
- `Roles` — human-readable grant qualifiers (`"Admin"`, `"Site: HQ"`). Keep ordering stable (sort where the API order can shuffle) and clone shared slices before appending per-record.
- Emit rows only for **holders of access** (people, service accounts, tokens, devices) — never for the resources being accessed. Fold resource context into the holder's `Roles` instead.

Structure and conventions:

- Constructor `New<Provider>Driver(httpClient *http.Client, logger *log.Logger, ...)` layers retries by **copying the caller's client and swapping only its transport**: `retryClient := *httpClient; retryClient.Transport = &retryRoundTripper{next: httpClient.Transport, maxRetries: 3}`. Never build a fresh `&http.Client{}` — the connection's client carries SSRF protection in both its transport dial check *and* its `CheckRedirect`, and a fresh client silently drops the second.
- Assert the interface: `var _ Driver = (*<Provider>Driver)(nil)`.
- Never set auth headers in the driver — the connection transport attaches the credential. The driver sets only `Accept: application/json` (and `Content-Type` for POST bodies).
- Build URLs with `url.JoinPath` + `url.PathEscape` on every interpolated value; never string-concatenate paths. Declare path segments as constants.
- Pagination: loop `for range maxPaginationPages { ... }`; falling out of the loop returns `fmt.Errorf("cannot list all <provider> <things>: %w", ErrPaginationLimitReached)`. Also terminate on an empty page regardless of what a total-count field claims. If the API returns a **next-page URL**, resolve it through `sameHostNextPageURL(provider, baseURL, next)` — it refuses cross-host/cross-scheme/path-escaping redirections.
- Error strings: `cannot <verb> <provider> <thing>: %w`, lowercase, no trailing punctuation. Never echo credentials, user-supplied values, or response bodies into errors or logs.
- A 404 that means "this feature/collection doesn't exist on this instance" is a stable answer → warn + empty result, not an error. Transient failures (5xx, decode errors) must abort: a silently short answer marks real accounts removed next campaign.
- Do not decode fields you don't need — especially anything credential-shaped (passwords, secrets, tokens): leaving them undecoded means they cannot leak into a record, log, or error.
- Write the driver's doc comment in the house style: what is reported, **what is deliberately not reported and why**, where the data comes from, and what the API cannot answer.

Name resolver (same file): implement `NameResolver` with `New<Provider>NameResolver(...)`. Return `("", nil)` when no good name exists (the source keeps its generic name) — an empty name is legal, an error is retried. On non-2xx use `nameStatusError("<provider> <thing>", status)` — it wraps `ErrTerminalNameResolution` for 400/401/403/404 so an unauthorized source stops being re-claimed forever. Register it via `NewNameResolver` in the registration.

## Step 4 — The provider registration (`pkg/connector/provider/<provider>.go`)

Read `types.go` field docs first. Key rules:

- **OAuth**: set `Endpoints.Auth` + `Endpoints.Token` (they are often on a *different* host than `APIBase` — never derive one from the other) and `OAuth2Scopes`. Client ID/secret never live in the registration — they come from deployment config via `ApplyOAuth2Defaults`. Set `ExtraAuthParams` (e.g. `access_type=offline`), `RequiresPKCE`, `TokenEndpointAuth` as the provider requires. There is no `SupportsOAuth` flag — OAuth is implied by the endpoints plus deployment credentials.
- **API key**: `SupportsAPIKey: true`; default transport is `Authorization: Bearer`. Set `APIKeyHeader` / `APIKeyBasicAuth` / `APIKeyBasicAuthUserPass` / `APIKeyAuthScheme` only if the provider deviates (one at most).
- `APIKeyExtraSettings: []ExtraSetting{{Key: "...", Label: "...", Required: true}}` for per-customer identifiers, in render order.
- `Endpoints.APIBase`: scheme-ful origin, no trailing slash. Leave empty when the host comes from settings. **Every URL the driver, probe, and name resolver hit must compose from `ep.APIBase`** so an endpoint override moves all three together — factory closures receive `Endpoints` as an argument precisely so they cannot capture a stale copy; never close over `reg.Endpoints`.
- Host literals for this provider may appear **only** in `pkg/connector/provider/<provider>.go` and `pkg/accessreview/drivers/<provider>.go` — `endpoint_host_literal_test.go` scans the whole repo and fails otherwise.
- Probe: prefer a static `Endpoints.Probe` URL (host must match `APIBase` — `Register` enforces it). Use `BuildProbeURL` when the URL depends on connector settings; pick the cheapest call that proves the credential reaches the *configured* resource, ideally the same call the driver opens with. Probe semantics: 401/403 = rejected, everything else = connected; add `extraReject` statuses via a custom `Probe` closure only if the API signals bad credentials differently.
- `DocumentationURL`: `accessReviewDocsURL("<slug>")` if the probo.com docs page exists; otherwise leave empty with a comment (a 404-ing link is worse than none).
- `NewDriver` reads settings via `coredata.ConnectorSettings[coredata.<Provider>ConnectorSettings](conn)`, validates them, and passes `logger.Named("<provider>")`.

Server-side settings validation (`apiKeyConnectorSettings` in `pkg/server/api/console/v1/connector_settings.go`): trim, require, and **reject rather than sanitize** values that would change URL structure (separators, `?`, `#`, `%`, whitespace). Error messages name the field, **never the value** (they are surfaced verbatim to the client).

## Step 5 — Tests

Follow `contrib/claude/go-testing.md`: `t.Parallel()` everywhere (top level and every subtest), `require` for preconditions, `assert` for values, white-box `package drivers` / `package provider` where unexported helpers are tested, black-box `package provider_test` for registration tests.

Driver tests (`pkg/accessreview/drivers/<provider>_test.go`):

- **Cassette-backed happy path** `Test<Provider>Driver`: `rec := newRecorder(t, "testdata/<provider>", "<PROVIDER>_API_KEY")` (the credential env var doubles as the record switch), client via `newVCRClient(rec, bearerAuth(token))` or `newVCRClientWithHeader(rec, "X-Custom", key)`. If the auth header is custom, **add it to the scrub list in `vcr_test.go`'s `BeforeSaveHook`**. Cassettes are committed; start them with a comment block documenting each interaction and the expected record count. Emails in cassettes must use synthetic domains (`.example.com`, `.test`, …) — `cassette_safety_test.go` enforces this automatically.
- Assert against the cassette: exact `require.Len` on the record count, per-record `NotEmpty(ExternalID)`, **ExternalID uniqueness via a seen-map**, expected `Roles`/`Active`/`AuthMethod`/`MFAStatus`/`AccountType` per record.
- **Error paths** via stubbed transports (the shared `roundTripFunc` pattern — no `httptest.Server`): transient 5xx → error + nil records; tolerated 404 → empty + no error; context cancellation → `errors.Is(err, context.Canceled)`; pagination guard trip; name resolver happy path + `errors.Is(err, ErrTerminalNameResolution)` on 401.
- If the driver follows a provider-supplied next-page URL, **add a case to `TestDriversRefuseCrossHostPagination`** in `pagination_guard_test.go` — new drivers are not covered automatically. Offset/cursor-parameter pagination doesn't need one. Retry behavior is covered globally; nothing per-driver needed.

Provider tests (`pkg/connector/provider/<provider>_test.go`): pin the registration metadata (display name, auth flags, header, endpoints, extra settings), `NewDriver` happy path (`assert.IsType`) and missing-settings error, `NewNameResolver` nil-on-bad-settings. Add a probe case to `TestBuildProbeURLFromAPIBase` with the exact expected URL. `TestBuiltinRegistry_ProbeCoverage` verifies probe presence automatically.

API settings tests (`pkg/server/api/console/v1/connector_settings_test.go`): tie the GraphQL input field to the declared `ExtraSetting.Key`, happy path, whitespace trimming, a rejection table (empty, pasted URL, extra path segments, traversal, query, fragment, embedded space) asserting `assert.NotContains(err.Error(), invalid)`, and the nil-pointer case.

## Step 6 — Validate

Run, and fix until clean:

```sh
make generate                                        # after .graphql changes
make lint                                            # REQUIRED — vet + gofmt + go fix + golangci-lint + JS lint
make test MODULE=./pkg/accessreview/drivers
make test MODULE=./pkg/connector/provider
make test MODULE=./pkg/server/api/console/v1
```

`make lint` must pass before the work is considered done.

## Common mistakes to avoid

- Inventing API endpoints instead of using the attached OpenAPI spec or documented API.
- Building a fresh `&http.Client{}` in the driver constructor (drops SSRF `CheckRedirect`).
- Setting `Active: &false` when the API simply has no status field (must be `nil`).
- Emitting records for resources (repos, SSIDs, projects) instead of access holders.
- Forgetting one of the three `connector_provider.go` edits (const, `ConnectorProviders()`, `IsValid()`).
- Adding `APIKeyExtraSettings` without the GraphQL input field + `mapAPIKeyExtraSettingToField` case — the dialog renders the field but submits nothing.
- Echoing user-supplied values or credentials in error messages.
- Missing the MIT license header on any new file (including the SQL migration and `.tsx`).
