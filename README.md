# Parro MCP

Read-only MCP server for [Parro](https://talk.parro.com) — the Dutch parent–school
communication app by Topicus (ParnasSys). Lets Claude read your announcements,
newsletters, chats and class info, **including the text inside PDF attachments**.

Single file, standard library only. `parro_mcp.py`.

## What it does

The Parro web client is a Flutter app talking to a Topicus "geon" REST API at
`https://rest-v2.parro.com/rest/v2`. This server speaks that API, and does two
things that make it useful to an LLM:

1. **Strips the geon boilerplate.** Raw responses bury every field under
   `permissions` / `links` / `dtype` blocks — a three-group list is 2.8 KB of
   JSON carrying maybe 300 bytes of information. Every tool returns a slimmed
   summary; pass `raw: true` when you want the untouched payload.
2. **Extracts attachment text.** School newsletters arrive as PDFs. `parro_attachment`
   downloads them and returns plain text, so they can be summarised or searched.
   Photos come back as viewable images instead.

It only ever issues `GET`. Nothing can be posted, changed or deleted.

## Tools

| Tool | What it gives you |
| --- | --- |
| `parro_auth_status` | Login state, account, role, token expiry. Start here when something fails. |
| `parro_login` | Headless login using `PARRO_USERNAME` / `PARRO_PASSWORD`. |
| `parro_login_url` / `parro_login_finish` | Interactive browser login (OAuth2 + PKCE). |
| `parro_logout` | Revoke tokens at the IdP and clear the cache. |
| `parro_me` | Account, school, children. |
| `parro_children` | Children linked to the account. |
| `parro_groups` | Classes and school-wide groups, with the ids other tools need. |
| `parro_announcements` | The main feed. Merges all groups, newest first, full text + attachment list. |
| `parro_announcement` | One announcement by id, with author. |
| **`parro_attachment`** | **Downloads an attachment and returns its text (PDF/docx/txt/csv/html) or the image.** |
| `parro_calendar` | Calendar items from the event feed. |
| `parro_chatrooms` / `parro_chat_messages` | Conversations with teachers. |
| `parro_unread` | Unread counts per category. |
| `parro_get` | Escape hatch: GET any `/rest/v2` path not covered above. |

## Install

```powershell
claude mcp add parro -s user -- C:\ProgramData\miniconda3\python.exe D:\Scripts\Parro\parro_mcp.py
```

Or in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "parro": {
      "command": "C:\\ProgramData\\miniconda3\\python.exe",
      "args": ["D:\\Scripts\\Parro\\parro_mcp.py"]
    }
  }
}
```

PDF extraction uses **PyMuPDF** if present, otherwise **pypdf**; image downscaling
uses **Pillow**. All three are optional — without them the server still runs, it
just reports that it cannot read a PDF. To be sure:

```powershell
C:\ProgramData\miniconda3\python.exe -m pip install pymupdf pillow
```

## Logging in

Everything here is OAuth2 against the ParnasSys IdP — there is no bespoke auth.
Tokens are cached in `~/.parro-mcp/tokens.json` and refreshed automatically.

The server asks for scope `openid offline_access`. The web client only asks for
`openid`, which is why its refresh token expires after 8 hours; `offline_access`
is advertised in the IdP's discovery document and accepted by the authorize
endpoint, so a login should last far longer.

**Option A — unattended.** Set your ParnasSys credentials in the server's
environment. It uses the OAuth2 **password grant** (`grant_type=password`, which
this IdP enables for the Parro client), falling back to driving the login form:

```json
"env": { "PARRO_USERNAME": "you@example.com", "PARRO_PASSWORD": "..." }
```

> **The IdP locks the account after a few failed logins** ("Account has N attempts
> remaining"). If credentials are rejected the server latches and stops trying, so
> a typo cannot burn one attempt per tool call. `parro_auth_status` then reports
> `automatic_login_halted`; fix the password and call `parro_login` to spend one
> deliberate attempt.

**Option B — no password stored.** Call `parro_login_url`, open the URL, log in,
then hand the redirect URL back to `parro_login_finish`. Copy the address bar
promptly: the Parro web app also tries to consume the code, and each code works
only once. If it fails, just run `parro_login_url` again.

`parro_logout` revokes both tokens at the IdP and deletes the cache.

### Why not a proper loopback redirect?

The tidy modern pattern (RFC 8252: spin up `http://127.0.0.1:PORT/callback`, let
the browser deliver the code automatically) needs a client registered with that
redirect URI. This IdP:

- publishes **no `registration_endpoint`** — no Dynamic Client Registration, so we
  cannot register one;
- validates redirect URIs strictly. Asking for `http://localhost:8765/callback`
  or `http://127.0.0.1:8765/callback` on the Parro client returns
  `invalid_client — Callback url does not match one of [registered]`;
- advertises **no device authorization grant**, so that escape route is out too.

So a local tool must borrow the web client's `client_id`, which is pinned to
`https://talk.parro.com/oauth2` — hence the copy-paste step. Option A avoids it
entirely. (The MCP spec's own OAuth support is a different thing: it covers a
client authenticating *to* a remote HTTP MCP server, not a local stdio server
authenticating to a third-party API.)

## Configuration

| Variable | Default |
| --- | --- |
| `PARRO_USERNAME` / `PARRO_PASSWORD` | — (enables headless login) |
| `PARRO_PASSWORD_FILE` | — (read the password from a file instead; wins over `PARRO_PASSWORD`) |
| `PARRO_TOKEN_FILE` | `~/.parro-mcp/tokens.json` |
| `PARRO_ROLE` | auto-derived, e.g. `GUARDIAN:1234567890` |
| `PARRO_ACCESS_TOKEN` | bootstrap with an existing token (no refresh) |
| `PARRO_BASE_URI` | `https://rest-v2.parro.com` |
| `PARRO_LOGIN_URI` | `https://inloggen.parnassys.net` |
| `PARRO_CONTRACT_VERSION` | `221` |
| `PARRO_SCOPE` | `openid offline_access` |
| `PARRO_MAX_DOWNLOAD` | `62914560` (60 MB) |
| `PARRO_MAX_IMAGE_PX` | `1400` |

Switch to the acceptance environment by overriding `PARRO_BASE_URI`,
`PARRO_LOGIN_URI` and `PARRO_CLIENT_ID`.

## Testing without a client

```powershell
python parro_mcp.py tools
python parro_mcp.py call parro_auth_status
python parro_mcp.py call parro_announcements '{\"limit\": 5}'
python parro_mcp.py call parro_attachment '{\"announcement_id\": 12345678901}'
```

## How this was built

Everything is derived from `talk.parro.com.har` (a captured browser session) plus
the string table of the app's `main.dart.js` bundle, which contains the full
endpoint surface. Verified live against the real API:

- `GET /account/me`, `/accountsettings`, `/child`, `/group`, `/identity/unreadcounts`,
  `/absence/setting`, `/systemnews`
- `GET /event?dtype=event.RAnnouncementEventPrimer&group={id}`
- `GET /event/{id}?dtype=event.RAnnouncementEvent` — the `dtype` is required, else
  the API answers `406 EVENT_BAD_TYPE`
- `GET /chatroom`, `/chatroom/{id}/chatmessage`

Request shape: `Authorization: Bearer`, `Accept: application/vnd.topicus.geon+json;version=221`,
`parro-app-version: web:2.25.4`, `parro-authorization-role: GUARDIAN:{guardianId}`.
Collections are `Range: items=0-49` paginated and answer `206` with a `Content-Range`
total. Attachments carry a direct, time-limited CloudFront URL which must be
fetched **without** the Parro `Authorization` header.

Endpoints present in the bundle but not wrapped in a dedicated tool — `/absence`,
`/calendaritem/*`, `/media-export`, `/conversations`, `/timeslot`, `/privacy` —
are reachable through `parro_get`.

## Note on the HAR

`talk.parro.com.har` contains the login POST **in plaintext**, including the
password, plus valid OAuth tokens. Treat it as a secret: don't commit it, and
consider changing that password since it has been sitting in a file on disk.
