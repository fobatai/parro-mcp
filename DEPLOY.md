# Running Parro MCP as a remote server

`parro_mcp.py` is a stdio server: it reads JSON-RPC from stdin and writes it to
stdout. Claude on the web and on the phone cannot speak to that - they need an
HTTPS endpoint. The `Dockerfile` here wraps the stdio server in
[mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy), which does two jobs:

1. **Transport.** It exposes the MCP server at `/mcp` (streamable HTTP) and
   `/sse`, spawning `python /app/parro_mcp.py` per session and piping to it.
2. **Authorization.** It is an OAuth 2.1 authorization server *and* resource
   server: it publishes `/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`, supports PKCE (S256) and dynamic
   client registration, and rejects unauthenticated calls to `/mcp` with a 401.
   Claude registers itself, sends you through a login page, and gets a token.

Without that second part the endpoint would be an open door to your children's
school information for anyone who guesses the hostname.

## Deploying on Dokploy

Create an **Application**, provider **GitHub**, this repository. Two build types
work; pick one:

| Build type | Container port | Notes |
| --- | --- | --- |
| **Nixpacks** (`nixpacks.toml`) | `8080` | No Dockerfile involved. Read the comments in `nixpacks.toml` before changing it - the Python venv and the libstdc++ path are both easy to break silently. |
| **Dockerfile** | `80` | Shorter and less magic. |

Both produce the same thing: mcp-auth-proxy in front of `parro_mcp.py`. If you
edit one, keep the other in step.

**Domain** - add the hostname (e.g. `parro.example.com`), the container port
from the table above, HTTPS on with Let's Encrypt. Traefik terminates TLS; the
container itself serves plain HTTP and must not try to get its own certificate,
hence `NO_AUTO_TLS` below.

**Volume** - mount a volume at `/data`. Skip this and every redeploy throws away
both the OAuth state (all clients must reconnect) and the Parro tokens (you must
log in to Parro again).

**Environment**

| Variable | Value | Why |
| --- | --- | --- |
| `EXTERNAL_URL` | `https://parro.example.com` | Goes into the OAuth metadata; must match the real hostname exactly or the flow breaks. |
| `NO_AUTO_TLS` | `true` | Traefik already handles TLS. |
| `PASSWORD_HASH` | bcrypt hash | Login for the human. Use `PASSWORD` for plaintext if you must, but the hash keeps it out of the Dokploy UI. |
| `TRUSTED_PROXIES` | Traefik's subnet | So the proxy sees the real client IP and scheme instead of Traefik's. |

To log in with GitHub or Google instead of a password, drop `PASSWORD_HASH` and
set `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` / `GITHUB_ALLOWED_USERS` (or the
`GOOGLE_*` equivalents). Every command-line flag of mcp-auth-proxy has an
environment variable: uppercase, dashes to underscores.

## Connecting Claude

Add a custom connector pointing at `https://parro.example.com/mcp`. Claude
discovers the metadata, registers itself, and opens the login page. After that
the 16 Parro tools appear.

## Logging in to Parro itself

Two separate logins live here: one into *this server* (above), and one into
*Parro* (below).

The container ships no Parro credentials. Call `parro_login_url`, open the URL,
log in, and hand the redirect URL to `parro_login_finish`. Tokens land in
`/data/parro-tokens.json` and refresh themselves.

For unattended login instead, set `PARRO_USERNAME` and point
`PARRO_PASSWORD_FILE` at a file on the `/data` volume holding the password.
Note the IdP locks the account after a few failed attempts, so a typo there is
costly - and Dokploy will hand you one for free if you use `PARRO_PASSWORD`
instead: it strips everything from a `#` onwards, quoted or not, so a password
containing one arrives truncated and every login attempt burns a try. The file
keeps the password out of Dokploy's database and out of the image layers too.

Check what actually arrived before trusting it:

```bash
docker exec <container> /opt/venv/bin/python -c \
  "import os,hashlib; p=open(os.environ['PARRO_PASSWORD_FILE']).read().strip(); \
   print(len(p), hashlib.sha256(p.encode()).hexdigest()[:16])"
```

## Notes

- The base image is pinned to `:latest`. Pin a release tag if you want
  reproducible builds.
- The 401 from `/mcp` does not carry the `WWW-Authenticate: Bearer
  resource_metadata=...` header the MCP spec asks for. Claude discovers the
  metadata through the well-known path anyway, but a stricter client might not.
