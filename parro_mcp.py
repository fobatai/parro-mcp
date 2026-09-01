#!/usr/bin/env python3
"""Parro MCP server - read-only access to the Parro schooldashboard (talk.parro.com).

Parro is the Dutch parent-communication app by Topicus (ParnasSys). Its web
client is a Flutter app talking to a Topicus "geon" REST API:

    https://rest-v2.parro.com/rest/v2/...

Auth is OAuth2 authorization-code + PKCE against the ParnasSys IdP at
https://inloggen.parnassys.net/idp. Every API call needs:

    Authorization: Bearer <access_token>
    Accept:        application/vnd.topicus.geon+json;version=221
    parro-app-version:         web:2.25.4
    parro-authorization-role:  GUARDIAN:<guardianId>

Collections are Range-paginated (`Range: items=0-49` -> 206 + Content-Range).

Everything here was derived from a HAR capture of a real talk.parro.com session
plus the string table of the app's main.dart.js bundle. This server is
READ-ONLY: it only ever issues GET requests.

Standard library only - no dependencies to install.

Configuration (environment):
    PARRO_USERNAME / PARRO_PASSWORD  ParnasSys login for unattended headless login
    PARRO_TOKEN_FILE                 token cache (default ~/.parro-mcp/tokens.json)
    PARRO_ROLE                       override role header, e.g. "GUARDIAN:123"
    PARRO_ACCESS_TOKEN               bootstrap with an existing token (no refresh)
    PARRO_BASE_URI                   default https://rest-v2.parro.com
    PARRO_LOGIN_URI                  default https://inloggen.parnassys.net
    PARRO_CONTRACT_VERSION           default 221
    PARRO_CLIENT_ID                  default MQygAaSBUcAgPU2WInKt (talk.parro.com)

Manual test from a shell:
    python parro_mcp.py call parro_me
    python parro_mcp.py call parro_announcements '{"limit": 5}'
"""
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------------------------------------------- config
BASE_URI = os.environ.get("PARRO_BASE_URI", "https://rest-v2.parro.com").rstrip("/")
LOGIN_URI = os.environ.get("PARRO_LOGIN_URI", "https://inloggen.parnassys.net").rstrip("/")
CONTRACT = os.environ.get("PARRO_CONTRACT_VERSION", "221")
CLIENT_ID = os.environ.get("PARRO_CLIENT_ID", "MQygAaSBUcAgPU2WInKt")
REDIRECT_URI = os.environ.get("PARRO_REDIRECT_URI", "https://talk.parro.com/oauth2")
APP_VERSION = os.environ.get("PARRO_APP_VERSION", "web:2.25.4")
GEON = "application/vnd.topicus.geon+json;version={}".format(CONTRACT)

# The web client only asks for "openid", which is why its refresh token dies
# after 8 hours. The IdP's discovery document advertises offline_access, and the
# authorize endpoint accepts it, so ask for a durable session instead.
SCOPE = os.environ.get("PARRO_SCOPE", "openid offline_access")

TOKEN_FILE = os.environ.get(
    "PARRO_TOKEN_FILE",
    os.path.join(os.path.expanduser("~"), ".parro-mcp", "tokens.json"),
)

UA = "parro-mcp/1.0"
HTTP_TIMEOUT = float(os.environ.get("PARRO_TIMEOUT", "30"))


def log(msg):
    print("[parro-mcp] {}".format(msg), file=sys.stderr, flush=True)


class ParroError(Exception):
    pass


# ------------------------------------------------------------- token storage
_state = {"tokens": None, "role": None, "account": None}


def _load_tokens():
    if _state["tokens"] is not None:
        return _state["tokens"]
    tok = {}
    try:
        with open(TOKEN_FILE, encoding="utf-8") as fh:
            tok = json.load(fh)
    except (OSError, ValueError):
        tok = {}
    env = os.environ.get("PARRO_ACCESS_TOKEN")
    if env and not tok.get("access_token"):
        # Bootstrap token: no expiry known, assume usable until the API says 401.
        tok = {"access_token": env, "expires_at": time.time() + 3600, "refresh_token": None}
    _state["tokens"] = tok
    return tok


def _save_tokens(tok):
    _state["tokens"] = tok
    try:
        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
        with open(TOKEN_FILE, "w", encoding="utf-8") as fh:
            json.dump(tok, fh, indent=1)
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
    except OSError as ex:
        log("could not persist tokens to {}: {}".format(TOKEN_FILE, ex))


def _store_token_response(data):
    tok = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "expires_at": time.time() + float(data.get("expires_in", 3600)) - 60,
        "obtained_at": time.time(),
    }
    _save_tokens(tok)
    _state["role"] = None
    _state["account"] = None
    return tok


# --------------------------------------------------------------- http helper
def _request(method, url, headers=None, body=None, opener=None, redirect=True):
    """Return (status, headers dict, bytes). Never raises on HTTP status."""
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    op = opener or urllib.request.build_opener(_NoRedirect() if not redirect else
                                               urllib.request.HTTPRedirectHandler())
    try:
        with op.open(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as ex:
        return ex.code, dict(ex.headers), ex.read()
    except urllib.error.URLError as ex:
        raise ParroError("network error calling {}: {}".format(url, ex.reason))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None

    def http_error_302(self, req, fp, code, msg, hdrs):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_302


# ---------------------------------------------------------------- oauth/PKCE
def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _pkce_pair():
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _authorize_url(challenge, state):
    q = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return "{}/idp/oauth2/authorize?{}".format(LOGIN_URI, q)


def _exchange_code(code, verifier):
    # The IdP takes these as QUERY parameters with an empty body (as the real
    # web client does), not as a form-encoded body.
    q = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "code": code,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    })
    url = "{}/idp/oauth2/token?{}".format(LOGIN_URI, q)
    status, _h, raw = _request("POST", url, {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
    }, body=b"")
    if status != 200:
        raise ParroError("token exchange failed ({}): {}".format(
            status, raw.decode("utf-8", "replace")[:400]))
    return _store_token_response(json.loads(raw.decode("utf-8")))


def _refresh(refresh_token):
    q = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })
    url = "{}/idp/oauth2/token?{}".format(LOGIN_URI, q)
    status, _h, raw = _request("POST", url, {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
    }, body=b"")
    if status != 200:
        raise ParroError("refresh failed ({}): {}".format(
            status, raw.decode("utf-8", "replace")[:300]))
    return _store_token_response(json.loads(raw.decode("utf-8")))


class LoginLocked(ParroError):
    pass


def _lockout_note():
    return _load_tokens().get("login_failed")


def _set_lockout(reason):
    tok = _load_tokens()
    tok["login_failed"] = reason
    _save_tokens(tok)


def _clear_lockout():
    tok = _load_tokens()
    if tok.pop("login_failed", None) is not None:
        _save_tokens(tok)


def _guard_lockout():
    """Refuse to spend another login attempt after credentials were rejected.

    The IdP counts failures and locks the account ("Account has N attempts
    remaining"). Without this latch a wrong PARRO_PASSWORD would burn one
    attempt per tool call and lock the real ParnasSys account within seconds.
    """
    note = _lockout_note()
    if note:
        raise LoginLocked(
            "not retrying automatic login - the last attempt was rejected: {}\n"
            "The IdP locks the account after a few failures, so fix the "
            "credentials first, then call parro_login to try again "
            "(or parro_login_url for the browser flow).".format(note))


def _env_credentials():
    """Username and password for headless login, or (None, None).

    PARRO_PASSWORD_FILE takes precedence over PARRO_PASSWORD, following the
    convention Docker and friends use for secrets. It also sidesteps hosts that
    mangle the value: Dokploy, for one, strips everything from a '#' onwards,
    which silently turns a password into its first few characters.
    """
    user = os.environ.get("PARRO_USERNAME")
    path = os.environ.get("PARRO_PASSWORD_FILE")
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return user, fh.read().strip("\r\n")
        except OSError as ex:
            raise ParroError("PARRO_PASSWORD_FILE {} is unreadable: {}".format(path, ex))
    return user, os.environ.get("PARRO_PASSWORD")


def _password_grant(username, password):
    """Standard OAuth2 password grant (RFC 6749 s4.3).

    The IdP advertises `password` in grant_types_supported and accepts it for
    this public client, which is far more robust than scraping the login form.
    """
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": SCOPE,
    }).encode("utf-8")
    status, _h, raw = _request("POST", "{}/idp/oauth2/token".format(LOGIN_URI), {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }, body=body)
    text = raw.decode("utf-8", "replace")
    if status == 200:
        _clear_lockout()
        return _store_token_response(json.loads(text))
    try:
        err = json.loads(text)
        detail = err.get("error_description") or err.get("error") or text
        code = err.get("error", "")
    except ValueError:
        detail, code = text[:200], ""
    if code == "invalid_grant":
        # Wrong username/password - latch so we never burn another attempt.
        _set_lockout(detail[:200])
        raise LoginLocked(
            "login rejected: {}\nNOT retrying automatically - the account locks "
            "after a few failed attempts. Correct the credentials, then call "
            "parro_login.".format(detail))
    raise ParroError("password grant failed ({}): {}".format(status, detail))


def _form_login(username, password):
    """Drive the ParnasSys Wicket login form and complete the PKCE flow.

    Fallback for when the password grant is refused for this client.
    GET /idp/oauth2/authorize -> login page -> POST credentials to the form's
    action -> 302 to REDIRECT_URI?code=... -> exchange for tokens.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_hex(8)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # Not _request(): that discards the final URL. The authorize endpoint
    # redirects to a session-bound login page and the form's action is relative
    # to *that* page, so it is the one to resolve against below.
    req = urllib.request.Request(_authorize_url(challenge, state))
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "text/html")
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            login_url, status, raw = resp.geturl(), resp.status, resp.read()
    except urllib.error.HTTPError as ex:
        login_url, status, raw = ex.url, ex.code, ex.read()
    except urllib.error.URLError as ex:
        raise ParroError("network error calling authorize: {}".format(ex.reason))
    if status != 200:
        raise ParroError("authorize returned {} (expected the login page)".format(status))
    html = raw.decode("utf-8", "replace")

    m = re.search(r'<form[^>]*\baction="([^"]*signInForm[^"]*)"', html, re.I)
    if not m:
        m = re.search(r'<form[^>]*\baction="([^"]+)"[^>]*>', html, re.I)
    if not m:
        raise ParroError(
            "could not find the login form on the ParnasSys page. The IdP layout may "
            "have changed, or an extra step (2FA / account chooser) is in the way.\n"
            "First 500 chars:\n" + html[:500])
    action = urllib.parse.urljoin(login_url, m.group(1).replace("&amp;", "&"))

    form = urllib.parse.urlencode({
        "aanmelden": "x",
        "emailadres": username,
        "wachtwoord": password,
    }).encode("utf-8")

    # Do not follow the redirect - we need the Location with ?code=.
    no_redirect = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    status, hdrs, raw = _request("POST", action, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html",
    }, body=form, opener=no_redirect)

    loc = hdrs.get("Location") or hdrs.get("location") or ""
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        body = raw.decode("utf-8", "replace")
        if re.search(r"onjuist|niet\s+juist|invalid|incorrect", body, re.I):
            _set_lockout("the login form rejected these credentials")
            raise LoginLocked(
                "login rejected: wrong username or password. NOT retrying - the "
                "account locks after a few failed attempts.")
        raise ParroError(
            "login did not yield an authorization code - an extra step "
            "(2FA / consent) may be required.\nstatus={} location={}".format(
                status, loc[:200]))
    _clear_lockout()
    return _exchange_code(code, verifier)


def _headless_login(username, password):
    """Log in without a browser: password grant first, login form as fallback."""
    try:
        return _password_grant(username, password)
    except LoginLocked:
        # invalid_grant does not always mean a wrong password: the IdP answers
        # it for accounts it will not put through the password grant at all,
        # and then the only way in is the form - which is what a browser does,
        # and which rejects bad credentials on its own terms. So try it once
        # rather than latching on a verdict the grant is not qualified to give.
        log("password grant rejected the credentials, trying the login form once")
        return _form_login(username, password)
    except ParroError as ex:
        log("password grant unavailable ({}), falling back to the login form".format(ex))
        return _form_login(username, password)


def _access_token():
    tok = _load_tokens()
    if tok.get("access_token") and tok.get("expires_at", 0) > time.time():
        return tok["access_token"]
    if tok.get("refresh_token"):
        try:
            return _refresh(tok["refresh_token"])["access_token"]
        except ParroError as ex:
            log("refresh failed, falling back to login: {}".format(ex))
    user, pwd = _env_credentials()
    if user and pwd:
        _guard_lockout()
        return _headless_login(user, pwd)["access_token"]
    raise ParroError(
        "not authenticated. Either set PARRO_USERNAME/PARRO_PASSWORD for automatic "
        "login, or run parro_login_url and then parro_login_finish with the code "
        "from the redirect URL.")


# ------------------------------------------------------------------- the API
def api_get(path, params=None, limit=None, offset=0, want_count=False, role=True):
    """GET a geon endpoint. Returns (parsed json, content-range or None)."""
    if not path.startswith("/"):
        path = "/" + path
    if not path.startswith("/rest/"):
        path = "/rest/v2" + path
    url = BASE_URI + path
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(clean)

    headers = {
        "Authorization": "Bearer " + _access_token(),
        "Accept": GEON,
        "Content-Type": GEON,
        "parro-app-version": APP_VERSION,
    }
    if role:
        r = _role_header()
        if r:
            headers["parro-authorization-role"] = r
    if limit is not None:
        headers["Range"] = "items={}-{}".format(offset, offset + int(limit) - 1)
        if want_count:
            headers["topicus-Range-Count"] = "Exact"

    status, hdrs, raw = _request("GET", url, headers)
    if status == 401:
        # Token may have gone stale mid-session; drop it and retry once.
        _state["tokens"] = None
        try:
            os.remove(TOKEN_FILE)
        except OSError:
            pass
        headers["Authorization"] = "Bearer " + _access_token()
        status, hdrs, raw = _request("GET", url, headers)
    if status not in (200, 206):
        raise ParroError("GET {} -> {}: {}".format(
            url, status, raw.decode("utf-8", "replace")[:400]))
    text = raw.decode("utf-8", "replace")
    return (json.loads(text) if text.strip() else None,
            hdrs.get("Content-Range") or hdrs.get("content-range"))


def _account():
    if _state["account"] is None:
        # Deliberately without the role header - that is what we are deriving.
        _state["account"] = api_get("/account/me", role=False)[0]
    return _state["account"]


def _role_header():
    """Build `parro-authorization-role`, e.g. GUARDIAN:1234567890."""
    if os.environ.get("PARRO_ROLE"):
        return os.environ["PARRO_ROLE"]
    if _state["role"]:
        return _state["role"]
    try:
        acct = _account()
    except ParroError:
        return None
    ident = acct.get("identity") or {}
    kind = (acct.get("accountType") or ident.get("role") or "GUARDIAN").upper()
    for key in ("guardians", "teachers", "children"):
        for entry in ident.get(key) or []:
            rid = _self_id(entry)
            if rid:
                _state["role"] = "{}:{}".format(kind, rid)
                return _state["role"]
    return None


# ------------------------------------------------------------ response slimming
def _self_id(obj):
    if not isinstance(obj, dict):
        return None
    for link in obj.get("links") or []:
        if link.get("rel") == "self" and "id" in link:
            return link["id"]
    return obj.get("id")


NOISE = ("permissions", "links", "dtype", "additionalObjects")


def slim(obj):
    """Strip the geon boilerplate (permissions/links/dtype) that makes these
    payloads 10x larger than the information they carry."""
    if isinstance(obj, list):
        return [slim(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {}
    rid = _self_id(obj)
    if rid is not None:
        out["id"] = rid
    if obj.get("dtype"):
        out["type"] = obj["dtype"].split(".")[-1]
    for k, v in obj.items():
        if k in NOISE or (k == "id" and "id" in out):
            continue
        if v is None or v == [] or v == {}:
            continue
        out[k] = slim(v)
    return out


def _items(payload):
    if isinstance(payload, dict) and "items" in payload:
        return payload["items"]
    return payload if isinstance(payload, list) else [payload]


def _total(content_range):
    if content_range and "/" in content_range:
        tail = content_range.rsplit("/", 1)[1].strip()
        if tail.isdigit():
            return int(tail)
    return None


def _text(obj):
    return json.dumps(obj, ensure_ascii=False, indent=1, default=str)


# ------------------------------------------------------- attachment text extraction
TEXTUAL = ("text/", "application/json", "application/xml", "text/csv")
MAX_DOWNLOAD = int(os.environ.get("PARRO_MAX_DOWNLOAD", str(60 * 1024 * 1024)))


def _is_extractable(content_type, filename):
    ct = (content_type or "").lower()
    name = (filename or "").lower()
    if "pdf" in ct or name.endswith(".pdf"):
        return True
    if any(ct.startswith(t) for t in TEXTUAL):
        return True
    if name.endswith((".txt", ".csv", ".md", ".json", ".xml", ".html", ".htm")):
        return True
    if ct.startswith("image/"):
        return False
    if name.endswith(".docx"):
        return True
    return False


def _download(url, size_hint=None):
    if size_hint and size_hint > MAX_DOWNLOAD:
        raise ParroError("attachment is {:.1f} MB, over the {:.0f} MB limit "
                         "(raise PARRO_MAX_DOWNLOAD to allow it)".format(
                             size_hint / 1e6, MAX_DOWNLOAD / 1e6))
    # CDN entry URLs are pre-signed and must NOT carry the Parro Authorization
    # header; API-hosted paths must.
    headers = {"Accept": "*/*"}
    if url.startswith(BASE_URI):
        headers["Authorization"] = "Bearer " + _access_token()
        headers["parro-app-version"] = APP_VERSION
        r = _role_header()
        if r:
            headers["parro-authorization-role"] = r
    status, hdrs, raw = _request("GET", url, headers)
    if status not in (200, 206):
        raise ParroError("downloading attachment failed ({}): {}".format(
            status, raw[:200].decode("utf-8", "replace")))
    if len(raw) > MAX_DOWNLOAD:
        raise ParroError("attachment is larger than PARRO_MAX_DOWNLOAD")
    return raw, hdrs.get("Content-Type", "")


def _pdf_to_text(data):
    """Extract text from a PDF, preferring PyMuPDF, then pypdf.

    Returns (text, page_count, engine). Raises ParroError if no engine is
    installed, since a silent empty string reads like an empty document.
    """
    try:
        import fitz  # PyMuPDF
        with fitz.open(stream=data, filetype="pdf") as doc:
            pages = [p.get_text("text") for p in doc]
        return "\n".join(pages), len(pages), "pymupdf"
    except ImportError:
        pass
    except Exception as ex:  # corrupt/encrypted PDF - fall through to pypdf
        log("pymupdf failed ({}), trying pypdf".format(ex))
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        pages = [(p.extract_text() or "") for p in reader.pages]
        return "\n".join(pages), len(pages), "pypdf"
    except ImportError:
        raise ParroError(
            "no PDF engine available. Install one into the interpreter running "
            "this server:  pip install pymupdf   (or: pip install pypdf)")
    except Exception as ex:
        raise ParroError("could not parse this PDF: {}".format(ex))


def _docx_to_text(data):
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        xml = z.read("word/document.xml").decode("utf-8", "replace")
    xml = re.sub(r"</w:p>", "\n", xml)
    xml = re.sub(r"<w:tab[^>]*/>", "\t", xml)
    return re.sub(r"<[^>]+>", "", xml)


def _strip_html(text):
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'"))
    return text


def _tidy(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def extract_text(data, content_type="", filename=""):
    """Turn attachment bytes into plain text. Returns (text, meta dict)."""
    ct = (content_type or "").lower()
    name = (filename or "").lower()
    if "pdf" in ct or name.endswith(".pdf"):
        text, pages, engine = _pdf_to_text(data)
        return _tidy(text), {"format": "pdf", "pages": pages, "engine": engine}
    if name.endswith(".docx") or "wordprocessingml" in ct:
        return _tidy(_docx_to_text(data)), {"format": "docx"}
    if "html" in ct or name.endswith((".html", ".htm")):
        return _tidy(_strip_html(data.decode("utf-8", "replace"))), {"format": "html"}
    if any(ct.startswith(t) for t in TEXTUAL) or name.endswith(
            (".txt", ".csv", ".md", ".json", ".xml")):
        return _tidy(data.decode("utf-8", "replace")), {"format": "text"}
    if ct.startswith("image/"):
        raise ParroError(
            "this attachment is an image ({}), which holds no extractable text. "
            "Its `url` from parro_announcements can be opened or downloaded "
            "directly.".format(ct or name))
    raise ParroError("no text extractor for content type '{}' (file '{}'). "
                     "Download it from the `url` instead.".format(content_type, filename))


MAX_IMAGE_PX = int(os.environ.get("PARRO_MAX_IMAGE_PX", "1400"))


def _shrink_image(data, content_type):
    """Downscale a photo so it does not blow up the response.

    Parro photos are full-resolution phone pictures (1-3 MB); base64 of that is
    a lot of tokens for no extra detail. Without Pillow the original is passed
    through unchanged.
    """
    try:
        import io
        from PIL import Image
    except ImportError:
        return data, content_type
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        if max(img.size) <= MAX_IMAGE_PX and len(data) < 900_000:
            return data, content_type
        img.thumbnail((MAX_IMAGE_PX, MAX_IMAGE_PX), Image.LANCZOS)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=82, optimize=True)
        return buf.getvalue(), "image/jpeg"
    except Exception as ex:
        log("image downscale failed ({}), sending original".format(ex))
        return data, content_type


# ---------------------------------------------------------------------- tools
def t_auth_status(_args):
    tok = _load_tokens()
    out = {
        "token_file": TOKEN_FILE,
        "has_access_token": bool(tok.get("access_token")),
        "has_refresh_token": bool(tok.get("refresh_token")),
        "credentials_in_env": all(_env_credentials()),
        "scope": SCOPE,
        "base_uri": BASE_URI,
    }
    if _lockout_note():
        out["automatic_login_halted"] = _lockout_note()
        out["how_to_resume"] = ("Fix the credentials, then call parro_login. Automatic "
                                "retries are suppressed so the account cannot be "
                                "locked out.")
    if tok.get("expires_at"):
        left = int(tok["expires_at"] - time.time())
        out["access_token_expires_in_seconds"] = left
        out["access_token_valid"] = left > 0
    try:
        acct = _account()
        out["logged_in_as"] = {
            "name": " ".join(filter(None, [
                (acct.get("identity") or {}).get("firstname"),
                (acct.get("identity") or {}).get("surname")])),
            "email": acct.get("email"),
            "accountType": acct.get("accountType"),
            "organisation": (acct.get("organisation") or {}).get("name"),
            "role_header": _role_header(),
        }
    except ParroError as ex:
        out["error"] = str(ex)
    return _text(out)


def t_login(_args):
    user, pwd = _env_credentials()
    if not (user and pwd):
        raise ParroError("PARRO_USERNAME and PARRO_PASSWORD are not set. Use "
                         "parro_login_url for the interactive browser flow instead.")
    # An explicit call means the operator believes the credentials are right now,
    # so clear the latch and spend exactly one attempt.
    _clear_lockout()
    _headless_login(user, pwd)
    return t_auth_status({})


def t_logout(_args):
    """Revoke the stored tokens and forget them."""
    tok = _load_tokens()
    revoked = []
    for kind in ("refresh_token", "access_token"):
        if not tok.get(kind):
            continue
        body = urllib.parse.urlencode({
            "token": tok[kind],
            "token_type_hint": kind,
            "client_id": CLIENT_ID,
        }).encode("utf-8")
        status, _h, _raw = _request("POST", "{}/idp/oauth2/revoke".format(LOGIN_URI), {
            "Content-Type": "application/x-www-form-urlencoded"}, body=body)
        revoked.append({kind: status})
    _state.update({"tokens": None, "role": None, "account": None})
    try:
        os.remove(TOKEN_FILE)
    except OSError:
        pass
    return _text({"logged_out": True, "revocation_responses": revoked,
                  "token_file_removed": TOKEN_FILE})


def t_login_url(_args):
    verifier, challenge = _pkce_pair()
    state = secrets.token_hex(8)
    tok = _load_tokens()
    tok["pending_verifier"] = verifier
    tok["pending_state"] = state
    _save_tokens(tok)
    return (
        "1. Open this URL in a browser and log in with your ParnasSys account:\n\n"
        "{}\n\n"
        "2. You land on {}?code=...&state=... - copy the FULL address bar URL\n"
        "   (do it promptly: the Parro web app tries to consume the code itself,\n"
        "   and each code works only once. If it fails, just run this tool again).\n\n"
        "3. Pass that URL to parro_login_finish."
    ).format(_authorize_url(challenge, state), REDIRECT_URI)


def t_login_finish(args):
    raw = (args.get("url") or args.get("code") or "").strip()
    if not raw:
        raise ParroError("pass the redirect `url` (or bare `code`) you were sent to.")
    code = raw
    if "?" in raw or raw.startswith("http"):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
        if qs.get("error"):
            raise ParroError("IdP returned an error: {}".format(qs["error"][0]))
        code = (qs.get("code") or [""])[0]
    if not code:
        raise ParroError("no ?code= found in that URL.")
    verifier = _load_tokens().get("pending_verifier")
    if not verifier:
        raise ParroError("no pending login - run parro_login_url first.")
    _exchange_code(code, verifier)
    return t_auth_status({})


def t_me(args):
    acct = _account()
    if args.get("raw"):
        return _text(acct)
    ident = acct.get("identity") or {}
    return _text({
        "name": " ".join(filter(None, [ident.get("firstname"), ident.get("surname")])),
        "email": acct.get("email"),
        "username": acct.get("username"),
        "accountType": acct.get("accountType"),
        "role_header": _role_header(),
        "organisation": slim(acct.get("organisation") or {}),
        "children": [c.get("firstname") for c in (ident.get("children") or [])] or None,
    })


def t_children(args):
    payload, cr = api_get("/child", limit=args.get("limit", 20), want_count=True)
    items = _items(payload)
    if args.get("raw"):
        return _text(payload)
    return _text({
        "total": _total(cr) or len(items),
        "children": [{
            "id": _self_id(c),
            "name": " ".join(filter(None, [c.get("firstname"), c.get("surname")])),
            "archived": c.get("archived"),
            "enrolledSince": c.get("enrolledSince"),
            "numberOfGuardians": c.get("numberOfGuardians"),
        } for c in items],
    })


def t_groups(args):
    scope = (args.get("scope") or "current").lower()
    if scope == "previous":
        payload, cr = api_get("/group", {"scope": "PREVIOUS_ACTIVE"},
                              limit=args.get("limit", 50), want_count=True)
    else:
        payload, cr = api_get("/group", {"dtype": "identity.RHomeGroup"},
                              limit=args.get("limit", 50), want_count=True)
    items = _items(payload)
    if args.get("raw"):
        return _text(payload)
    return _text({
        "scope": scope,
        "total": _total(cr) or len(items),
        "groups": [{
            "id": _self_id(g),
            "name": g.get("name"),
            "schoolyear": g.get("schooljaar"),
            "type": g.get("type"),
            "isHomeGroup": g.get("stamgroep"),
            "unread": g.get("unreadCount"),
            "muted": g.get("memberMuted"),
            "children": [a.get("firstname") for a in g.get("childAvatars") or []] or None,
            "counts": {"children": g.get("numberOfChildren"),
                       "guardians": g.get("numberOfGuardians"),
                       "teachers": g.get("numberOfTeachers")},
        } for g in items],
    })


def _group_ids(args):
    if args.get("group_id"):
        return [args["group_id"]]
    payload, _cr = api_get("/group", {"dtype": "identity.RHomeGroup"}, limit=50)
    return [_self_id(g) for g in _items(payload) if _self_id(g)]


def _source_entry(att):
    """Pick the downloadable original out of an attachment's `entries`.

    Images carry several entries (SOURCE plus resized variants); documents carry
    a single SOURCE. Each entry holds a direct, time-limited CDN `url`.
    """
    entries = att.get("entries") or ([att.get("entry")] if att.get("entry") else [])
    entries = [e for e in entries if isinstance(e, dict)]
    if not entries:
        return {}
    for e in entries:
        if e.get("type") == "SOURCE":
            return e
    return entries[0]


def _fmt_attachments(ev):
    out = []
    for a in ev.get("attachments") or []:
        e = _source_entry(a)
        out.append({k: v for k, v in {
            "attachment_id": _self_id(a),
            "kind": a.get("attachmentType"),
            "filename": e.get("filename"),
            "contentType": e.get("contentType"),
            "size": e.get("size"),
            "url": e.get("url"),
            "readable": _is_extractable(e.get("contentType"), e.get("filename")),
        }.items() if v is not None})
    return out


def _fmt_announcement(ev, group_name=None):
    out = {
        "id": _self_id(ev),
        "date": ev.get("sortDate") or ev.get("createdAt"),
        "title": ev.get("title"),
        "from": group_name,
        "read": ev.get("read"),
        "liked": ev.get("liked"),
        "contents": ev.get("contents"),
    }
    atts = _fmt_attachments(ev)
    if atts:
        out["attachments"] = atts
        out["hint"] = ("Use parro_attachment with this announcement id to read the "
                       "attachment text.")
    return {k: v for k, v in out.items() if v is not None}


def t_announcements(args):
    limit = int(args.get("limit", 20))
    groups = {}
    if not args.get("group_id"):
        payload, _cr = api_get("/group", {"dtype": "identity.RHomeGroup"}, limit=50)
        groups = {_self_id(g): g.get("name") for g in _items(payload)}
        gids = list(groups)
    else:
        gids = [args["group_id"]]

    collected = []
    for gid in gids:
        payload, _cr = api_get("/event", {
            "dtype": "event.RAnnouncementEventPrimer", "group": gid}, limit=limit)
        for ev in _items(payload):
            collected.append((ev, groups.get(gid)))

    if args.get("raw"):
        return _text([e for e, _ in collected])

    collected.sort(key=lambda t: t[0].get("sortDate") or "", reverse=True)
    out = [_fmt_announcement(ev, name) for ev, name in collected[:limit]]
    if args.get("unread_only"):
        out = [a for a in out if not a.get("read")]
    return _text({"count": len(out), "announcements": out})


def _event(eid, dtype="event.RAnnouncementEvent"):
    # The single-event endpoint needs a dtype, otherwise it answers
    # 406 EVENT_BAD_TYPE on the abstract supertype.
    return api_get("/event/{}".format(eid), {"dtype": dtype})[0]


def t_announcement(args):
    eid = args.get("id")
    if not eid:
        raise ParroError("`id` is required (get it from parro_announcements).")
    payload = _event(eid, args.get("dtype") or "event.RAnnouncementEvent")
    if args.get("raw"):
        return _text(payload)
    out = _fmt_announcement(payload)
    owner = payload.get("owner") or {}
    if owner:
        out["author"] = " ".join(filter(None, [owner.get("firstname"),
                                               owner.get("surname")])) or None
    return _text(out)


def t_attachment(args):
    """Download an announcement attachment and return its text."""
    url = args.get("url")
    filename = args.get("filename") or ""
    content_type = args.get("content_type") or ""
    size = None

    if not url:
        eid = args.get("announcement_id") or args.get("id")
        if not eid:
            raise ParroError(
                "give either `announcement_id` (optionally with `attachment_id`) "
                "or a direct `url` from parro_announcements.")
        ev = _event(eid, args.get("dtype") or "event.RAnnouncementEvent")
        atts = ev.get("attachments") or []
        if not atts:
            raise ParroError("announcement {} has no attachments.".format(eid))
        wanted = args.get("attachment_id")
        if wanted:
            atts = [a for a in atts if _self_id(a) == wanted]
            if not atts:
                raise ParroError("attachment {} not found on announcement {}.".format(
                    wanted, eid))
        elif len(atts) > 1 and not args.get("all"):
            return _text({
                "announcement": ev.get("title"),
                "message": "This announcement has several attachments. Call again with "
                           "`attachment_id`, or pass `all: true` to read them all.",
                "attachments": _fmt_attachments(ev),
            })
        results, images = [], []
        for a in atts:
            e = _source_entry(a)
            name = e.get("filename") or _name_from_url(e.get("url"))
            ct = e.get("contentType") or ""
            try:
                data, served_ct = _download(e.get("url"), e.get("size"))
                ct = ct or served_ct
                if ct.startswith("image/") and not args.get("no_images"):
                    images.append(_image_block(data, ct, name, _self_id(a)))
                    results.append({"attachment_id": _self_id(a), "filename": name,
                                    "contentType": ct, "bytes": e.get("size"),
                                    "returned_as": "image"})
                    continue
                text, meta = extract_text(data, ct, name)
            except ParroError as ex:
                results.append({"attachment_id": _self_id(a), "filename": name,
                                "error": str(ex)})
                continue
            r = _attachment_result(text, meta, name, ct, e.get("size"),
                                   e.get("url"), args)
            r["attachment_id"] = _self_id(a)
            results.append(r)

        if len(results) == 1:
            summary = dict(results[0], announcement=ev.get("title"))
        else:
            summary = {"announcement": ev.get("title"), "attachments": results}
        blocks = [{"type": "text", "text": _text(summary)}]
        return blocks + images if images else _text(summary)

    data, served_ct = _download(url, size)
    ct = content_type or served_ct
    name = filename or _name_from_url(url)
    if ct.startswith("image/") and not args.get("no_images"):
        return [{"type": "text", "text": _text(
            {"filename": name, "contentType": ct, "bytes": len(data),
             "returned_as": "image"})},
            _image_block(data, ct, name, None)]
    text, meta = extract_text(data, ct, name)
    return _text(_attachment_result(text, meta, name, ct, len(data), url, args))


def _name_from_url(url):
    if not url:
        return None
    return urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]) or None


def _image_block(data, content_type, name, aid):
    data, content_type = _shrink_image(data, content_type)
    return {"type": "image",
            "data": base64.b64encode(data).decode("ascii"),
            "mimeType": content_type}


def _attachment_result(text, meta, filename, content_type, size, url, args):
    max_chars = int(args.get("max_chars", 40000))
    out = {
        "filename": filename,
        "contentType": content_type,
        "bytes": size,
        "chars": len(text),
    }
    out.update(meta)
    if args.get("page") and meta.get("format") == "pdf":
        out["note"] = "`page` is not supported; the full text is returned."
    if len(text) > max_chars:
        out["truncated"] = True
        out["shown_chars"] = max_chars
        out["hint"] = "Raise `max_chars` to read the rest."
        text = text[:max_chars]
    if not text.strip():
        out["warning"] = ("No text could be extracted. This is most likely a scanned "
                          "or image-only document, which would need OCR.")
        out["url"] = url
    out["text"] = text
    return out


def t_calendar(args):
    limit = int(args.get("limit", 20))
    dtype = args.get("dtype") or "event.RCalendarItemEventPrimer"
    groups = {}
    if not args.get("group_id"):
        payload, _cr = api_get("/group", {"dtype": "identity.RHomeGroup"}, limit=50)
        groups = {_self_id(g): g.get("name") for g in _items(payload)}
        gids = list(groups)
    else:
        gids = [args["group_id"]]

    collected = []
    for gid in gids:
        payload, _cr = api_get("/event", {"dtype": dtype, "group": gid}, limit=limit)
        for ev in _items(payload):
            collected.append((ev, groups.get(gid)))
    if args.get("raw"):
        return _text([e for e, _ in collected])
    collected.sort(key=lambda t: t[0].get("sortDate") or "")
    return _text({"count": len(collected), "items": [
        dict(slim(ev), group=name) for ev, name in collected[:limit]]})


def t_chatrooms(args):
    payload, cr = api_get("/chatroom", limit=args.get("limit", 25), want_count=True)
    items = _items(payload)
    if args.get("raw"):
        return _text(payload)
    return _text({"total": _total(cr) or len(items),
                  "chatrooms": [slim(c) for c in items]})


def t_chat_messages(args):
    rid = args.get("chatroom_id")
    if not rid:
        raise ParroError("`chatroom_id` is required (get it from parro_chatrooms).")
    payload, cr = api_get("/chatroom/{}/chatmessage".format(rid),
                          limit=args.get("limit", 30), want_count=True)
    items = _items(payload)
    if args.get("raw"):
        return _text(payload)
    return _text({"total": _total(cr) or len(items),
                  "messages": [slim(m) for m in items]})


def t_unread(args):
    payload, _cr = api_get("/identity/unreadcounts")
    if args.get("raw"):
        return _text(payload)
    out = []
    for it in _items(payload):
        g = it.get("guardian") or it.get("identity") or {}
        out.append({
            "for": " ".join(filter(None, [g.get("firstname"), g.get("surname")])),
            "children": g.get("childNames"),
            "announcements": it.get("numberOfUnreadAnnouncements"),
            "calendar": it.get("numberOfUnreadCalendarItems"),
            "systemNews": it.get("numberOfUnreadSystemNewsItems"),
            "chats": it.get("numberOfUnreadChatRooms"),
            "portal": it.get("numberOfUnreadPortalNotifications"),
        })
    return _text(out)


def t_get(args):
    path = args.get("path")
    if not path:
        raise ParroError("`path` is required, e.g. /accountsettings or "
                         "/event?dtype=event.RAnnouncementEventPrimer&group=123")
    params = args.get("params") or None
    payload, cr = api_get(path, params, limit=args.get("limit"),
                          offset=args.get("offset", 0), want_count=True)
    body = payload if args.get("raw") else slim(payload)
    return _text({"content_range": cr, "body": body})


TOOL_IMPL = {
    "parro_auth_status": t_auth_status,
    "parro_login": t_login,
    "parro_login_url": t_login_url,
    "parro_login_finish": t_login_finish,
    "parro_logout": t_logout,
    "parro_me": t_me,
    "parro_children": t_children,
    "parro_groups": t_groups,
    "parro_announcements": t_announcements,
    "parro_announcement": t_announcement,
    "parro_attachment": t_attachment,
    "parro_calendar": t_calendar,
    "parro_chatrooms": t_chatrooms,
    "parro_chat_messages": t_chat_messages,
    "parro_unread": t_unread,
    "parro_get": t_get,
}

_RAW = {"raw": {"type": "boolean",
                "description": "Return the untouched geon payload instead of the "
                               "slimmed-down summary."}}


def _schema(props=None, required=None, raw=True):
    p = dict(props or {})
    if raw:
        p.update(_RAW)
    s = {"type": "object", "properties": p}
    if required:
        s["required"] = required
    return s


TOOLS = [
    {"name": "parro_auth_status",
     "description": "Show whether the server is logged in to Parro, which account and "
                    "role it is using, and when the access token expires. Start here "
                    "if a call fails with an auth error.",
     "inputSchema": _schema(raw=False)},
    {"name": "parro_login",
     "description": "Log in headlessly using the PARRO_USERNAME/PARRO_PASSWORD "
                    "environment variables. Normally unnecessary - every tool logs in "
                    "and refreshes on demand.",
     "inputSchema": _schema(raw=False)},
    {"name": "parro_login_url",
     "description": "Start the interactive browser login (OAuth2 + PKCE) and return "
                    "the URL to open. Use this when no username/password is configured. "
                    "Follow up with parro_login_finish.",
     "inputSchema": _schema(raw=False)},
    {"name": "parro_login_finish",
     "description": "Complete the interactive login by handing back the redirect URL "
                    "(https://talk.parro.com/oauth2?code=...) you landed on.",
     "inputSchema": _schema({
         "url": {"type": "string", "description": "The full redirect URL, or just the code."},
     }, raw=False)},
    {"name": "parro_logout",
     "description": "Revoke the stored tokens at the IdP and delete the local token "
                    "cache.",
     "inputSchema": _schema(raw=False)},
    {"name": "parro_me",
     "description": "The logged-in Parro account: name, e-mail, account type, school "
                    "(organisation) and children.",
     "inputSchema": _schema()},
    {"name": "parro_children",
     "description": "The children linked to this account, with enrolment info.",
     "inputSchema": _schema({"limit": {"type": "integer", "default": 20}})},
    {"name": "parro_groups",
     "description": "School groups (classes) this account can see, with ids needed by "
                    "parro_announcements and parro_calendar, plus unread counts.",
     "inputSchema": _schema({
         "scope": {"type": "string", "enum": ["current", "previous"], "default": "current",
                   "description": "'current' = this school year, 'previous' = last year."},
         "limit": {"type": "integer", "default": 50}})},
    {"name": "parro_announcements",
     "description": "Read announcements ('mededelingen') posted by teachers and the "
                    "school - the main Parro feed. Without group_id it merges every "
                    "group, newest first. Includes full message text and attachments.",
     "inputSchema": _schema({
         "group_id": {"type": "integer", "description": "Restrict to one group (see parro_groups)."},
         "limit": {"type": "integer", "default": 20},
         "unread_only": {"type": "boolean", "description": "Only announcements not yet read."}})},
    {"name": "parro_announcement",
     "description": "One announcement in full, by id, including attachment download URLs.",
     "inputSchema": _schema({"id": {"type": "integer"}}, required=["id"])},
    {"name": "parro_attachment",
     "description": "Read the CONTENTS of an announcement attachment - the newsletters "
                    "('nieuwsbrief') and letters the school sends as PDF. Downloads the "
                    "file and returns its extracted text, so it can be summarised or "
                    "searched. Also handles .docx, .txt/.csv and .html. Photo "
                    "attachments come back as viewable images (downscaled). Pass "
                    "announcement_id (from parro_announcements), or a direct url.",
     "inputSchema": _schema({
         "announcement_id": {"type": "integer",
                             "description": "Announcement holding the attachment."},
         "attachment_id": {"type": "integer",
                           "description": "Which attachment, when there are several."},
         "all": {"type": "boolean",
                 "description": "Read every attachment on the announcement."},
         "url": {"type": "string",
                 "description": "Direct attachment url instead of looking it up."},
         "filename": {"type": "string", "description": "Helps pick the parser when using url."},
         "content_type": {"type": "string", "description": "Ditto, e.g. application/pdf."},
         "max_chars": {"type": "integer", "default": 40000,
                       "description": "Truncate the returned text at this many characters."},
         "no_images": {"type": "boolean",
                       "description": "Describe photos instead of returning image data."},
     }, raw=False)},
    {"name": "parro_calendar",
     "description": "Calendar items (events, parent-teacher evenings, activities) from "
                    "the event feed, soonest first.",
     "inputSchema": _schema({
         "group_id": {"type": "integer"},
         "limit": {"type": "integer", "default": 20},
         "dtype": {"type": "string",
                   "description": "Override the event dtype, default event.RCalendarItemEventPrimer."}})},
    {"name": "parro_chatrooms",
     "description": "Chat conversations with teachers.",
     "inputSchema": _schema({"limit": {"type": "integer", "default": 25}})},
    {"name": "parro_chat_messages",
     "description": "Messages in one chat conversation.",
     "inputSchema": _schema({
         "chatroom_id": {"type": "integer"},
         "limit": {"type": "integer", "default": 30}}, required=["chatroom_id"])},
    {"name": "parro_unread",
     "description": "Unread counts across announcements, calendar, chats and system news.",
     "inputSchema": _schema()},
    {"name": "parro_get",
     "description": "Escape hatch: GET any Parro REST endpoint (read-only) and return "
                    "the slimmed JSON. Paths are relative to /rest/v2, e.g. "
                    "'/accountsettings', '/absence/setting', '/organisation/{id}' "
                    "(the school's id is in the parro_me output), '/systemnews'. "
                    "Use this for endpoints without a dedicated tool.",
     "inputSchema": _schema({
         "path": {"type": "string", "description": "e.g. /accountsettings"},
         "params": {"type": "object", "description": "Query parameters, e.g. {\"dtype\": \"...\"}"},
         "limit": {"type": "integer", "description": "Page size (sets the Range header)."},
         "offset": {"type": "integer", "default": 0}}, required=["path"])},
]


def call_tool(name, args):
    """Return either a string or a list of MCP content blocks."""
    fn = TOOL_IMPL.get(name)
    if not fn:
        return "ERROR: unknown tool: {}".format(name)
    try:
        return fn(args or {})
    except ParroError as ex:
        return "ERROR: {}".format(ex)


def _blocks(result):
    """Normalise a tool result into MCP content blocks."""
    if isinstance(result, list):
        return result
    return [{"type": "text", "text": result}]


# ------------------------------------------------------------------- JSON-RPC
def send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def handle(req):
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        ver = params.get("protocolVersion") or "2025-06-18"
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": ver,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "parro", "version": "1.0.0"},
        }}
    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method in ("resources/list", "prompts/list"):
        key = "resources" if method.startswith("resources") else "prompts"
        return {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            result = call_tool(name, args)
            is_err = isinstance(result, str) and result.startswith("ERROR:")
        except Exception:
            result, is_err = traceback.format_exc(), True
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": _blocks(result), "isError": is_err}}

    if rid is None:
        return None
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "Method not found: {}".format(method)}}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "call":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        name = sys.argv[2] if len(sys.argv) > 2 else "parro_auth_status"
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        for block in _blocks(call_tool(name, args)):
            if block.get("type") == "image":
                print("<image {} {} bytes base64>".format(
                    block.get("mimeType"), len(block.get("data", ""))))
            else:
                print(block.get("text", ""))
        return
    if len(sys.argv) > 1 and sys.argv[1] == "tools":
        for t in TOOLS:
            print("{:22s} {}".format(t["name"], t["description"].split(".")[0]))
        return

    try:
        sys.stdin.reconfigure(encoding="utf-8-sig")
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    except Exception:
        pass
    log("started, talking to {}".format(BASE_URI))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as ex:
            log("bad JSON: {}".format(ex))
            continue
        try:
            resp = handle(req)
        except Exception:
            log(traceback.format_exc())
            resp = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32603, "message": traceback.format_exc()}}
        if resp is not None:
            send(resp)
    log("stdin closed, exiting")


if __name__ == "__main__":
    main()
