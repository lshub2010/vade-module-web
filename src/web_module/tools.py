"""Web tools — GET/HEAD over http(s) with the boundary in front of every socket.

Two tools (`web_fetch`, `web_head`) and one job: make it impossible for a model
to turn a URL into a probe of the host's own network. The whole module therefore
funnels every request through `_validate_url()`, which answers three questions
before a socket exists:

1. **Is the scheme one we speak?** Only `http` and `https`. `file://`, `ftp://`,
   `data:` and friends are refused with `PERMISSION_DENIED` before urllib ever
   sees the string (urllib ships handlers for `file:` and `ftp:`; they are not
   reachable from here).
2. **Does the name point somewhere public?** Every address `getaddrinfo`
   returns is checked; one non-public answer fails the whole request. "Public"
   is `ipaddress.is_global` **plus** an explicit deny list, because `is_global`
   is wrong for exactly the cases that matter: it says `True` for multicast
   (`224.0.0.1`), for `64:ff9b::/96` NAT64 wrappers around `127.0.0.1`, and it
   has nothing to say about `100.64.0.0/10` being carrier-grade NAT.
3. **Which socket are we actually opening?** The validated address is pinned:
   the connection is made to that literal IP, while `Host`/SNI/certificate
   checks still use the original host name. Re-resolving at connect time would
   hand a rebinding attacker the last word — pinning takes it back.

Redirects are followed by hand (`MAX_REDIRECTS = 3`), never by urllib, and each
hop is re-validated with the same function. That is the difference between
"the first URL was checked" and "the URL we are fetching was checked".

Everything below is stdlib (`urllib`, `http.client`, `socket`, `ipaddress`) and
the module never imports `vade_sdk` — see `server.py` for the adapter.

Limits are deliberate and small: `DEFAULT_MAX_BYTES` 256 KiB, hard ceiling 1 MiB,
10 s per hop, 30 s per call. A tool that can be asked for an unbounded download
is a tool that can be asked to exhaust the process.
"""

from __future__ import annotations

import errno
import functools
import http.client
import ipaddress
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message
from typing import Any, Callable

__all__ = [
    "tool",
    "ToolFailure",
    "DEFAULT_MAX_BYTES",
    "MAX_BYTES_CEILING",
    "MAX_REDIRECTS",
    "REQUEST_TIMEOUT_SECONDS",
    "TOTAL_TIMEOUT_SECONDS",
    "MAX_URL_LENGTH",
    "USER_AGENT",
    "ALLOWED_SCHEMES",
    "REDIRECT_STATUSES",
    "FRAME_PLAINTEXT_BYTES",
    "validate_url",
    "web_fetch",
    "web_head",
    "all_tools",
]

#: Default body window for `web_fetch`. A model asking to "read a page" wants a
#: page, not a megabyte of tokens.
DEFAULT_MAX_BYTES = 262_144

#: Hard ceiling for one response body, independent of the caller's `max_bytes`.
MAX_BYTES_CEILING = 1024 * 1024

#: Redirect hops we are willing to follow. Each hop is re-validated; a chain
#: longer than this is refused with `INVALID_ARGUMENT`, not followed blindly.
MAX_REDIRECTS = 3

#: Socket timeout for one hop (connect, and each read on that socket).
REQUEST_TIMEOUT_SECONDS = 10.0

#: Wall-clock budget for the whole call (initial request + all redirects).
TOTAL_TIMEOUT_SECONDS = 30.0

#: A URL longer than this is refused before parsing: no legitimate page link is
#: 8 KiB, and the limit keeps error messages bounded.
MAX_URL_LENGTH = 8_192

#: Sent on every request. No cookie jar, no auth handler, no netrc: this module
#: never carries a credential it was not handed, and it is not handed any.
USER_AGENT = "vade-web/1.0"

#: The only two schemes. Everything else is `PERMISSION_DENIED`.
ALLOWED_SCHEMES = ("http", "https")

#: Statuses we follow. 300/304/305/306 are not redirects for our purposes.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: One plaintext frame of the v1 transport is 65519 bytes and v1 has no
#: fragmentation. `web_fetch` may locally return up to `MAX_BYTES_CEILING`, but
#: a result bigger than a frame cannot be sent to core — see README "Frame
#: ceiling". Kept as a documented constant so the limitation is visible to
#: readers instead of being discovered in production.
FRAME_PLAINTEXT_BYTES = 65_519

_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    # text/* is what we will decode; application/json is the one structured
    # type the contract allows. Anything else is refused after the headers.
    "Accept": "text/*, application/json;q=0.9",
    # No transparent compression: we do not decode gzip, so do not invite it.
    "Accept-Encoding": "identity",
    "Connection": "close",
}

_CHUNK_BYTES = 65_536


class ToolFailure(Exception):
    """A structured failure raised by a pure tool.

    Deliberately NOT `vade_sdk.ToolError`: importing the SDK here would break
    the "write and test tools before the SDK" rule. `server.py` translates this
    into a ToolError with the same C-04 code, so nothing is lost.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def tool(
    name: str,
    description: str,
    *,
    risk: str = "low",
    timeout_ms: int = 30_000,
    idempotent: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Attach manifest metadata to a function (no SDK, no validation logic)."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn.tool_meta = {  # type: ignore[attr-defined]
            "name": name,
            "description": description,
            "risk": risk,
            "timeout_ms": timeout_ms,
            "idempotent": idempotent,
        }
        return fn

    return decorate


# --------------------------------------------------------------------- arguments


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ToolFailure("INVALID_ARGUMENT", f"{field} must be a string, got {type(value).__name__}")
    return value


def _require_int(value: Any, field: str) -> int:
    # bool is an int subclass; `max_bytes=True` must not become 1 byte.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolFailure("INVALID_ARGUMENT", f"{field} must be an integer, got {type(value).__name__}")
    return value


# ------------------------------------------------------------------ address policy

#: Networks that are non-public *even when `ipaddress.is_global` disagrees*.
#: Kept literal and documented so the policy can be read, not inferred.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        # IPv4
        "0.0.0.0/8",          # "this network"
        "10.0.0.0/8",         # RFC 1918
        "100.64.0.0/10",      # carrier-grade NAT (is_global says True for some)
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local, cloud metadata
        "172.16.0.0/12",      # RFC 1918
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.88.99.0/24",     # 6to4 relay anycast
        "192.168.0.0/16",     # RFC 1918
        "198.18.0.0/15",      # benchmark
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast (is_global is True!)
        "240.0.0.0/4",        # reserved + broadcast
        # IPv6
        "::/128",             # unspecified
        "::1/128",            # loopback
        "64:ff9b::/96",       # NAT64 — a whole prefix that only wraps IPv4
        "100::/64",           # discard-only
        "2001:db8::/32",      # documentation
        "2002::/16",          # 6to4 — embeds IPv4, deprecated
        "fc00::/7",           # unique local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    )
)

#: IPv6 wrappers that carry an IPv4 address in their low 32 bits. The prefixes
#: above deny the translation ranges outright; unwrapping is the second line,
#: and it is what catches `::ffff:127.0.0.1` — an IPv4 address that merely
#: *looks* like IPv6, and which `is_global` alone would wave through.
_IPV4_WRAPPERS = (
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("2002::/16"),
)


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    for wrapper in _IPV4_WRAPPERS:
        if address in wrapper:
            return ipaddress.IPv4Address(int(address) & 0xFFFF_FFFF)
    return None


def address_is_blocked(address: Any) -> bool:
    """True when `address` must not be connected to.

    Fail-closed, in this order: the explicit deny list; then, for an IPv6 form
    that wraps an IPv4 address, the judgement on that IPv4; then `is_global`.
    A new reserved range therefore starts blocked, not allowed.
    """
    if any(address.version == network.version and address in network for network in _BLOCKED_NETWORKS):
        return True
    if address.version == 6:
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            return address_is_blocked(embedded)
    return not address.is_global


# ------------------------------------------------------------------------ urls


@dataclass(frozen=True)
class _Target:
    """A URL that has passed every check, plus the addresses to connect to.

    `addresses` is every answer that passed the policy, in resolver order; the
    transport tries them in turn inside one hop budget. `address` is the first
    of them, kept for readers that only want "where does this go".
    """

    url: str
    scheme: str
    host: str
    port: int
    address: str
    addresses: tuple[str, ...]


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _quote(text: str, extra: str = "") -> str:
    # `%` stays safe so an already-encoded path is not double-encoded.
    return urllib.parse.quote(text, safe="/%:@!$&'()*+,;=-._~" + extra)


def _resolve(host: str, port: int) -> tuple[str, ...]:
    """Resolve `host` and prove every answer is public; return the pinned list.

    Every address in the answer is checked, not just the first: a name that
    resolves to one public and one private address is a rebinding attempt or a
    misconfiguration, and both deserve `PERMISSION_DENIED`.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # No host name in the message: the caller already knows what it asked
        # for, and resolution failures for internal names are not our business.
        raise ToolFailure("UNAVAILABLE", "could not resolve the host name") from None
    except (TimeoutError, OSError):
        raise ToolFailure("UNAVAILABLE", "could not resolve the host name") from None

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        raw = sockaddr[0]
        # A zone id (`fe80::1%eth0`) is not part of the address.
        literal = raw.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            # A name that resolves to something we cannot even parse is not
            # something we will connect to.
            raise ToolFailure("PERMISSION_DENIED", "host resolved to an address that is not usable") from None
        if address_is_blocked(address):
            # The address itself is never echoed: it is exactly the internal
            # topology a probing model is looking for.
            raise ToolFailure("PERMISSION_DENIED", "refusing to connect to a non-public address")
        addresses.append(literal)

    if not addresses:
        raise ToolFailure("UNAVAILABLE", "could not resolve the host name")
    return tuple(dict.fromkeys(addresses))  # de-duplicate, keep resolver order


def _parse_url(url: Any) -> tuple[str, str, int, str, str]:
    """Parse and sanity-check one URL. Returns (scheme, host, port, path, query).

    No DNS here and no I/O: this is the pure half, which is why the scheme and
    shape rules can be unit-tested without a socket.
    """
    text = _require_str(url, "url")
    if not text:
        raise ToolFailure("INVALID_ARGUMENT", "url must not be empty")
    if len(text) > MAX_URL_LENGTH:
        raise ToolFailure("INVALID_ARGUMENT", f"url must be at most {MAX_URL_LENGTH} characters")
    for character in text:
        if character <= " " or character == "\x7f":
            # A raw space or CR/LF either fails inside http.client with a
            # confusing error or, worse, becomes a header split.
            raise ToolFailure("INVALID_ARGUMENT", "url must not contain whitespace or control characters")

    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        raise ToolFailure("INVALID_ARGUMENT", "url cannot be parsed") from None

    scheme = parts.scheme.lower()
    if not scheme:
        raise ToolFailure("INVALID_ARGUMENT", "url must be absolute and start with http:// or https://")
    if scheme not in ALLOWED_SCHEMES:
        raise ToolFailure(
            "PERMISSION_DENIED",
            f"scheme {scheme!r} is not allowed; only http and https are supported",
        )
    if not parts.netloc:
        raise ToolFailure("INVALID_ARGUMENT", "url has no host")
    if "@" in parts.netloc:
        # user:password@host and the empty-user form both end up here: this
        # module never sends a credential, so a URL carrying one is a mistake.
        raise ToolFailure("INVALID_ARGUMENT", "url must not contain credentials")

    host = parts.hostname or ""
    if not host:
        raise ToolFailure("INVALID_ARGUMENT", "url has no host")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ToolFailure("INVALID_ARGUMENT", "host name is not valid IDNA") from None

    try:
        port = parts.port
    except ValueError:
        raise ToolFailure("INVALID_ARGUMENT", "url has an invalid port") from None
    if port is None:
        port = _default_port(scheme)
    elif not 1 <= port <= 65_535:
        raise ToolFailure("INVALID_ARGUMENT", "url port must be within [1, 65535]")

    path = _quote(parts.path or "/")
    query = _quote(parts.query, extra="?")
    return scheme, host, port, path, query


def validate_url(url: Any) -> _Target:
    """Full validation: shape, scheme, resolution, address policy, pinning.

    Called once for the first request and again for **every** redirect target.
    """
    scheme, host, port, path, query = _parse_url(url)
    addresses = _resolve(host, port)
    netloc = host if port == _default_port(scheme) else f"{host}:{port}"
    normalized = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    return _Target(
        url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        address=addresses[0],
        addresses=addresses,
    )


# ------------------------------------------------------------------- transport


def _open_connection(address: str, port: int, timeout: float) -> socket.socket:
    """The one place a socket to the outside is created (tests patch this).

    `address` is always the literal that `validate_url` approved, never a name.
    """
    return socket.create_connection((address, port), timeout)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials the validated literal instead of the name."""

    def __init__(self, host: str, pinned_address: str, **kwargs: Any) -> None:
        self._pinned_address = pinned_address
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = _open_connection(self._pinned_address, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection with the same pin — TLS still verifies against the name.

    `server_hostname` is `self.host`, so SNI and certificate matching use the
    URL's host name while the TCP connection goes to the checked IP. Pinning
    without that split would verify the certificate of an IP address.
    """

    def __init__(self, host: str, pinned_address: str, **kwargs: Any) -> None:
        self._pinned_address = pinned_address
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        sock = _open_connection(self._pinned_address, self.port, self.timeout)
        if self._tunnel_host:
            # A CONNECT tunnel hands name resolution to the proxy, which voids
            # the pinning. Proxies are disabled anyway; this is the belt.
            sock.close()
            raise OSError("proxy tunnels are not supported")
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, address: str) -> None:
        super().__init__()
        self._address = address

    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(functools.partial(_PinnedHTTPConnection, pinned_address=self._address), req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, address: str) -> None:
        super().__init__()
        self._address = address

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(
            functools.partial(_PinnedHTTPSConnection, pinned_address=self._address),
            req,
            context=self._context,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn urllib's automatic redirects off.

    Returning None makes `http_error_30x` fall through to `http_error_default`,
    which raises `HTTPError` — a 3xx becomes an ordinary response the caller can
    inspect, and following it is our decision, not urllib's.
    """

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        return None


def _build_opener(address: str) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        # No proxy: a proxy resolves the name itself, which is the one thing
        # this module refuses to delegate.
        urllib.request.ProxyHandler({}),
        _PinnedHTTPHandler(address),
        _PinnedHTTPSHandler(address),
        _NoRedirectHandler(),
    )


def _status_of(response: Any) -> int:
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(response, "code", 0)
    try:
        return int(status or 0)
    except (TypeError, ValueError):
        return 0


def _unavailable(reason: Any, timeout: float | None = None) -> ToolFailure:
    """Map a transport failure to UNAVAILABLE without echoing the address.

    `reason` may be an exception or a bare string from `URLError`. Only the
    class name is used for the unknown cases: `str(exc)` of a socket error is
    usually harmless, but it is not *guaranteed* to be, and the message is the
    one place an internal address could leak.
    """
    if isinstance(reason, (TimeoutError, socket.timeout)):
        seconds = REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
        return ToolFailure("UNAVAILABLE", f"request timed out after {seconds:g}s")
    if isinstance(reason, socket.gaierror):
        return ToolFailure("UNAVAILABLE", "could not resolve the host name")
    return ToolFailure("UNAVAILABLE", f"request failed ({type(reason).__name__})")


#: errno values that mean "this address did not answer", i.e. worth trying the
#: next validated address for the same name. A TLS or protocol error is not in
#: this set: the next address would fail the same way.
_RETRYABLE_ERRNOS = frozenset(
    {
        errno.ECONNREFUSED,
        errno.ETIMEDOUT,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.EADDRNOTAVAIL,
    }
)


def _retryable(reason: Any) -> bool:
    if isinstance(reason, (ConnectionRefusedError, TimeoutError, socket.timeout, socket.gaierror)):
        return True
    return isinstance(reason, OSError) and reason.errno in _RETRYABLE_ERRNOS


def _open_response(target: _Target, *, method: str, timeout: float) -> Any:
    """One request, no redirect handling. The returned object must be closed.

    The addresses validated for this host are tried in turn, sharing the hop's
    budget: a host whose first answer is an unreachable family (a common case
    with IPv6-only AAAA records behind an IPv4-only network) must not fail the
    fetch when a working answer was in the same DNS response. Every address
    tried here has already passed the policy, so the fallback cannot widen it.
    """
    request = urllib.request.Request(target.url, headers=dict(_REQUEST_HEADERS), method=method)
    remaining = list(target.addresses)
    budget = timeout
    last_reason: Any = None

    while remaining:
        address = remaining[0]
        share = max(0.25, budget / len(remaining))
        started = time.monotonic()
        try:
            return _build_opener(address).open(request, timeout=share)
        except urllib.error.HTTPError as exc:
            # 3xx/4xx/5xx are answers, not transport failures: the status and
            # body are the tool's result (`HTTPError` is a readable response).
            return exc
        except urllib.error.URLError as exc:
            last_reason = exc.reason
        except (TimeoutError, OSError) as exc:
            last_reason = exc
        except http.client.HTTPException as exc:
            raise ToolFailure("UNAVAILABLE", f"invalid HTTP response ({type(exc).__name__})") from None
        except ValueError as exc:
            raise ToolFailure("INVALID_ARGUMENT", f"url cannot be requested: {exc}") from None
        finally:
            budget -= time.monotonic() - started

        remaining.pop(0)
        if remaining and not _retryable(last_reason):
            break

    raise _unavailable(last_reason, timeout) from None


def _read_body(response: Any, max_bytes: int, deadline: float) -> tuple[bytes, bool]:
    """Read at most `max_bytes + 1` bytes; stop on EOF or when the budget ends.

    The extra byte is how truncation is detected without trusting
    `Content-Length`: a server that lies about its length still cannot make us
    buffer more than the window.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= max_bytes:
            if time.monotonic() >= deadline:
                raise ToolFailure("UNAVAILABLE", f"request timed out after {TOTAL_TIMEOUT_SECONDS:g}s")
            want = min(_CHUNK_BYTES, max_bytes + 1 - total)
            chunk = response.read(want)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except ToolFailure:
        raise
    except (TimeoutError, socket.timeout) as exc:
        raise _unavailable(exc) from None
    except (OSError, http.client.HTTPException) as exc:
        raise _unavailable(exc) from None

    raw = b"".join(chunks)
    truncated = len(raw) > max_bytes
    return raw[:max_bytes], truncated


# -------------------------------------------------------------------- responses


@dataclass(frozen=True)
class _Reply:
    status: int
    headers: Message
    body: bytes
    truncated: bool
    final_url: str
    content_type: str | None


def _content_type(headers: Message) -> str | None:
    """The parsed media type, or None when the server sent no Content-Type.

    `Message.get_content_type()` defaults a *missing* header to `text/plain`,
    which would silently wave an unlabelled binary body through. The header is
    therefore inspected before asking.
    """
    header = headers.get("Content-Type")
    if header is None or not str(header).strip():
        return None
    return headers.get_content_type()


def _charset(headers: Message) -> str:
    charset = headers.get_content_charset()
    return charset or "utf-8"


def _decode(body: bytes, headers: Message) -> str:
    """Decode the window as text, never raising.

    `errors="replace"` on purpose: a page that is 99% valid UTF-8 plus one bad
    byte is a page, not an error. A window cut mid-character is the normal case
    for a truncated body, and refusing it would make truncation useless.
    """
    charset = _charset(headers)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        # An unknown charset label is the server's bug, not the caller's.
        return body.decode("utf-8", errors="replace")


def _require_text_type(headers: Message) -> None:
    content_type = _content_type(headers)
    if content_type is None:
        raise ToolFailure(
            "INVALID_ARGUMENT",
            "response has no Content-Type; refusing to decode it as text",
        )
    if content_type.startswith("text/") or content_type == "application/json":
        return
    raise ToolFailure(
        "INVALID_ARGUMENT",
        f"content type {content_type!r} is not text; only text/* and application/json are returned",
    )


def _perform(
    url: str,
    *,
    method: str,
    read_body: bool,
    max_bytes: int = 0,
    text_only: bool = False,
) -> _Reply:
    """Request `url`, following at most `MAX_REDIRECTS` re-validated hops."""
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    target = validate_url(url)
    redirects = 0

    while True:
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise ToolFailure("UNAVAILABLE", f"request timed out after {TOTAL_TIMEOUT_SECONDS:g}s")
        response = _open_response(target, method=method, timeout=min(REQUEST_TIMEOUT_SECONDS, budget))
        try:
            status = _status_of(response)
            headers = response.headers
            location = headers.get("Location")
            if status in REDIRECT_STATUSES and location:
                if redirects >= MAX_REDIRECTS:
                    raise ToolFailure(
                        "INVALID_ARGUMENT",
                        f"more than {MAX_REDIRECTS} redirects; refusing to follow further",
                    )
                redirects += 1
                # The whole point of the module: the *next* hop gets the same
                # scheme/host/address checks as the first one.
                target = validate_url(urllib.parse.urljoin(target.url, str(location).strip()))
                continue  # `finally` closes this response

            if text_only:
                # Refuse non-text before pulling the body: no reason to download
                # a 256 KiB image just to throw it away.
                _require_text_type(headers)

            body, truncated = (b"", False)
            if read_body:
                body, truncated = _read_body(response, max_bytes, deadline)

            return _Reply(
                status=status,
                headers=headers,
                body=body,
                truncated=truncated,
                final_url=target.url,
                content_type=_content_type(headers),
            )
        finally:
            response.close()


def _content_length(headers: Message) -> int | None:
    raw = headers.get("Content-Length")
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


# ------------------------------------------------------------------------ tools


@tool(
    "web_fetch",
    "抓取 http/https URL 的文本（仅 text/* 与 application/json）；拒绝内网地址，最多 3 次重定向，超过 max_bytes 截断",
    risk="medium",
    timeout_ms=35_000,
    idempotent=True,
)
def web_fetch(url: str, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """GET a URL's text. Returns status/content_type/text/bytes/truncated/final_url."""
    window = _require_int(max_bytes, "max_bytes")
    if window < 1 or window > MAX_BYTES_CEILING:
        raise ToolFailure("INVALID_ARGUMENT", f"max_bytes must be within [1, {MAX_BYTES_CEILING}]")

    reply = _perform(url, method="GET", read_body=True, max_bytes=window, text_only=True)
    return {
        "status": reply.status,
        "content_type": reply.content_type,
        "text": _decode(reply.body, reply.headers),
        "bytes": len(reply.body),
        "truncated": reply.truncated,
        "final_url": reply.final_url,
    }


@tool(
    "web_head",
    "获取 http/https URL 的 HEAD 响应：status/content_type/content_length；同样拒绝内网地址与超限重定向",
    timeout_ms=35_000,
    idempotent=True,
)
def web_head(url: str) -> dict[str, Any]:
    """HEAD a URL. Returns status/content_type/content_length; never a body."""
    reply = _perform(url, method="HEAD", read_body=False)
    return {
        "status": reply.status,
        "content_type": reply.content_type,
        "content_length": _content_length(reply.headers),
    }


def all_tools() -> tuple[Callable[..., Any], ...]:
    """Every decorated tool, in declaration order (manifest order is stable)."""
    return (web_fetch, web_head)
