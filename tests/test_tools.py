"""web tool tests — stdlib + pytest only, NO SDK import (module self-sufficiency).

The module's real subject is the boundary, so the tests are organised around it:

* a **fake internet** fixture: `web.test` resolves to a public address and every
  connection to that address is delivered to a local `http.server`. The happy
  path therefore runs through a real socket stack while the address policy still
  sees a public IP;
* a **blocked matrix**: loopback, RFC 1918, link-local, CGNAT, IPv4-mapped IPv6,
  NAT64, multicast, TEST-NET — asserted by code, never by "raises";
* **redirects**: every hop is re-validated, so a 302 to `http://127.0.0.1/` is
  the headline test of the module;
* **limits**: `max_bytes` truncation, the result budget, per-hop timeout, 3 hops.
"""

from __future__ import annotations

import ast
import errno
import ipaddress
import json
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from web_module import tools  # noqa: E402

#: A real, globally routable address (example.com). The fake DNS below claims
#: `web.test` lives here; `_open_connection` then delivers the socket to the
#: local server, so no packet ever leaves the machine.
PUBLIC_ADDRESS = "93.184.216.34"


# --------------------------------------------------------------------- test server


class _RecordingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def handle_error(self, request, client_address):
        # The timeout tests hang up mid-response on purpose; a traceback per
        # abandoned socket would drown the real output.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    server_version = "vade-test/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep pytest output clean
        return

    def do_GET(self):  # noqa: N802 (http.server API)
        self._handle(body=True)

    def do_HEAD(self):  # noqa: N802 (http.server API)
        self._handle(body=False)

    def _handle(self, *, body: bool) -> None:
        path = urllib.parse.urlsplit(self.path).path
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.requests.append(  # type: ignore[attr-defined]
                {
                    "method": self.command,
                    "path": path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                }
            )

        if path == "/hello":
            self._send(200, "text/plain; charset=utf-8", "hello world", body=body)
        elif path == "/json":
            self._send(200, "application/json", '{"ok": true, "n": 1}', body=body)
        elif path == "/image":
            self._send(200, "image/png", "\x89PNG\r\n", body=body)
        elif path == "/xml":
            self._send(200, "application/xml", "<a/>", body=body)
        elif path == "/noctype":
            self._send(200, None, "unlabelled", body=body)
        elif path == "/big":
            self._send(200, "text/plain", "x" * 5000, body=body)
        elif path == "/exact":
            self._send(200, "text/plain", "y" * 64, body=body)
        elif path.startswith("/pad/"):
            # A body of exactly N ASCII bytes: the result-budget tests need to
            # sit one byte either side of the limit.
            self._send(200, "text/plain", "a" * int(path.rsplit("/", 1)[1]), body=body)
        elif path.startswith("/cjk/"):
            # Three-byte characters: a byte-wise cut would split one in half.
            self._send(200, "text/plain; charset=utf-8", "世" * int(path.rsplit("/", 1)[1]), body=body)
        elif path == "/utf8":
            self._send(200, "text/plain; charset=utf-8", "hello 世界", body=body)
        elif path == "/latin1":
            self._send_raw(200, "text/plain; charset=latin-1", "café".encode("latin-1"), body=body)
        elif path == "/badcharset":
            self._send_raw(200, "text/plain; charset=not-a-charset", b"plain ascii", body=body)
        elif path == "/nocontentlength":
            self._send(200, "text/plain", "abc", body=body, content_length=False)
        elif path == "/404":
            self._send(404, "text/plain", "not found", body=body)
        elif path == "/500":
            self._send(500, "text/plain", "boom", body=body)
        elif path == "/redirect-to-hello":
            self._redirect("/hello")
        elif path == "/redirect-to-private":
            self._redirect(f"http://127.0.0.1:{self.server.server_address[1]}/hello")  # type: ignore[attr-defined]
        elif path == "/redirect-to-file":
            self._redirect("file:///etc/passwd")
        elif path == "/redirect-to-relative":
            self._redirect("../hello")
        elif path == "/redirect-loop":
            self._redirect("/redirect-loop")
        elif path == "/redirect-nolocation":
            self._send(302, "text/plain", "where?", body=body)
        elif path.startswith("/chain/"):
            step = int(path.rsplit("/", 1)[1])
            if step <= 0:
                self._send(200, "text/plain", "chain done", body=body)
            else:
                self._redirect(f"/chain/{step - 1}")
        elif path == "/slow":
            # Nothing at all for 1.5 s: the timeout fires while waiting for the
            # status line.
            time.sleep(1.5)
            self._send(200, "text/plain", "late", body=body)
        elif path == "/slow-body":
            # Headers immediately, body trickling: the timeout must also fire
            # inside `_read_body`, not just during connect.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "10")
            self.end_headers()
            if body:
                self.wfile.write(b"01234")
                self.wfile.flush()
                time.sleep(1.5)
                self.wfile.write(b"56789")
        else:
            self._send(404, "text/plain", "no route", body=body)

    # -- response helpers ------------------------------------------------------

    def _send(
        self,
        status: int,
        content_type: str | None,
        text: str,
        *,
        body: bool,
        content_length: bool = True,
    ) -> None:
        self._send_raw(status, content_type, text.encode("utf-8"), body=body, content_length=content_length)

    def _send_raw(
        self,
        status: int,
        content_type: str | None,
        payload: bytes,
        *,
        body: bool,
        content_length: bool = True,
    ) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        if content_length:
            self.send_header("Content-Length", str(len(payload)))
        else:
            self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(payload)
            self.wfile.flush()

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="session")
def server():
    httpd = _RecordingServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def net(server, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int, float]]:
    """A fake internet: `web.test` is public, and its sockets land on `server`."""
    real_getaddrinfo = socket.getaddrinfo
    server_port = server.server_address[1]

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host in ("web.test", "public.test"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    calls: list[tuple[str, int, float]] = []

    def fake_connect(address: str, port: int, timeout: float) -> socket.socket:
        # Records what the transport was asked to dial: the pinned literal, not
        # the host name. Then hands the socket to the local server.
        calls.append((address, port, float(timeout)))
        return socket.create_connection(("127.0.0.1", server_port), timeout)

    monkeypatch.setattr(tools.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(tools, "_open_connection", fake_connect)
    server.requests.clear()  # type: ignore[attr-defined]
    return calls


def base(server, path: str) -> str:
    return f"http://web.test:{server.server_address[1]}{path}"


def _failure(code: str, fn, *args, **kwargs) -> tools.ToolFailure:
    with pytest.raises(tools.ToolFailure) as excinfo:
        fn(*args, **kwargs)
    assert excinfo.value.code == code, f"expected {code}, got {excinfo.value.code}: {excinfo.value.message}"
    return excinfo.value


def _no_dial(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    def explode(*args, **kwargs):
        raise AssertionError(message)

    monkeypatch.setattr(tools, "_open_connection", explode)


# ------------------------------------------------------------------ self-sufficiency


def test_no_sdk_import_in_tools():
    """AST check, not a substring scan: a docstring may *mention* the SDK."""
    tree = ast.parse(Path(tools.__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name == "vade_sdk" or name.startswith("vade_sdk.")]
    assert not [name for name in imported if name == "vade" or name.startswith("vade.")]


def test_only_stdlib_is_imported():
    """No `requests`, no `httpx`, no `aiohttp`: urllib and friends only."""
    tree = ast.parse(Path(tools.__file__).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".", 1)[0])
    assert roots <= set(sys.stdlib_module_names), sorted(roots - set(sys.stdlib_module_names))


def test_documented_limits():
    assert tools.DEFAULT_MAX_BYTES == 32_768
    assert tools.MAX_RESULT_BYTES == 49_152
    assert tools.MAX_BYTES_CEILING == 49_152
    assert tools.MAX_RESULT_BYTES == tools.MAX_BYTES_CEILING
    assert tools.MAX_REDIRECTS == 3
    assert tools.REQUEST_TIMEOUT_SECONDS == 10.0
    assert tools.TOTAL_TIMEOUT_SECONDS == 30.0
    assert tools.USER_AGENT == "vade-web/1.0"
    assert tools.ALLOWED_SCHEMES == ("http", "https")
    assert tools.FRAME_PLAINTEXT_BYTES == 65_519
    # The budget must leave room for the JSON-RPC envelope inside one frame.
    assert tools.DEFAULT_MAX_BYTES < tools.MAX_RESULT_BYTES < tools.FRAME_PLAINTEXT_BYTES


def test_every_tool_is_decorated_and_unique():
    names = [fn.tool_meta["name"] for fn in tools.all_tools()]
    assert names == ["web_fetch", "web_head"]
    assert len(names) == len(set(names))
    for fn in tools.all_tools():
        assert fn.__name__ == fn.tool_meta["name"]


def test_risk_and_idempotency_are_declared_per_tool():
    meta = {fn.tool_meta["name"]: fn.tool_meta for fn in tools.all_tools()}
    assert meta["web_fetch"]["risk"] == "medium"
    assert meta["web_fetch"]["idempotent"] is True
    assert meta["web_head"]["risk"] == "low"
    assert meta["web_head"]["idempotent"] is True
    # A 35 s tool timeout is deliberate: 30 s of budget plus one slow hop.
    for name in ("web_fetch", "web_head"):
        assert meta[name]["timeout_ms"] > tools.TOTAL_TIMEOUT_SECONDS * 1000


# --------------------------------------------------------------------------- schemes


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "ftp://example.com/x",
        "ftps://example.com/x",
        "data:text/plain,hello",
        "gopher://example.com/",
        "javascript:alert(1)",
        "ws://example.com/socket",
        "wss://example.com/socket",
        "dict://example.com:11211/",
        "http+unix://%2Fvar%2Frun%2Fsocket/x",
    ],
)
def test_non_http_schemes_are_denied_before_any_socket(url: str, monkeypatch: pytest.MonkeyPatch, server):
    _no_dial(monkeypatch, "no connection may be attempted for a refused scheme")
    failure = _failure("PERMISSION_DENIED", tools.web_fetch, url)
    assert "not allowed" in failure.message
    _failure("PERMISSION_DENIED", tools.web_head, url)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "example.com/x",
        "//example.com/x",
        "http://",
        "http:///path",
        "http://example.com:notaport/",
        "http://example.com:0/",
        "http://example.com:70000/",
        "http://user:hunter2@example.com/",
        "http://@example.com/",
        "http://exa mple.com/",
        "http://example.com/a\nb",
        "http://example.com/" + "a" * 9000,
    ],
)
def test_malformed_urls_are_invalid_arguments(url: str, monkeypatch: pytest.MonkeyPatch, server):
    _no_dial(monkeypatch, "no connection may be attempted for an invalid URL")
    _failure("INVALID_ARGUMENT", tools.web_fetch, url)
    _failure("INVALID_ARGUMENT", tools.web_head, url)


def test_url_must_be_a_string(server):
    _failure("INVALID_ARGUMENT", tools.web_fetch, 123)
    _failure("INVALID_ARGUMENT", tools.web_fetch, None)
    _failure("INVALID_ARGUMENT", tools.web_head, ["http://example.com/"])


def test_scheme_is_case_insensitive(server, net):
    result = tools.web_fetch(f"HTTP://web.test:{server.server_address[1]}/hello")
    assert result["status"] == 200
    assert result["text"] == "hello world"


# ------------------------------------------------------------------------------ ssrf


@pytest.mark.parametrize(
    "url",
    [
        # IPv4 loopback / private / link-local / CGNAT / reserved
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/",
        "http://0.0.0.0/",
        "http://10.0.0.1/",
        "http://10.255.255.254/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.0.1/",
        "http://192.168.255.255/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://100.64.0.1/",
        "http://192.0.2.1/",
        "http://198.18.0.1/",
        "http://255.255.255.255/",
        "http://224.0.0.1/",
        # IPv6 loopback / unspecified / link-local / unique-local / mapped
        "http://[::1]/",
        "http://[::]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[fd00:ec2::254]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:10.0.0.1]/",
        # NAT64 wrapping 127.0.0.1 — `is_global` says True, the policy must not
        "http://[64:ff9b::7f00:1]/",
        # documentation / multicast
        "http://[2001:db8::1]/",
        "http://[ff02::1]/",
    ],
)
def test_non_public_literal_addresses_are_denied(url: str, monkeypatch: pytest.MonkeyPatch, server):
    _no_dial(monkeypatch, "a blocked address must not reach the socket layer")
    failure = _failure("PERMISSION_DENIED", tools.web_fetch, url)
    # The address is the one thing a probing caller must not learn back.
    literal = (urllib.parse.urlsplit(url).hostname or "").strip("[]")
    assert literal not in failure.message
    _failure("PERMISSION_DENIED", tools.web_head, url)


def test_public_literal_is_accepted_and_pinned(server):
    target = tools.validate_url(f"http://{PUBLIC_ADDRESS}:8080/path?q=1")
    assert target.address == PUBLIC_ADDRESS
    assert target.host == PUBLIC_ADDRESS
    assert target.port == 8080
    assert target.url == f"http://{PUBLIC_ADDRESS}:8080/path?q=1"


def test_ipv4_mapped_public_address_is_judged_as_its_ipv4(server):
    """`::ffff:93.184.216.34` is a public IPv4 wearing an IPv6 hat."""
    assert tools.address_is_blocked(ipaddress.ip_address("::ffff:93.184.216.34")) is False
    assert tools.address_is_blocked(ipaddress.ip_address("::ffff:10.0.0.1")) is True


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",   # NAT64 → 127.0.0.1
        "2002:7f00:0001::",  # 6to4 → 127.0.0.1
        "2002:5db8:d822::",  # 6to4 wrapping a public IPv4: still refused
        "224.0.0.1",         # multicast, is_global is True
        "ff02::1",           # multicast, is_global is True
        "100.64.0.1",        # CGNAT
        "93.184.216.34",     # control: must be allowed
    ],
)
def test_address_policy_is_explicit(address: str):
    blocked = tools.address_is_blocked(ipaddress.ip_address(address))
    assert blocked is (address != "93.184.216.34")


def test_dns_answer_is_checked_against_the_policy(monkeypatch: pytest.MonkeyPatch, server):
    real_getaddrinfo = socket.getaddrinfo

    def private_dns(host, port, *args, **kwargs):
        if host == "evil.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(tools.socket, "getaddrinfo", private_dns)
    _no_dial(monkeypatch, "a name resolving to a private address must not be dialled")

    failure = _failure("PERMISSION_DENIED", tools.web_fetch, "http://evil.test/")
    assert "10.1.2.3" not in failure.message
    assert "evil.test" not in failure.message


def test_one_private_answer_poisons_the_whole_name(monkeypatch: pytest.MonkeyPatch, server):
    """A split answer (public + private) is a rebinding shape: refuse it."""
    real_getaddrinfo = socket.getaddrinfo

    def split_dns(host, port, *args, **kwargs):
        if host == "split.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", port)),
            ]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(tools.socket, "getaddrinfo", split_dns)
    _no_dial(monkeypatch, "a split DNS answer must not be dialled")
    _failure("PERMISSION_DENIED", tools.web_fetch, "http://split.test/")


def test_dns_failure_is_unavailable(monkeypatch: pytest.MonkeyPatch, server):
    real_getaddrinfo = socket.getaddrinfo

    def broken_dns(host, port, *args, **kwargs):
        if host == "nxdomain.test":
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(tools.socket, "getaddrinfo", broken_dns)
    failure = _failure("UNAVAILABLE", tools.web_fetch, "http://nxdomain.test/")
    assert "nxdomain" not in failure.message


def test_loopback_name_is_denied(monkeypatch: pytest.MonkeyPatch, server):
    """`localhost` is refused by resolution, not by a name blocklist."""
    _no_dial(monkeypatch, "loopback must not be dialled")
    _failure("PERMISSION_DENIED", tools.web_fetch, "http://localhost:8080/")


def test_connection_is_pinned_to_the_validated_address(server, net):
    """The socket is dialled with the IP, never the name: rebinding has no window."""
    result = tools.web_fetch(base(server, "/hello"))
    assert result["status"] == 200
    assert net, "the transport was not exercised"
    assert {call[0] for call in net} == {PUBLIC_ADDRESS}
    assert all(call[2] <= tools.REQUEST_TIMEOUT_SECONDS for call in net)


def test_connection_failure_is_unavailable(server, net, monkeypatch: pytest.MonkeyPatch):
    def refuse(address: str, port: int, timeout: float):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(tools, "_open_connection", refuse)
    failure = _failure("UNAVAILABLE", tools.web_fetch, base(server, "/hello"))
    assert PUBLIC_ADDRESS not in failure.message
    assert "Connection refused" not in failure.message


def test_a_dead_address_falls_through_to_the_next(server, net, monkeypatch: pytest.MonkeyPatch):
    """Two public answers, the first refuses: the second must still be used."""
    real_getaddrinfo = socket.getaddrinfo
    second = "93.184.216.35"
    attempts: list[str] = []

    def two_answers(host, port, *args, **kwargs):
        if host == "web.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (second, port)),
            ]
        return real_getaddrinfo(host, port, *args, **kwargs)

    real_connect = tools._open_connection

    def flaky(address: str, port: int, timeout: float) -> socket.socket:
        attempts.append(address)
        if address == PUBLIC_ADDRESS:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
        return real_connect(address, port, timeout)

    monkeypatch.setattr(tools.socket, "getaddrinfo", two_answers)
    monkeypatch.setattr(tools, "_open_connection", flaky)

    result = tools.web_fetch(base(server, "/hello"))
    assert result["text"] == "hello world"
    assert attempts == [PUBLIC_ADDRESS, second]


def test_a_non_network_failure_does_not_retry_the_next_address(server, net, monkeypatch: pytest.MonkeyPatch):
    """A TLS handshake failure is not address-specific: do not spray attempts."""
    real_getaddrinfo = socket.getaddrinfo
    attempts: list[str] = []

    def two_answers(host, port, *args, **kwargs):
        if host == "web.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", port)),
            ]
        return real_getaddrinfo(host, port, *args, **kwargs)

    def tls_failure(address: str, port: int, timeout: float) -> socket.socket:
        attempts.append(address)
        raise OSError(errno.EPROTO, "bad handshake")

    monkeypatch.setattr(tools.socket, "getaddrinfo", two_answers)
    monkeypatch.setattr(tools, "_open_connection", tls_failure)

    _failure("UNAVAILABLE", tools.web_fetch, base(server, "/hello"))
    assert attempts == [PUBLIC_ADDRESS]


# -------------------------------------------------------------------------- headers


def test_request_headers_carry_no_identity(server, net):
    tools.web_fetch(base(server, "/hello"))
    recorded = server.requests[-1]["headers"]  # type: ignore[index]
    assert recorded["user-agent"] == "vade-web/1.0"
    assert recorded["accept-encoding"] == "identity"
    assert "cookie" not in recorded
    assert "authorization" not in recorded
    assert "referer" not in recorded


def test_head_does_not_download_a_body(server, net):
    result = tools.web_head(base(server, "/big"))
    assert result == {"status": 200, "content_type": "text/plain", "content_length": 5000}
    assert server.requests[-1]["method"] == "HEAD"  # type: ignore[index]


def test_head_reports_a_missing_content_length_as_none(server, net):
    result = tools.web_head(base(server, "/nocontentlength"))
    assert result["content_length"] is None
    assert result["content_type"] == "text/plain"


def test_head_does_not_gate_on_content_type(server, net):
    """HEAD describes; only a downloaded body has to be text."""
    assert tools.web_head(base(server, "/image"))["content_type"] == "image/png"


def test_error_statuses_are_returned_instead_of_raising(server, net):
    assert tools.web_head(base(server, "/404"))["status"] == 404
    assert tools.web_fetch(base(server, "/404"))["status"] == 404


# ---------------------------------------------------------------------- content type


def test_text_and_json_are_returned(server, net):
    text = tools.web_fetch(base(server, "/hello"))
    assert text["content_type"] == "text/plain"
    assert text["text"] == "hello world"
    assert text["bytes"] == len("hello world")

    payload = tools.web_fetch(base(server, "/json"))
    assert payload["content_type"] == "application/json"
    assert json.loads(payload["text"]) == {"ok": True, "n": 1}


@pytest.mark.parametrize("path", ["/image", "/xml"])
def test_non_text_content_types_are_refused(path: str, server, net):
    failure = _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, path))
    assert "not text" in failure.message


def test_missing_content_type_is_refused(server, net):
    failure = _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, "/noctype"))
    assert "Content-Type" in failure.message


def test_declared_charset_is_used(server, net):
    assert tools.web_fetch(base(server, "/latin1"))["text"] == "café"
    assert tools.web_fetch(base(server, "/utf8"))["text"] == "hello 世界"


def test_unknown_charset_falls_back_to_utf8(server, net):
    assert tools.web_fetch(base(server, "/badcharset"))["text"] == "plain ascii"


def test_error_status_body_is_still_returned(server, net):
    result = tools.web_fetch(base(server, "/500"))
    assert result["status"] == 500
    assert result["text"] == "boom"


# ---------------------------------------------------------------------------- limits


def test_max_bytes_truncates_and_says_so(server, net):
    result = tools.web_fetch(base(server, "/big"), max_bytes=100)
    assert result["truncated"] is True
    assert result["bytes"] == 100
    assert len(result["text"]) == 100
    assert result["status"] == 200


def test_max_bytes_exact_fit_is_not_truncated(server, net):
    result = tools.web_fetch(base(server, "/exact"), max_bytes=64)
    assert result["truncated"] is False
    assert result["bytes"] == 64


def test_default_window_covers_a_small_page(server, net):
    result = tools.web_fetch(base(server, "/big"))
    assert result["bytes"] == 5000
    assert result["truncated"] is False


def test_max_bytes_must_be_within_the_ceiling(server, net):
    for bad in (0, -1, tools.MAX_BYTES_CEILING + 1, True, "100", 1.5, None):
        _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, "/hello"), max_bytes=bad)
    assert server.requests == []  # type: ignore[comparison-overlap]


def test_max_bytes_ceiling_is_enforced_against_the_constant(server, net, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(tools, "MAX_BYTES_CEILING", 8)
    _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, "/hello"), max_bytes=9)
    assert tools.web_fetch(base(server, "/hello"), max_bytes=8)["bytes"] == 8


# ------------------------------------------------------------------ result budget


def _result_bytes(result) -> int:
    """Independent measurement: the whole result, metadata included, as UTF-8 JSON."""
    return len(json.dumps(result, ensure_ascii=False).encode("utf-8"))


def _pad_result_size(server, text_len: int) -> int:
    """What `web_fetch` would serialise for `/pad/<text_len>` if left untouched."""
    return _result_bytes(
        {
            "status": 200,
            "content_type": "text/plain",
            "text": "a" * text_len,
            "bytes": text_len,
            "truncated": False,
            "final_url": base(server, f"/pad/{text_len}"),
        }
    )


def _largest_pad_that_fits(server) -> int:
    """The N whose untouched result is exactly `MAX_RESULT_BYTES` long."""
    size = tools.MAX_RESULT_BYTES
    for _ in range(8):
        size = tools.MAX_RESULT_BYTES - (_pad_result_size(server, size) - size)
    assert _pad_result_size(server, size) == tools.MAX_RESULT_BYTES
    return size


def test_result_exactly_at_the_budget_is_not_truncated(server, net):
    size = _largest_pad_that_fits(server)
    result = tools.web_fetch(base(server, f"/pad/{size}"), max_bytes=size)
    assert _result_bytes(result) == tools.MAX_RESULT_BYTES
    assert result["truncated"] is False
    assert result["bytes"] == size
    assert len(result["text"]) == size


def test_result_one_byte_over_the_budget_is_cut_and_flagged(server, net):
    size = _largest_pad_that_fits(server) + 2
    result = tools.web_fetch(base(server, f"/pad/{size}"), max_bytes=size)
    assert _result_bytes(result) <= tools.MAX_RESULT_BYTES
    assert result["truncated"] is True
    # `bytes` still reports the body window; only `text` was shortened.
    assert result["bytes"] == size
    assert len(result["text"]) < size
    assert result["text"] == "a" * len(result["text"])
    # Maximal, not merely small: one more character would break the budget.
    assert _result_bytes({**result, "text": result["text"] + "a"}) > tools.MAX_RESULT_BYTES


def test_budget_that_only_the_flag_itself_exceeds_cuts_a_character(server, net):
    """One byte over is the awkward case: `false` → `true` alone would fit.

    The flag must not be raised over text that is still complete, so a character
    is dropped and the claim stays true.
    """
    size = _largest_pad_that_fits(server) + 1
    result = tools.web_fetch(base(server, f"/pad/{size}"), max_bytes=size)
    assert _result_bytes(result) <= tools.MAX_RESULT_BYTES
    assert result["truncated"] is True
    assert len(result["text"]) == size - 1
    assert result["text"] == "a" * len(result["text"])


def test_default_window_result_fits_one_frame(server, net):
    result = tools.web_fetch(base(server, "/pad/200000"))
    assert result["bytes"] == tools.DEFAULT_MAX_BYTES
    assert result["truncated"] is True
    assert len(result["text"]) == tools.DEFAULT_MAX_BYTES
    assert _result_bytes(result) <= tools.MAX_RESULT_BYTES
    assert _result_bytes(result) < tools.FRAME_PLAINTEXT_BYTES


def test_ceiling_sized_body_still_yields_a_sendable_result(server, net):
    """The widest allowed body plus its metadata no longer fits, so text is cut."""
    result = tools.web_fetch(base(server, "/pad/200000"), max_bytes=tools.MAX_BYTES_CEILING)
    assert result["bytes"] == tools.MAX_BYTES_CEILING
    assert result["truncated"] is True
    assert _result_bytes(result) <= tools.MAX_RESULT_BYTES
    assert _result_bytes(result) < tools.FRAME_PLAINTEXT_BYTES
    assert len(result["text"]) < result["bytes"]


def test_result_budget_never_splits_a_utf8_character(server, net, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(tools, "MAX_RESULT_BYTES", 600)
    result = tools.web_fetch(base(server, "/cjk/500"), max_bytes=1500)
    assert result["truncated"] is True
    assert _result_bytes(result) <= 600
    # A byte-wise cut would leave U+FFFD at the edge; a character-wise one cannot.
    assert result["text"] == "世" * len(result["text"])
    assert "\ufffd" not in result["text"]


def test_read_timeout_is_unavailable(server, net, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(tools, "REQUEST_TIMEOUT_SECONDS", 0.2)
    failure = _failure("UNAVAILABLE", tools.web_fetch, base(server, "/slow"))
    assert "timed out" in failure.message


def test_body_read_timeout_is_unavailable(server, net, monkeypatch: pytest.MonkeyPatch):
    """Headers on time, body late: the socket timeout must still fire."""
    monkeypatch.setattr(tools, "REQUEST_TIMEOUT_SECONDS", 0.2)
    failure = _failure("UNAVAILABLE", tools.web_fetch, base(server, "/slow-body"))
    assert "timed out" in failure.message


# ------------------------------------------------------------------------- redirects


def test_relative_redirect_is_followed(server, net):
    result = tools.web_fetch(base(server, "/redirect-to-hello"))
    assert result["status"] == 200
    assert result["text"] == "hello world"
    assert result["final_url"] == base(server, "/hello")


def test_redirect_is_revalidated_and_a_private_target_is_denied(server, net):
    """The headline case: hop 1 is public, hop 2 is `http://127.0.0.1/`."""
    failure = _failure("PERMISSION_DENIED", tools.web_fetch, base(server, "/redirect-to-private"))
    assert "127.0.0.1" not in failure.message
    # Only the first hop was ever dialled: the redirect never became a request.
    assert len(net) == 1


def test_redirect_to_file_scheme_is_denied(server, net):
    _failure("PERMISSION_DENIED", tools.web_fetch, base(server, "/redirect-to-file"))
    assert len(net) == 1


def test_relative_redirect_escape_stays_on_the_origin(server, net):
    result = tools.web_fetch(base(server, "/redirect-to-relative"))
    assert result["status"] == 200
    assert result["final_url"] == base(server, "/hello")


def test_three_redirects_are_allowed_and_four_are_not(server, net):
    ok = tools.web_fetch(base(server, "/chain/3"))
    assert ok["status"] == 200
    assert ok["text"] == "chain done"

    failure = _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, "/chain/4"))
    assert "redirect" in failure.message


def test_redirect_loop_is_stopped(server, net):
    _failure("INVALID_ARGUMENT", tools.web_fetch, base(server, "/redirect-loop"))
    assert tools.MAX_REDIRECTS == 3
    assert len(net) == tools.MAX_REDIRECTS + 1


def test_redirect_without_location_is_returned_as_is(server, net):
    result = tools.web_fetch(base(server, "/redirect-nolocation"))
    assert result["status"] == 302
    assert result["text"] == "where?"


def test_head_follows_redirects_and_revalidates_them(server, net):
    assert tools.web_head(base(server, "/redirect-to-hello"))["status"] == 200
    _failure("PERMISSION_DENIED", tools.web_head, base(server, "/redirect-to-private"))


# --------------------------------------------------------------------------- errors


def test_error_messages_never_echo_a_private_address(server, net):
    failures = [
        _failure("PERMISSION_DENIED", tools.web_fetch, "http://169.254.169.254/"),
        _failure("PERMISSION_DENIED", tools.web_fetch, "http://[::1]/"),
        _failure("PERMISSION_DENIED", tools.web_fetch, base(server, "/redirect-to-private")),
    ]
    for failure in failures:
        for secret in ("169.254.169.254", "::1", "127.0.0.1"):
            assert secret not in failure.message


def test_tool_failure_carries_a_code_and_a_message(server):
    failure = _failure("PERMISSION_DENIED", tools.web_head, "file:///etc/passwd")
    assert str(failure).startswith("PERMISSION_DENIED: ")


def test_fragment_is_stripped_from_the_final_url(server, net):
    result = tools.web_fetch(base(server, "/hello") + "#section")
    assert "#" not in result["final_url"]


def test_query_string_reaches_the_server(server, net):
    tools.web_fetch(base(server, "/hello?a=1&b=two"))
    assert server.requests[-1]["path"] == "/hello"  # type: ignore[index]
