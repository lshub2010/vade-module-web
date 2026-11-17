# web module

两个工具：`web_fetch`（GET 正文）与 `web_head`（HEAD 元数据）。模块的价值不在
"能发 HTTP 请求"，而在**这条请求永远打不到本机/内网**：协议白名单、每次解析后的
地址校验、每次重定向后的重新校验、以及把套接字钉死在已校验的字面 IP 上。

只用 stdlib：`urllib.request` + `http.client` + `socket` + `ipaddress`。没有
`requests`、没有 `httpx`、没有全局 opener 状态。

## 工具

| 工具 | 签名 | 结果 | risk | idempotent |
|---|---|---|---|---|
| `web_fetch` | `web_fetch(url: str, max_bytes: int = 32768)` | `{status, content_type, text, bytes, truncated, final_url}` | **medium** | true |
| `web_head` | `web_head(url: str)` | `{status, content_type, content_length}` | low | true |

**名字为什么是下划线**：SDK 的 `ToolSpec` 只接受 `^[a-z][a-z0-9_]{0,63}$`，`.` 不合法，
所以讨论里可以叫 `web.fetch`，代码与 manifest 一律用 `web_fetch`；module_id 是
`com.example.web`，core 对模型暴露的名字是 `web__web_fetch`。

结果字段的约定：

- `status`：HTTP 状态码（int）。**4xx/5xx 不是错误**，是结果：`{"status": 404, ...}`
  比抛异常更有用，模型能看到服务器说了什么。
- `content_type`：解析后的媒体类型，不含 `charset` 参数；服务器没发这个头时为 `null`。
- `text`：正文按 `charset`（缺省 `utf-8`）解码；无法识别的 charset 回退到 utf-8；
  解码用 `errors="replace"`，一个坏字节不会让整页失败。
- `bytes`：**窗口内实际读到的正文字节数**（因 `max_bytes` 截断后），不是 `Content-Length`。
- `truncated`：`text` 是否不是完整的正文。两种原因都算：`max_bytes` 窗口截断，或
  整个结果（含 JSON 元数据）超出 `MAX_RESULT_BYTES` 后在这里又切了一刀。后一种情况下
  `text` 会比 `bytes` 短。
- `final_url`：跟完重定向后的 URL（已规范化：去掉 fragment、补全 idna、缺省端口不写）。
- `content_length`（仅 head）：`Content-Length` 头的整数值；缺失或非法 → `null`
  （服务器用 chunked 时很常见）。

## 安全模型（本模块的重点）

### 1. 协议白名单

只有 `http` 与 `https`。`file://`、`ftp://`、`data:`、`gopher://`、`ws://`、
`http+unix://` 一律 `PERMISSION_DENIED`，并且在 **urllib 看到这个字符串之前**就被拒。
这一点很重要：`urllib.request` 自带 `FileHandler` 与 `FTPHandler`，先校验后请求
才谈得上"不允许"。

### 2. SSRF：解析之后、连接之前

```
url → _parse_url()  (形状/协议/端口，无 I/O)
    → _resolve()    (getaddrinfo，逐条查地址策略)
    → _Target       (url + 已校验的字面 IP 列表)
    → 连接那个 IP   (Host/SNI/证书仍用域名)
```

`_resolve()` 对 `getaddrinfo` 返回的**每一条**地址做判断，任意一条不合规就整名拒绝
（一个名字同时返回公网与私网地址 = 重绑定或配置错误，两种都该拒）。

`address_is_blocked()` 的允许条件是 **"`is_global` 且不在拒绝表里"**，即 fail-closed。
必须自己写拒绝表，因为 `ipaddress.is_global` 在几个关键点上会骗人：

| 地址 | `is_global` | 本模块 |
|---|---|---|
| `224.0.0.1`（组播） | **True** | 拒绝（`224.0.0.0/4`） |
| `ff02::1`（组播） | **True** | 拒绝（`ff00::/8`） |
| `64:ff9b::7f00:1`（NAT64 → `127.0.0.1`） | **True** | 拒绝（整段 `64:ff9b::/96`） |
| `100.64.0.1`（CGNAT） | False | 拒绝（显式 `100.64.0.0/10`） |
| `::ffff:127.0.0.1`（IPv4-mapped） | False | 拒绝（先拆成 `127.0.0.1`） |

覆盖范围：`0.0.0.0/8`、`10/8`、`100.64/10`、`127/8`、`169.254/16`、`172.16/12`、
`192.0.0/24`、`192.0.2/24`、`192.88.99/24`、`192.168/16`、`198.18/15`、
`198.51.100/24`、`203.0.113/24`、`224/4`、`240/4`，以及 IPv6 的 `::`、`::1`、
`64:ff9b::/96`、`100::/64`、`2001:db8::/32`、`2002::/16`、`fc00::/7`、`fe80::/10`、
`ff00::/8`。

判定顺序是：**显式拒绝表 → 拆 IPv6 包装 → `is_global`**。NAT64 与 6to4 两段整体拒绝
（它们只用于把 IPv4 塞进 IPv6，对抓网页没有正当用途）；`::ffff:0:0/96` 不整段拒绝而是
拆出内嵌 IPv4 再判——`::ffff:93.184.216.34` 就是 `93.184.216.34`，允许它才是对的，
而 `::ffff:127.0.0.1` 会被判成 `127.0.0.1` 拒绝。
`test_address_policy_is_explicit` 把这几条逐项钉住（含 `2002:5db8:d822::` 这种
"6to4 包公网 IPv4 也拒绝"的用例）。

### 3. 套接字钉死在已校验的 IP 上

只做"解析后检查"仍有窗口：检查时域名答 `1.2.3.4`，连接时再解析一次可能答
`127.0.0.1`（DNS rebinding）。所以本模块**不把域名交给连接层**：

- `_PinnedHTTPConnection` / `_PinnedHTTPSConnection` 直接
  `socket.create_connection((validated_ip, port))`；
- `Host` 头、TLS SNI、证书校验仍用**域名**（`server_hostname=self.host`）——
  钉 IP 但不降级证书验证；
- **代理被显式禁用**（`ProxyHandler({})`）：代理会自己解析域名，等于把检查作废；
  `CONNECT` 隧道同样被拒（`_tunnel_host` 分支）。

同一域名有多条合规地址时会依次尝试（共享该跳预算），因为"第一条不可达"（常见于
只有 AAAA 记录的主机）不该让整次抓取失败；被尝试的每一条都已经过策略检查，
回退不会放宽边界。

### 4. 重定向：最多 3 次，每次重新校验

urllib 的自动重定向被关掉（`_NoRedirectHandler.redirect_request` 返回 `None`），
`_perform()` 自己跟：

```python
if status in REDIRECT_STATUSES and location:
    if redirects >= MAX_REDIRECTS: raise ToolFailure("INVALID_ARGUMENT", ...)
    redirects += 1
    target = validate_url(urljoin(target.url, location))   # 完整重来一遍
```

`urljoin` 之后走的是**同一个** `validate_url()`：协议白名单、DNS、地址策略、钉 IP
全部重来。`302 → http://127.0.0.1/` 与 `302 → file:///etc/passwd` 都是
`PERMISSION_DENIED`，而且**第二次请求根本没发生**（测试断言只拨号了一次）。

超过 3 次 → `INVALID_ARGUMENT`（这是 URL 的属性，重试也没用，不是 `UNAVAILABLE`）。

### 5. 大小与时间

| 上限 | 值 | 触发 |
|---|---|---|
| `max_bytes` 默认 | 32 KiB | —— |
| 一次结果总预算（`MAX_RESULT_BYTES`） | 48 KiB（49152） | `text` + JSON 元数据超过 → 按字节切 `text`，`truncated=true` |
| `max_bytes` 硬上限 | 48 KiB（`MAX_BYTES_CEILING`，与结果预算同值） | 越界 → `INVALID_ARGUMENT`（不发起请求） |
| 单跳 | 10 s（`REQUEST_TIMEOUT_SECONDS`） | 连接与每次 read 都受它约束 |
| 整次调用 | 30 s（`TOTAL_TIMEOUT_SECONDS`） | 含全部重定向 |
| 重定向 | 3 次（`MAX_REDIRECTS`） | 超出 → `INVALID_ARGUMENT` |

- 正文只读 `max_bytes + 1` 字节（多读 1 字节只为判断截断），**不信任
  `Content-Length`**：谎报长度的服务器也只能塞给我们一个窗口。
- **`max_bytes` 管正文，`MAX_RESULT_BYTES` 管结果**，两者不是一回事：JSON 转义
  （`\n`、引号、控制字符）和多字节文本都会让信封比读到的字节更长，而 transport 还得
  带上元数据。所以 `text` 解出来之后还会按预算再校一次，超了就用二分法找最长的字符前缀
  ——按字节预算切，但落点永远在字符边界上，不会切出半个 UTF-8 序列。
- 预算小于一帧（65519），差额留给 JSON-RPC 信封；`web_fetch` 的任何结果都能装进一帧。
- 读的时候按 64 KiB 分块，每块之间检查总预算，所以"慢慢挤字节"的服务器也会被 30 s 掐掉，
  而不是让一次调用挂到工具超时。
- 工具 `timeout_ms=35000`：30 s 预算 + 一跳的余量。

### 6. 内容类型

只返回 `text/*` 与 `application/json`，其余 `INVALID_ARGUMENT`——而且是在**读正文之前**
用响应头判断的：下载 32 KiB 图片再扔掉没有意义。

**没有 `Content-Type` 头也算不合法**。这里有个坑：`email.message.Message.get_content_type()`
在头缺失时会返回 `text/plain`，等价于把未标注的二进制放行；所以代码先看头在不在
（`test_missing_content_type_is_refused` 钉住这条）。

`web_head` 不做内容类型限制：HEAD 只描述，`image/png` 也是合法答案。

### 7. 不携带任何身份

- 不发 cookie（没有 cookie jar）、不带 `Authorization`、不读 `.netrc`、不读环境代理；
- URL 里带 `user:pass@` 直接 `INVALID_ARGUMENT`（本模块没有可发的凭证，带着它一定是错的）；
- `User-Agent: vade-web/1.0`，`Accept-Encoding: identity`（不解压，所以不邀请压缩）。

### 8. 错误码与信息

| 码 | 何时 |
|---|---|
| `INVALID_ARGUMENT` | URL 畸形/无 scheme/含空白或控制字符/超 8192 字符/带凭证/端口非法、`max_bytes` 越界、非文本内容类型、缺少 `Content-Type`、重定向超限 |
| `PERMISSION_DENIED` | 非 http(s) 协议、解析到非公网地址（含重定向之后） |
| `UNAVAILABLE` | DNS 失败、连接失败、TLS 失败、超时、响应不是合法 HTTP |
| `INTERNAL` | 未归类（`server.py` 只翻译 `ToolFailure`，其余异常由 SDK 兜底） |

**错误信息里不回显任何解析出来的地址**：SSRF 拒绝只说 "refusing to connect to a
non-public address"，连接失败只说异常类名（`request failed (ConnectionRefusedError)`），
DNS 失败也不带域名。唯一被回显的是调用方自己给的 scheme（"scheme 'file' is not
allowed"），那是输入而不是拓扑。

`test_error_messages_never_echo_a_private_address` 对
`169.254.169.254` / `::1` / `127.0.0.1` 做子串断言。

## 布局

```
modules/web/
├── manifest.json            generated — never hand-edited
├── pyproject.toml
├── src/web_module/
│   ├── tools.py             pure functions, stdlib only, no SDK import
│   └── server.py            ModuleApp + ToolSpec, only forwards
├── tests/test_tools.py      runs without vade-sdk installed (local http.server)
├── tests/test_server.py     skipped when vade-sdk is missing
├── .github/workflows/ci.yml pytest only, no network egress needed
├── Dockerfile               build from the REPO ROOT (needs sdk/python)
└── data/                    module key lives here (gitignored, volume it)
```

`tools.py` 不 import `vade_sdk`（AST 测试钉住），也不 import 任何第三方包
（`sys.stdlib_module_names` 白名单测试钉住）；`server.py` 不碰套接字，只做
`ToolFailure → ToolError` 的翻译。`ToolSpec` 由 SDK 从函数签名生成 JSON Schema，
签名就是 schema，默认值直接进 manifest。

## 测试怎么做到不碰真网

`tests/test_tools.py` 里的 `net` fixture 造了一个假互联网：

1. `socket.getaddrinfo("web.test", …)` → 返回**公网**地址 `93.184.216.34`
   （example.com 的 A 记录），所以地址策略看到的是"合规"；
2. `tools._open_connection(...)` → 把套接字投递到本地 `http.server` 的端口。

于是正常路径走的是真实的 `http.client` + `urllib` 栈，而**一次外网包都不发**。
这个 seam 同时证明了钉 IP：`net` 记录的是"传输层被要求拨号的地址"，测试断言它只有
`93.184.216.34`，从来不是 `web.test`。

四个变异验证过测试是有效的（把代码改坏，测试会红）：

| 变异 | 变红的测试 |
|---|---|
| 重定向只做形状检查、不做完整校验 | `test_redirect_is_revalidated_and_a_private_target_is_denied` |
| `address_is_blocked()` 恒返回 False | 38 条（SSRF 矩阵 + 泄漏断言） |
| 只检查 DNS 的第一条答案 | `test_one_private_answer_poisons_the_whole_name` |
| `_content_type()` 直接用 `get_content_type()` | `test_missing_content_type_is_refused` |

## 运行

```bash
pip install -e sdk/python          # 或 pip install "vade-sdk==0.1.*"
pip install -e modules/web

pytest modules/web/tests -q        # 126 passed（无 core；无 SDK 时 server 测试 skip）
python -m web_module --check       # exit 0，并把 manifest 打到 stdout

python -m web_module --standalone web_fetch --args '{"url":"https://example.com/","max_bytes":200}'
# {"ok": true, "result": {"status": 200, "content_type": "text/html", "text": "...", ...}}

python -m web_module --standalone web_fetch --args '{"url":"http://169.254.169.254/latest/meta-data/"}'
# {"ok": false, "error": {"code": "PERMISSION_DENIED", "message": "refusing to connect to a non-public address", ...}}   exit 1
```

`manifest.json` 由同一条生成路径产出（`--print-manifest` / `--check` / `module/register`
共用一个函数）：

```bash
PYTHONPATH=src python -m web_module --print-manifest > manifest.json
PYTHONPATH=src python -m web_module --print-manifest | diff - manifest.json   # 空
```

连 core（需要 core 白名单里有这个模块的 key，且 core 的 Noise 公钥已知）：

```bash
CORE_PUBLIC_KEY=<64 hex> MODULE_KEY_PATH=data/module.key \
  python -m web_module --core wss://127.0.0.1:8443
```

`concurrency="pooled"`：无状态、只读，多个实例可分担负载。

## Frame ceiling（为什么预算是 48 KiB）

v1 传输**没有分片**，一帧明文上限 65519 字节（`FRAME_PLAINTEXT_BYTES`），transport 在
`payload > 65519` 时直接 `PAYLOAD_TOO_LARGE` 并断开（fatal）。一个发不出去的结果等于没有
结果，所以本模块把**整个结果**（`text` + JSON 元数据）压到 `MAX_RESULT_BYTES = 49152`
以内：65519 − 49152 = 16367 字节留给 JSON-RPC 信封和 Noise 帧头，绰绰有余。

- 默认 `max_bytes=32768`，加上元数据离预算还有 ~16 KiB，默认调用永远不会触发二次截断；
- `MAX_BYTES_CEILING` 也是 49152：允许读更宽的正文没有意义，反正装不进结果；
- 如果调用方显式要了 49152 的窗口，`text` 会被预算再切掉几百字节（元数据与转义的开销），
  这时 `truncated=true`、`text` 比 `bytes` 短——这是正常的，不是 bug；
- `--standalone` 不经过 transport，但同样受预算约束（`web_fetch` 自己就是那个约束）。

`bytes` 是窗口读到的正文字节数，`truncated` 是判断"要不要再要一次更小的窗口"的依据。

## 容器

```bash
docker build -f modules/web/Dockerfile -t vade/web:dev .
docker run --rm -v /tmp/agent:/data vade/web:dev \
  --standalone web_head --args '{"url":"https://example.com/"}'
```

镜像里 uid 10001，`/data` 之外没有可写层；容器需要出网（这是模块的用途），
所以不要把内网网段路由给它——SSRF 防护是应用层的第二道门，不是唯一一道。

## 三条不变量

1. `tools.py` 零 SDK import、零第三方 import（两个 AST 测试）。
2. 每个请求都经过 `validate_url()`；重定向后的目标也经过它，没有例外。
3. 连接用**已校验的字面 IP**，`Host`/SNI/证书用域名——两者永不互换。
