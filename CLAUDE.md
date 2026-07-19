# CLAUDE.md
This file provides information that Claude Code needs to know when handling the source code of Kaede.

## Overview
Kaede is a Python library for processing commonly used protocols. (e.g. TCP, UDP, QUIC, TLS, HTTP)

Please read README.md for details.

## Directory Structure
```
kaede/
├── pyproject.toml # プロジェクト設定
├── uv.lock        # 依存関係ロックファイル
├── tests          # 自動テスト (pytest)
│   └── ...
└── src
    └── kaede
        ├── __init__.py
        ├── ip.py        # IP関連の抽象化クラス
        ├── url.py       # URL
        ├── constants.py # 定数 (共通)
        ├── tls
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   └── ech.py # ECH (Encrypted Client Hello) 関連処理
        │   ├── __init__.py
        │   ├── models.py  # 抽象化クラス
        │   ├── errors.py  # 例外クラス
        │   └── openssl.py # OpenSSL (ctypes)
        ├── uds
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # UDSクライアント (高水準API)
        │   │   └── server.py # UDSサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── tcp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # TCPクライアント (高水準API)
        │   │   └── server.py # TCPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # TCP固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── udp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # UDPクライアント (高水準API)
        │   │   └── server.py # UDPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # UDP固有のDTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── mail
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # メールクライアント (高水準API)
        │   │   └── server.py # メールサーバー    (高水準API)
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── dns.py   # DNS   関連処理 (MXレコード等)
        │   │   ├── spf.py   # SPF   関連処理
        │   │   ├── dkim.py  # DKIM  関連処理
        │   │   └── dmarc.py # DMARC 関連処理
        │   ├── __init__.py
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   ├── parser.py   # パーサー
        │   └── protocol.py # プロトコル
        ├── smtp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # SMTPクライアント (高水準API)
        │   │   └── server.py # SMTPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # SMTP固有のTLS関連処理 (SMTPS関連処理)
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── imap
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # IMAPクライアント (高水準API)
        │   │   └── server.py # IMAPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # IMAP固有のTLS関連処理 (IMAPS関連処理)
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── pop3
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # POP3クライアント (高水準API)
        │   │   └── server.py # POP3サーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # POP3固有のTLS関連処理 (POP3S関連処理)
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── quic
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # QUICクライアント (高水準API)
        │   │   └── server.py # QUICサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # QUIC固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス
        │   └── protocol.py # プロトコル
        ├── http
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # HTTPクライアント (高水準API)
        │   │   └── server.py # HTTPサーバー    (高水準API)
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── dns.py         # DNS   関連処理 (HTTPSレコード等)
        │   │   ├── hsts.py        # HSTS  関連処理
        │   │   ├── hpack.py       # HPACK 関連処理
        │   │   ├── qpack.py       # QPACK 関連処理
        │   │   └── compression.py # メッセージボディ圧縮
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── handler.py    # UDS/TCP/QUIC 接続ハンドラ
        │   │   ├── connection.py # HTTP         接続抽象化クラス (1/2/3 共通)
        │   │   ├── h1.py         # HTTP/1.x     接続抽象化クラス
        │   │   ├── h2.py         # HTTP/2.x     接続抽象化クラス
        │   │   └── h3.py         # HTTP/3.x     接続抽象化クラス
        │   ├── __init__.py
        │   ├── errors.py    # 例外クラス
        │   ├── models.py    # 抽象化クラス
        │   ├── headers.py   # ヘッダー固有クラス
        │   ├── responses.py # レスポンス種類別のレスポンスクラス
        │   ├── finalizer.py # リクエスト/レスポンスの後処理(Server/Dateヘッダーの付与等)とHTTP仕様準拠の検証
        │   └── websocket.py # WebSocket固有処理
        └── dns
            ├── api
            │   ├── __init__.py
            │   ├── client.py # DNSクライアント (高水準API)
            │   └── server.py # DNSサーバー    (高水準API)
            ├── helpers
            │   ├── __init__.py
            │   └── dnssec.py # DNSSEC 関連処理
            ├── protocol
            │   ├── __init__.py
            │   ├── tcp.py     # DNS over TCP   固有処理
            │   ├── udp.py     # DNS over UDP   固有処理
            │   ├── tls.py     # DNS over TLS   固有処理
            │   ├── quic.py    # DNS over QUIC  固有処理
            │   ├── https.py   # DNS over HTTPS 固有処理
            │   └── handler.py # TCP/UDP/HTTP   接続ハンドラ
            ├── __init__.py
            ├── errors.py  # 例外クラス
            ├── models.py  # レコード種別/レコードクラス/レコードデータ/レコード/レコード一覧 クラス
            └── records.py # レコード種類別のレコードデータクラス
```

## Code Style
The Kaede source code style differs in some ways from the standard style of its respective languages. Please maintain the existing code structure and style.

In Python:
- Private objects (constants, variables, functions, etc.) do not exist (there are no objects starting with "_").
- Do not create objects (constants, variables, functions, classes, etc.) intended only for internal processing. Every object must be designed with the assumption that a user of the library may directly use it.
- Direct placement of objects (constants, variables, functions, etc.) in files is discouraged (simple processes or processes that are not particularly long should be placed as methods within the target class. For example, a helper function that only determines whether an HTTP message status code is a server-side error should be placed in the HTTPMessage class, while excessively long functions should be placed in locations like `helpers.py` or `helpers/*.py`).
- Use object (constant, variable, function, etc.) names that are simple but whose functionality and behavior can be inferred from the name (e.g., instead of hoge, fuga, aaaa, untitled, or cleanup_stale_socket, use cleanup, free, or drain).
- Classify what Kaede's protocols handle — not only the data/content being processed (e.g. DNSRecord for DNS records, HTTPMessage for HTTP messages), but also the entities that carry or act on it, such as per-version connection classes (e.g. H1Connection, H2Connection, H3Connection) and bindings (e.g. OpenSSL bindings). Use classes or data classes instead of redundant arguments to make these easier to handle. This does not mean classifying aggressively wherever possible — apply it to the data/content being processed and the entities that carry or act on it, not to every piece of logic.
- Keep the code symmetrical between all counterparts, not only between protocols and versions. Counterparts include protocols (TCP and UDP must both be usable in the same way; TCP-TLS, UDP-DTLS, and QUIC must all be usable in the same way), versions (the implementations of HTTP/1.x, HTTP/2, and HTTP/3 must be symmetrical), roles (the server and the client of each protocol must be symmetrical), directions (requests and responses must be handled, parsed, built, and validated in the same way), and any other pair or group that plays a corresponding role (e.g. encode/decode, send/receive, open/close, query/reply).
    - The important characteristics of Kaede that must be maintained are that it has reached a practically usable level, that anyone can use any protocol easily and intuitively, and that the differences between counterparts such as versions, protocols, roles, and directions are minimal or nonexistent.
- ...and so on. There are other conventions as well. If you discover any characteristics while working, please follow those patterns.

## Automated Testing
pytest is used for automated testing. While minimal tests can be covered by automated tests, they are not perfect, so prioritize manual testing as much as possible.

When using automated tests or updating test content, observe the following:

- Use automated tests only to easily verify that all existing features in Kaede function correctly and are in full compliance with specifications such as RFCs.
- The content of automated tests must always verify whether it is in full compliance with the strict protocol specifications, regardless of Kaede's current behavior.
    - If you assume Kaede's current behavior, the automated tests may pass even when there is an error in the implementation, preventing early detection.
    - If automated tests are based on current behavior, they effectively become tests for verifying consistency with the status quo, which defeats their original purpose.
    - If an implementation error is discovered and fixed, tests will not pass if they were based on the previous behavior, even if the fix itself is correct. This increases the effort required to update test content and undermines reliability.
    - For the reasons mentioned above, when updating test content, do not trust Kaede's source code or behavior at all; ensure the content complies with actual protocol specifications. You should follow this for safety and quality, even if you wrote the code yourself and are confident in its compliance.

## Testing by Claude
When performing manual testing, follow these steps:

1. First, discover as many bugs or vulnerabilities as possible. Use various creative methods such as reading all the code, carefully examining each part of the code, executing the server, or testing in different environments like Docker. Focus only on finding as many issues as possible without confirming whether they are actually problems.
2. Next, create a detailed list of the issues discovered in step 1.
3. Finally, verify whether those issues are truly problems. Use various methods such as reading related code, thinking through the actual execution flow line by line, verifying in a real environment, or checking the actual specifications of related libraries on the internet.

### Note
This procedure incorporates the following approaches. Please keep these in mind when updating this procedure:
- Dividing into multiple steps helps focus on each stage, enabling more reliable testing.
- Step 2 is performed before verifying issues, which helps in better understanding through documentation, making the verification and correction of issues easier and more reliable.

## Fixing by Claude
When fixing issues, follow these steps:

1. First, verify whether the issue is actually a problem. Use various methods such as reading related code, thinking through the actual execution flow line by line, verifying in a real environment, or checking the actual specifications of related libraries on the internet. Even if a pre-check was performed as in step 3 of "Testing by Claude," you must perform this again.
2. Next, gather the information necessary for the fix. As in step 1, read the actual code and conduct research on the internet.
3. Finally, fix the issue in compliance with the rules for code changes in the "Changes by Claude" section.

## Changes by Claude
When making changes to code or content, observe the following:

- Maintain the structure and style of existing code, and use simple and reliable methods to implement features or fix issues with highly readable code.
- Strive to ensure that each feature or module does not contain code specific to other features, modules, or common areas. If there is absolutely no way other than adding it, keep the added code to a minimum.
- Carefully consider implementation methods. In particular, pay close attention to safety and reliability.
- It must be possible for humans to understand the changes completely and without misunderstanding. Provide detailed work logs in a prominent form at a medium frequency during work.
- When implementing new features, add as many high-quality and detailed tests as possible to the automated tests. When adding, strictly observe the rules for expanding test items.
- Always run tests after completing work. Execute automated tests with pytest or the steps in the "Testing by Claude" section. It is strongly recommended to perform manual testing compliant with the "Testing by Claude" section in addition to automated tests.

When approved by human review and a human requests the creation of a commit, you may create a commit after observing the following:

- Before actually creating the commit, summarize the commit message and the changes to be included (i.e., staged with git add) in detail, inform the human, and create the commit once approved.
- Write the commit message in Japanese or English.
- The first line of the commit message should allow for easy understanding of the commit content even without knowing the details in the following lines.
- Summarize more detailed changes from the second/third line onwards.
- Add the "Claude: " prefix to the first line of the commit message.
- Include a trailer in the format "Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL 0] [TOOL 1]" in the commit.
    - Use names like "Claude", "ChatGPT", or "Gemini" for AGENT_NAME.
    - Use text like "claude-sonnet-4.6" for MODEL_VERSION.
    - For [TOOL 0] [TOOL 1], list the names of the tools used to analyze the code, separated by spaces.
        - You do not need to list basic daily system tools like file editing, web search/browsing, git, uv, or clang.
