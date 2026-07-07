![](assets/kaede.png)

> [!IMPORTANT]
> リライト作業中です。

# Kaede
TCP、UDP、HTTPのような一般的なプロトコルを扱うためのPythonライブラリ

## システム要件
- Linux / macOS
- CPython 3.10+
- OpenSSL 3.6+ or 4.0+

### Windowsへの対応について

Windowsへの対応は予定していません。
ただし、未検証ですがuvloopを除去しlibssl/libcryptoの読み込み部分を拡張すればWindowsでも動作すると思います。

## 対応プロトコル

### UDS
UDSは`asyncio`標準ライブラリのラッパーとして実装します。

### TCP
TCPは`asyncio`標準ライブラリのラッパーとして実装します。

### UDP
UDPは`asyncio`標準ライブラリのラッパーとして実装します。

### QUIC
QUICはKaedeのUDPモジュールとOpenSSLによるTLS実装を使用して実装します。

### HTTP 1.0/1.1/2.0/3.0
HTTPはKaedeのUDS/TCP/QUICモジュールとOpenSSLによるTLS実装を使用して実装します。

### DNS
KaedeのTCP/UDP/HTTPモジュールとOpenSSLによるTLS実装を使用して実装します。

## ディレクトリ構造
```
kaede/
├── pyproject.toml # プロジェクト設定
├── uv.lock        # 依存関係ロックファイル
├── tests          # 自動テスト (pytest)
│   └── ...
└── src
    └── kaede
        ├── __init__.py
        ├── url.py       # URL
        ├── constants.py # 定数 (共通)
        ├── ip
        │   ├── __init__.py
        │   └── models.py # 抽象化クラス
        ├── tls
        │   ├── __init__.py
        │   ├── models.py  # 抽象化クラス
        │   ├── errors.py  # 例外クラス
        │   └── openssl.py # OpenSSLローダー (ctypes)
        ├── tcp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # TCPクライアント (高水準API)
        │   │   └── server.py # TCPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # TCP固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── udp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # UDPクライアント (高水準API)
        │   │   └── server.py # UDPサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── quic
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # QUICクライアント (高水準API)
        │   │   └── server.py # QUICサーバー    (高水準API)
        │   ├── __init__.py
        │   ├── tls.py      # QUIC固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── http
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── client.py # HTTPクライアント (高水準API)
        │   │   └── server.py # HTTPサーバー    (高水準API)
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── dns.py   # DNS   関連処理 (HTTPSレコード等)
        │   │   ├── hsts.py  # HSTS  関連処理
        │   │   ├── hpack.py # HPACK 関連処理
        │   │   └── qpack.py # QPACK 関連処理
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── h1.py      # HTTP/1.0/1.1 固有処理
        │   │   ├── h2.py      # HTTP/2.0     固有処理
        │   │   ├── h3.py      # HTTP/3.0     固有処理
        │   │   └── handler.py # TCP/QUIC     接続ハンドラ
        │   ├── __init__.py
        │   ├── errors.py    # 例外クラス
        │   ├── models.py    # 抽象化クラス
        │   ├── headers.py   # ヘッダー固有クラス
        │   ├── responses.py # レスポンス種類別のレスポンスクラス
        │   ├── finalizer.py # リクエスト/レスポンスの後処理とHTTP仕様準拠の検証
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
            │   ├── tcp.py     # DNS over TCP         固有処理
            │   ├── udp.py     # DNS over UDP         固有処理
            │   ├── tls.py     # DNS over TLS   (DoT) 固有処理
            │   ├── https.py   # DNS over HTTPS (DoH) 固有処理
            │   └── handler.py # TCP/UDP/HTTP         接続ハンドラ
            ├── __init__.py
            ├── errors.py  # 例外クラス
            ├── models.py  # レコード種別/レコードクラス/レコードデータ/レコード/レコード一覧 クラス
            └── records.py # レコード種類別のレコードデータクラス
```
