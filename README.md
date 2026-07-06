![](assets/kaede.png)

> [!IMPORTANT]
> リライト作業中です。

# Kaede
TCP、UDP、HTTPのような一般的なプロトコルを扱うためのPythonライブラリ

## システム要件
- Linux / macOS
- CPython 3.10+
- OpenSSL 3.6+ or 4.0+

Windowsへの対応は予定していません。
ただし、未検証ですがuvloopを除去しlibssl/libcryptoの読み込み部分を拡張すればWindowsでも動作すると思います。

## 対応プロトコル

### DNS
DNSは`socket`標準ライブラリを使用して実装します。

### TCP
TCPは`socket`標準ライブラリとOpenSSLによるTLS実装を使用して実装します。

### UDP
UDPは`socket`標準ライブラリを使用して実装します。

### QUIC
QUICはKaedeのUDP実装とOpenSSLによるTLS実装を使用して実装します。

### HTTP 1.0/1.1/2.0/3.0
HTTPはKaedeのTCP/QUIC実装、`socket`標準ライブラリによるUDS実装を使用して実装します。

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
        │   ├── models.py  # 抽象化クラス
        │   ├── errors.py  # 例外クラス
        │   └── helpers.py # ヘルパー関数
        ├── tls
        │   ├── __init__.py
        │   ├── models.py  # 抽象化クラス
        │   ├── errors.py  # 例外クラス
        │   └── openssl.py # OpenSSLローダー (ctypes)
        ├── tcp
        │   ├── __init__.py
        │   ├── tls.py      # TCP固有のTLS関連処理
        │   ├── client.py   # TCPクライアント (高水準API)
        │   ├── server.py   # TCPサーバー    (高水準API)
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── udp
        │   ├── __init__.py
        │   ├── client.py   # UDPクライアント (高水準API)
        │   ├── server.py   # UDPサーバー    (高水準API)
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── quic
        │   ├── __init__.py
        │   ├── tls.py      # QUIC固有のTLS関連処理
        │   ├── client.py   # QUICクライアント (高水準API)
        │   ├── server.py   # QUICサーバー    (高水準API)
        │   ├── errors.py   # 例外クラス
        │   └── protocol.py # プロトコル実装
        ├── http
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── hpack.py # HTTP/2.0 HPACK関連処理
        │   │   └── qpack.py # HTTP/3.0 QPACK関連処理
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── h1.py      # HTTP/1.0/1.1 固有処理
        │   │   ├── h2.py      # HTTP/2.0     固有処理
        │   │   ├── h3.py      # HTTP/3.0     固有処理
        │   │   └── handler.py # TCP/QUIC     接続ハンドラ
        │   ├── __init__.py
        │   ├── client.py    # HTTPクライアント (高水準API)
        │   ├── server.py    # HTTPサーバー    (高水準API)
        │   ├── errors.py    # 例外クラス
        │   ├── models.py    # 抽象化クラス
        │   ├── headers.py   # ヘッダー固有クラス
        │   ├── responses.py # レスポンス種類別のレスポンスクラス
        │   ├── finalizer.py # リクエスト/レスポンスの後処理とHTTP仕様準拠の検証
        │   └── websocket.py # WebSocket固有処理
        └── dns
            ├── protocol
            │   ├── __init__.py
            │   ├── tcp.py  # DNS over TCP
            │   ├── udp.py  # DNS over UDP
            │   ├── tls.py  # DNS over TLS  (DoT)
            │   └── http.py # DNS over HTTP (DoH)
            ├── __init__.py
            ├── client.py   # DNSクライアント (高水準API)
            ├── server.py   # DNSサーバー    (高水準API)
            ├── errors.py   # 例外クラス
            ├── models.py   # レコード種別/レコードクラス/レコードデータ/レコード/レコード一覧 クラス
            ├── records.py  # レコード種類別のレコードデータクラス
            └── protocol.py # プロトコル関連処理
```

## クレジット
TCP/UDP実装のコア部分は[t3tra-dev/tcp-ip](https://github.com/t3tra-dev/tcp-ip/)を参考にしています。
