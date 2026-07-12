![](assets/kaede.png)

> [!IMPORTANT]
> リライト作業中です。

# Kaede
TCP、UDP、HTTPのような一般的なプロトコルを扱うためのPythonライブラリ

## システム要件
- Linux / macOS
- CPython 3.9+
- OpenSSL 3.6+ or 4.0+

### Windowsへの対応について

Windowsへの対応は予定していません。
ただし、未検証ですがuvloopを除去しlibssl/libcryptoの読み込み部分を拡張すればWindowsでも動作すると思います。

## プロトコル

### UDS
標準ライブラリのラッパーとして実装します。

### TCP
標準ライブラリのラッパーとして実装します。

### UDP
標準ライブラリのラッパーとして実装します。

### SMTP
KaedeのTLS/TCPモジュールを使用して実装します。

### IMAP
KaedeのTLS/TCPモジュールを使用して実装します。

### POP3
KaedeのTLS/TCPモジュールを使用して実装します。

### QUIC
KaedeのTLS/UDPモジュールを使用して実装します。

### HTTP 1.0/1.1/2.0/3.0
KaedeのTLS/UDS/TCP/QUICモジュールを使用して実装します。

### DNS
KaedeのTLS/TCP/UDP/HTTPモジュールを使用して実装します。
