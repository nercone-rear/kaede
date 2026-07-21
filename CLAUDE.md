# CLAUDE.md
このファイルは、Kaedeのソースコードを扱う際にClaudeが把握しておくべき情報を提供するものです。

## 概要
Kaedeは、一般的に使用されるプロトコル(TCP、UDP、QUIC、HTTPなど)を処理するためのPythonライブラリです。

詳細はREADME.mdを参照してください。

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
        ├── ip.py        # IP関連の抽象化クラス
        ├── url.py       # URL
        ├── models.py    # 抽象化クラス (Limits/ServerLimits)
        ├── constants.py # 定数 (共通)
        ├── tls
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   └── ech.py # ECH (Encrypted Client Hello) 関連処理
        │   ├── __init__.py
        │   ├── errors.py  # 例外クラス
        │   ├── models.py  # 抽象化クラス (TLSVersion/TLSState/TLSGroup/TLSCipher/TLSConfig)
        │   └── openssl.py # OpenSSL (ctypes)
        ├── uds
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # UDS 共通　　　　 (UDS      Limits/UDS      Config)
        │   │   ├── client.py # UDS クライアント (UDSClientLimits/UDSClientConfig/UDSClient)
        │   │   └── server.py # UDS サーバー　　 (UDSServerLimits/UDSServerConfig/UDSServer/UDSHandler)
        │   ├── __init__.py
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス (UDSPort)
        │   └── protocol.py # プロトコル　 (UDSConnection/UDSProtocol)
        ├── tcp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # TCP 共通　　　　 (TCP      Limits/TCP      Config)
        │   │   ├── client.py # TCP クライアント (TCPClientLimits/TCPClientConfig/TCPClient)
        │   │   └── server.py # TCP サーバー　　 (TCPServerLimits/TCPServerConfig/TCPServer/TCPHandler)
        │   ├── __init__.py
        │   ├── tls.py      # TCP固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス (TCPPort)
        │   └── protocol.py # プロトコル　 (TCPConnection/TCPProtocol)
        ├── udp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # UDP 共通　　　　 (UDP      Limits/UDP      Config)
        │   │   ├── client.py # UDP クライアント (UDPClientLimits/UDPClientConfig/UDPClient)
        │   │   └── server.py # UDP サーバー　　 (UDPServerLimits/UDPServerConfig/UDPServer/UDPHandler)
        │   ├── __init__.py
        │   ├── tls.py      # UDP固有のDTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   ├── models.py   # 抽象化クラス (UDPPort)
        │   └── protocol.py # プロトコル　 (UDPConnection/UDPProtocol)
        ├── mail
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── dns.py   # DNS   関連処理 (MXレコード等)
        │   │   ├── spf.py   # SPF   関連処理
        │   │   ├── dkim.py  # DKIM  関連処理
        │   │   └── dmarc.py # DMARC 関連処理
        │   ├── __init__.py
        │   ├── errors.py   # 例外クラス
        │   └── models.py   # 抽象化クラス
        ├── smtp
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # SMTP 共通　　　　 (SMTP      Limits/SMTP      Config)
        │   │   ├── client.py # SMTP クライアント (SMTPClientLimits/SMTPClientConfig/SMTPClient)
        │   │   └── server.py # SMTP サーバー　　 (SMTPServerLimits/SMTPServerConfig/SMTPServer/SMTPHandler)
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── common.py # SMTP  共通
        │   │   ├── base.py   # SMTP  基底 (SMTPConnection/SMTPProtocol)
        │   │   └── s1.py     # SMTP1 固有 (S1  Connection/S1  Protocol)
        │   ├── __init__.py
        │   ├── tls.py      # SMTP固有のTLS関連処理 (SMTPS関連処理)
        │   ├── errors.py   # 例外クラス
        │   └── models.py   # 抽象化クラス
        ├── imap
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # IMAP 共通　　　　 (IMAP      Limits/IMAP      Config)
        │   │   ├── client.py # IMAP クライアント (IMAPClientLimits/IMAPClientConfig/IMAPClient)
        │   │   └── server.py # IMAP サーバー　　 (IMAPServerLimits/IMAPServerConfig/IMAPServer/IMAPHandler)
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── common.py # IMAP  共通
        │   │   ├── base.py   # IMAP  基底 (IMAPConnection/IMAPProtocol)
        │   │   ├── i1.py     # IMAP1 固有 (I1  Connection/I1  Protocol)
        │   │   ├── i2.py     # IMAP2 固有 (I2  Connection/I2  Protocol)
        │   │   ├── i3.py     # IMAP3 固有 (I3  Connection/I3  Protocol)
        │   │   └── i4.py     # IMAP4 固有 (I4  Connection/I4  Protocol)
        │   ├── __init__.py
        │   ├── tls.py      # IMAP固有のTLS関連処理 (IMAPS関連処理)
        │   ├── errors.py   # 例外クラス
        │   └── models.py   # 抽象化クラス
        ├── pop
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # POP 共通　　　　 (POP      Limits/POP      Config)
        │   │   ├── client.py # POP クライアント (POPClientLimits/POPClientConfig/POPClient)
        │   │   └── server.py # POP サーバー　　 (POPServerLimits/POPServerConfig/POPServer/POPHandler)
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── common.py # POP  共通
        │   │   ├── base.py   # POP  基底 (POPConnection/POPProtocol)
        │   │   ├── p1.py     # POP1 固有 (P1 Connection/P1 Protocol)
        │   │   ├── p2.py     # POP2 固有 (P2 Connection/P2 Protocol)
        │   │   └── p3.py     # POP3 固有 (P3 Connection/P3 Protocol)
        │   ├── __init__.py
        │   ├── tls.py      # POP固有のTLS関連処理 (POP3S関連処理)
        │   ├── errors.py   # 例外クラス
        │   └── models.py   # 抽象化クラス
        ├── quic
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # QUIC 共通　　　　 (QUIC      Limits/QUIC      Config)
        │   │   ├── client.py # QUIC クライアント (QUICClientLimits/QUICClientConfig/QUICClient)
        │   │   └── server.py # QUIC サーバー　　 (QUICServerLimits/QUICServerConfig/QUICServer/QUICHandler)
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── common.py # QUIC   共通
        │   │   ├── base.py   # QUIC   基底 (QUICConnection/QUICProtocol)
        │   │   ├── q1.py     # QUICv1 固有 (Q1  Connection/Q1  Protocol)
        │   │   └── q2.py     # QUICv2 固有 (Q2  Connection/Q2  Protocol)
        │   ├── __init__.py
        │   ├── tls.py      # QUIC固有のTLS関連処理
        │   ├── errors.py   # 例外クラス
        │   └── models.py   # 抽象化クラス
        ├── http
        │   ├── api
        │   │   ├── __init__.py
        │   │   ├── common.py # HTTP 共通　　　　 (HTTP      Limits/HTTP      Config)
        │   │   ├── client.py # HTTP クライアント (HTTPClientLimits/HTTPClientConfig/HTTPClient)
        │   │   └── server.py # HTTP サーバー　　 (HTTPServerLimits/HTTPServerConfig/HTTPServer/HTTPHandler)
        │   ├── helpers
        │   │   ├── __init__.py
        │   │   ├── dns.py         # DNS   関連処理 (HTTPSレコード等)
        │   │   ├── hsts.py        # HSTS  関連処理
        │   │   ├── hpack.py       # HPACK 関連処理
        │   │   ├── qpack.py       # QPACK 関連処理
        │   │   └── compression.py # メッセージボディ圧縮 (compress/compress_with/decompress)
        │   ├── protocol
        │   │   ├── __init__.py
        │   │   ├── handler.py # UDS/TCP/QUIC 接続ハンドラ (HTTPUDSHandler/HTTPTCPHandler/HTTPQUICHandler)
        │   │   ├── common.py  # HTTP         共通
        │   │   ├── base.py    # HTTP         基底　　　　 (HTTPConnection/HTTPProtocol)
        │   │   ├── h1.py      # HTTP/1.x     固有　　　　 (H1  Connection/H1  Protocol)
        │   │   ├── h2.py      # HTTP/2.x     固有　　　　 (H2  Connection/H2  Protocol)
        │   │   └── h3.py      # HTTP/3.x     固有　　　　 (H3  Connection/H3  Protocol)
        │   ├── __init__.py
        │   ├── errors.py    # 例外クラス
        │   ├── models.py    # 抽象化クラス (HTTPPort/HTTPRole/HTTPBroadRole/HTTPHeaderCase/HTTPHeaders/HTTPMessage/HTTPRequest/HTTPResponse)
        │   ├── headers.py   # ヘッダー固有クラス
        │   ├── responses.py # レスポンス種類別のレスポンスクラス
        │   ├── finalizer.py # リクエスト/レスポンスの後処理(Server/Dateヘッダーの付与等)とHTTP仕様準拠の検証 (finalize_request/finalize_response)
        │   └── websocket.py # WebSocket固有処理 (WSOpCode/WSCloseCode/WSFrame/WSConnection)
        └── dns
            ├── api
            │   ├── __init__.py
            │   ├── common.py # DNS 共通　　　　 (DNS      Limits/DNS      Config)
            │   ├── client.py # DNS クライアント (DNSClientLimits/DNSClientConfig/DNSClient)
            │   └── server.py # DNS サーバー　　 (DNSServerLimits/DNSServerConfig/DNSServer/DNSHandler)
            ├── helpers
            │   ├── __init__.py
            │   └── dnssec.py # DNSSEC 関連処理
            ├── protocol
            │   ├── __init__.py
            │   ├── handler.py # TCP/UDP/TLS/QUIC/HTTPS 接続ハンドラ (DNSTCPHandler/DNSUDPHandler/DNSTLSHandler/DNSQUICHandler/DNSHTTPSHandler)
            │   ├── common.py  # DNS
            │   ├── base.py    # DNS                    基底 (DNS     Connection/DNS     Protocol)
            │   ├── tcp.py     # DNS over TCP           固有 (DNSTCP  Connection/DNSTCP  Protocol)
            │   ├── udp.py     # DNS over UDP           固有 (DNSUDP  Connection/DNSUDP  Protocol)
            │   ├── tls.py     # DNS over TLS           固有 (DNSTLS  Connection/DNSTLS  Protocol)
            │   ├── quic.py    # DNS over QUIC          固有 (DNSQUIC Connection/DNSQUIC Protocol)
            │   └── https.py   # DNS over HTTPS         固有 (DNSHTTPSConnection/DNSHTTPSProtocol)
            ├── __init__.py
            ├── errors.py  # 例外クラス
            ├── models.py  # 抽象化クラス (DNSOpCode/DNSResponseCode/DNSRecordName/DNSRecordType/DNSRecordClass/DNSRecordData/DNSRecords/DNSExtension/DNSMessage)
            └── records.py # レコード種類別のレコードデータクラス
```

## コードの制約
Kaedeのソースコードのスタイルは、各言語の標準的なスタイルといくつかの点で異なります。既存のコード構造やスタイルを維持してください。

- プライベートなオブジェクト(定数、変数、関数、クラスなど)は存在しません。(言語の仕様上`_`から始める必要がなく、つまりPythonでは`__str__`や`os._exit()`などでない場合、先頭が`_`で始まるオブジェクトは存在するべきではありません)
- 内部処理のためだけに使用することを意図したオブジェクトを作成しないでください。すべてのオブジェクトは、ライブラリの利用者が直接使用する可能性があることを前提に設計する必要があります。
- 特定のクラスに対して作用する関数は、その関数が過度に長い場合を除いて、クラス内にメソッドとして配置してください。
- 関数や定数は、Enumやデータクラスの場合、または言語の仕様上クラス上に配置する必要があるもの(Pythonでは`_fields_`など)、または利便性のための最低限のクラス内定数(`OpenSSL.minimum_version`のように)を除いて、そのクラスが配置されているファイルに直接、インポート直後または対象クラス周辺に配置してください。
- オブジェクト名はシンプルかつ役割や振る舞いを正確に理解できる必要があります。(例: `Server.cleanup_stale_socket()`ではなく`HTTPServer.cleanup()`)
- あらゆる対応関係でコードの対称性を保ってください。これはプロトコル(TCP/UDP/QUIC、IMAP/POP3)、バージョン(HTTP/1.x/2.x/3.x)、役割(クライアント/サーバー)、方向性(リクエスト/レスポンス)、およびその他の対応する役割を果たすペアやグループ(例: エンコード/デコード、送信/受信、オープン/クローズ、クエリ/リプライ)が該当します。対称性にはオブジェクトの配置、役割、動作などが含まれ、例えば同じ種類のプロトコル同士であれば(そのプロトコル自身の特徴に関する箇所を除いて)完全なドロップイン互換を保証する必要があります。
    - Kaedeにおいて維持すべき重要な特性は、実用的に使用可能なレベルに達していること、誰もがどのプロトコルも簡単かつ直感的に使用できること、そしてバージョン・プロトコル・役割などのカウンターパート間の差異が最小限、あるいは一切存在しないことです。
    - 例として、バージョン間の互換性は基底クラスを作成し(`class H1Connection(HTTPConnection)`のように)継承させることで保証しやすくなります。また、そのクラスを使用する側は可能な限り(`H1Connection`のような)バージョン固有のクラスではなく(`HTTPConnection`のような)基底クラスを参照するようにするといいでしょう。
- 高レイヤーのプロトコルは、低レイヤーのプロトコルを扱う際、ライブラリの利用者と全く同じ方法で扱ってください。
    - 例えばHTTPがTCPプロトコルでの通信を受けて処理するためには、`TCPServer`/`HTTPTCPHandler(TCPHandler)`/`TCPServerConfig`/`TCPServerLimits`を使用します。
- ...など。これらに限定されません。作業中に何らかの特徴を発見した際は、それに従ってください。

### 型/クラス名について
- `XXXVersion`はXXXプロトコルのバージョンを表すための型です。
- `XXXPort`はXXXプロトコルのポートを表すための型です。UDS/TCP/UDPのような独自のポートを持つプロトコル、またはDNSやHTTPのような複数のプロトコル上で動作するプロトコルに存在します。
- `XXXLimits`はXXXプロトコルの処理中に適用する制限(同時接続数、レート制限、サイズ上限 など)を管理するためのインスタンスです。
- `XXXConfig`はXXXプロトコルの処理中に適用する設定(有効なバージョンの一覧 など)を管理するためのインスタンスです。
- `XXXClient`はXXXプロトコルのクライアント(通信開始)側の高水準APIです。
- `XXXServer`はXXXプロトコルのサーバー(通信処理/応答)側の高水準APIです。
- `XXXHandler`はXXXプロトコルのサーバーが通信を処理する際に実行するコールバック関数をまとめたクラスです。
- `XXXProtocol`はXXXプロトコルにおいて1接続に対して作成されるインスタンスです。1つ下の層(QUICの場合はUDP)の1接続に対して1つ作成されます。UDS/TCP/UDPのような標準ライブラリ上に実装されているプロトコルでは、`asyncio.Protocol`または`asyncio.DatagramProtocol`を継承するクラスとして存在します。
- `XXXConnection`はXXXプロトコルにおいて1接続に対して作成されるインスタンスです。QUICなどの擬似的な接続管理を採用しているプロトコルの場合、その擬似的な接続に対して1つ作成されます。

## 自動テスト
自動テストにはpytestを使用します。最小限のテストは自動テストでカバーできますが、あくまで補助的なものであり、可能な限り手動テストを優先してください。

テスト内容を更新する場合は、以下を遵守してください:

- 自動テストは、Kaedeの既存機能がすべて正しく動作し、RFCなどの仕様に完全に準拠していることを容易に検証するためだけに使用してください。現状のKaedeの構造に可能な限り依存しないようにしてください。
- 自動テストの内容は、Kaedeの現在の挙動にかかわらず、常に厳格なプロトコル仕様への完全な準拠を検証するものでなければなりません。
    - Kaedeの現在の挙動を前提とすると、実装に誤りがあっても自動テストが通ってしまう可能性があり、早期発見を妨げます。
    - 自動テストが現在の挙動を前提としている場合、それは事実上、現状維持との整合性を検証するテストとなってしまい、本来の目的を損ないます。
    - 実装の誤りが発見され修正された場合、修正自体が正しくても、以前の挙動を前提としたテストは通らなくなります。これによりテスト内容の更新にかかる労力が増え、信頼性が損なわれます。
    - 上記の理由から、テスト内容を更新する際は、Kaedeのソースコードや挙動を一切信頼せず、内容が実際のプロトコル仕様に準拠していることを確認してください。たとえ自分がそのコードを書き、準拠していると確信していたとしても、安全性と品質のためにこれを遵守すべきです。
- 自動テストの内容は、MUST違反のような重大なものに限定せず、プロトコルの完全な仕様を含んでいる必要があります。

## Claudeによるテスト
手動テストを実施する際は、以下の手順に従ってください:

1. まず、可能な限り多くのバグや脆弱性を発見してください。すべてのコードを読む、各部分を注意深く精査する、サーバーを実行する、Dockerなど異なる環境でテストするなど、様々な方法を使用してください。この段階では、それが実際に問題かどうかを確認せず、問題をできるだけ多く発見することだけに専念してください。
2. 次に、手順1で発見した問題の詳細なリストを作成してください。リストには発見した経緯や追加した理由などを含めてください。
3. 最後に、それらの問題が本当に問題であるかを検証してください。関連コードを読む、実際の実行フローを一行ずつ考える、実環境で検証する、インターネットで関連ライブラリの実際の仕様を確認するなど、様々な方法を使用して慎重に行なってください。

### 注記
この手順には以下の知見が組み込まれています。この手順を更新する際は、これらを念頭に置いてください:
- 複数の手順に分けることで各手順に集中しやすくなり、より確実なテストが可能になります。
- 手順2を問題の検証前に実施することで、ドキュメント化を通じた理解が深まり、問題の検証・修正がより容易かつ確実になります。

## Claudeによる修正
問題を修正する際は、以下の手順に従ってください:

1. まず、その問題が実際に問題であるかを検証してください。関連コードを読む、実際の実行フローを一行ずつ考える、実環境で検証する、インターネットで関連ライブラリの実際の仕様を確認するなど、様々な方法を使用してください。「Claudeによるテスト」の手順3のような事前確認を行っていたとしても、これを再度実施する必要があります。
2. 次に、修正に必要な情報を収集してください。手順1と同様に、実際のコードを読み、インターネットで調査を行ってください。
3. 最後に、「Claudeによる変更」セクションのコード変更ルールに準拠して問題を修正してください。

## Claudeによる変更
コードや内容を変更する際は、以下を遵守してください:

- 既存コードの構造とスタイルを維持し、可読性の高いコードで、シンプルかつ確実な方法により機能の実装や問題の修正を行ってください。
- 各機能やモジュールに、他の機能・モジュール・共通部分に固有のコードが含まれないよう努めてください。追加する以外に方法が全くない場合は、追加するコードを最小限に留めてください。
- 実装方法を慎重に検討してください。特に、安全性と信頼性に細心の注意を払ってください。
- 人間が変更内容を誤解なく完全に理解できるようにしてください。作業中は目立つ形で、中程度の頻度で詳細な作業ログを提供してください。
- 大きな変更を行なった際は、できるだけ多くの高品質かつ詳細なテストを自動テストに追加してください。追加する際は、テスト項目更新のルールを厳格に遵守してください。
- 作業完了後は必ずテストを実行してください。pytestによる自動テスト、または「Claudeによるテスト」セクションの手順を実行してください。自動テストに加え、「Claudeによるテスト」セクションに準拠した手動テストの実施を強く推奨します。

## Claudeによるコミット
人間によるレビューで承認を受け、人間からコミット作成の依頼があった場合、以下を遵守した上でコミットを作成できます:

- 実際にコミットを作成する前に、コミットメッセージと含める変更内容(すなわちgit addでステージングされるもの)を詳細に説明し、承認を得てからコミットを作成してください。
- コミットメッセージは日本語または英語で記述してください。
- コミットメッセージの1行目は、詳細を知らなくてもコミット内容が容易に理解できるものにしてください。
- 2行目/3行目以降でより詳細な変更内容を要約してください。
- コミットメッセージの1行目に「Claude: 」「ChatGPT: 」「Gemini: 」のようなプレフィックスを付けてください。
- コミットに「Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL 0] [TOOL 1]」形式のトレーラーを含めてください。
    - AGENT_NAMEには「Claude」「ChatGPT」「Gemini」のような名前を使用してください。
    - MODEL_VERSIONには「claude-sonnet-4.6」のようなテキストを使用してください。
    - [TOOL 0] [TOOL 1]には、コード分析に使用したツールの名前をスペース区切りで列挙してください。
        - ファイル編集、Web検索/ブラウジング、git、uv、clangといった基本的な日常的システムツールは列挙する必要はありません。

## トラブルシューティング / 参考情報

### 適切なバージョンのOpenSSLがインストールされていない場合

Kaedeは、ほとんどのLinuxディストリビューションが提供する最新版でも満たされないほど厳格なOpenSSLの要件を持っています。
(この記述の更新時点では、3.6+または4.0+が必要とされています)

これはClaudeのサンドボックス環境も例外ではありません。Claude Codeをローカルで実行している場合を除き、Claudeはサンドボックス内でのみ作業できます。
標準的なLinux環境と同様、サンドボックス内では古いバージョンのOpenSSLしか利用できないため、ソースからビルドするか、ビルド済みバイナリを取得する必要があります。

幸い、開発のために、GitHub Actionsを利用してOpenSSLを定期的にビルドするGitHubリポジトリを用意しています。
[nercone-rear/openssl](https://github.com/nercone-rear/openssl/releases/)から、各OpenSSLバージョン・プラットフォーム・アーキテクチャ向けのビルドを取得できます。これらはCIで使用されているものと同一のバイナリです。注意点として、実行時にOPENSSLCONF環境変数を設定する必要があることに注意してください。

適切なバージョンのOpenSSLがインストールされていない場合は、nercone-rear/opensslからバイナリを取得し使用してください。
各リリースにはSHA256SUMS/SHA384SUMS/SHA512SUMSファイルが含まれているため、ダウンロード後は必ず検証してください。

サンドボックス上で(nercone-rear/opensslのような)外部リポジトリからコンテンツを取得する場合、`add_repo`を実行する必要があるかもしれません。ほとんどの場合、ユーザーはこれを承認します。
