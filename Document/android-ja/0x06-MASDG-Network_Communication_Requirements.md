# ネットワーク通信要件

## MSTG-NETWORK-1
データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。

### 安全なネットワークリクエスト

#### 推奨されるネットワーク API の使い方

まず、ソースコード内ですべてのネットワークリクエストを特定し、平文の HTTP URL が使用されていないことを確認する必要がある。機密情報は、[HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection) または [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html) (TLS を使用したソケットレベルの通信用 ) を使用して、安全なチャネルで送信されるようにする。<br>

次に、セキュアな接続を行うことを前提とした低レベルの API (SSLSocket など) を使用する場合でも、セキュアな実装が必要であることに注意する。例えば、SSLSocket はホスト名を検証しない。ホスト名を確認するには getDefaultHostnameVerifier を使用する。[コード例](https://developer.android.com/training/articles/security-ssl#WarningsSslSocket)は Android の開発者向けドキュメントを参照する。<br>

参考資料
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing Network Requests over Secure Protocols](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-network-requests-over-secure-protocols)
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing Network API Usage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-network-api-usage)

ルールブック
* [平文の HTTP URL が使用されていないことを確認する（必須）](#平文の-http-url-が使用されていないことを確認する必須)
* [機密情報は安全なチャネルで送信されるようにする（必須）](#機密情報は安全なチャネルで送信されるようにする必須)
* [低レベルの API を使用したセキュアな実装（必須）](#低レベルの-api-を使用したセキュアな実装必須)

#### 平文の HTTP トラフィックの設定

次に、アプリが平文の HTTP トラフィックを許可していないことを確認する必要がある。 Android 9 ( API level 28 ) 以降、平文の HTTP トラフィックはデフォルトでブロックされる（ [デフォルトのネットワークセキュリティ構成](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)によって ）が、アプリが平文を送信する方法はまだ複数ある。<br>

* AndroidManifest.xml ファイルの \<application\> タグの [android:usesCleartextTraffic](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) 属性を設定する。Network Security Configuration が設定されている場合、このフラグは無視されることに注意する。
* \<domain-config\> 要素で cleartextTrafficPermitted 属性を true に設定し、 CleartextTraffic を有効にするように Network Security Configuration を設定する。
* 低レベルの API (例： [Socket](https://developer.android.com/reference/java/net/Socket) ) を使用して、カスタム HTTP 接続を設定する。
* クロスプラットフォームフレームワーク ( Flutter、Xamarin など ) を使用する。これらには通常、 HTTP ライブラリの独自の実装がある。

上記のすべてのケースは、全体として注意深く分析する必要がある。例えば、アプリが Android Manifest や Network Security Configuration で CleartextTraffic を許可していない場合でも、実際には HTTP トラフィックを送信している可能性がある。これは、低レベルの API ( Network Security Configuration が無視される ) を使用している場合や、クロスプラットフォームフレームワークが適切に設定されていない場合に起こり得る。<br>

詳細については、「 [HTTPS と SSL によるセキュリティ](https://developer.android.com/training/articles/security-ssl.html) 」を参照。<br>

参考資料
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing for Cleartext Traffic](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-for-cleartext-traffic)

ルールブック
* [アプリが平文の HTTP トラフィックを許可していないことを確認する（必須）](#アプリが平文の-http-トラフィックを許可していないことを確認する必須)


### ルールブック
1. [平文の HTTP URL が使用されていないことを確認する（必須）](#平文の-http-url-が使用されていないことを確認する必須)
1. [機密情報は安全なチャネルで送信されるようにする（必須）](#機密情報は安全なチャネルで送信されるようにする必須)
1. [低レベルの API を使用したセキュアな実装（必須）](#低レベルの-api-を使用したセキュアな実装必須)
1. [アプリが平文の HTTP トラフィックを許可していないことを確認する（必須）](#アプリが平文の-http-トラフィックを許可していないことを確認する必須)

#### 平文の HTTP URL が使用されていないことを確認する（必須）

ソースコード内ですべてのネットワークリクエストを特定し、平文の HTTP URL が使用されていないことを確認する必要がある。

これに違反する場合、以下の可能性がある。
* 平文情報が第三者に漏洩する。

#### 機密情報は安全なチャネルで送信されるようにする（必須）
危険なチャネル（ HTTP ）により機密情報を送信すると、平文のまま送信されることにより第三者へ漏洩する可能性がある。そのため、機密情報を送信する場合は安全なチャネル（ HTTPS、SSL 等）で送信する必要がある。

以下に安全なチャネルで送信するためのサンプルコードを示す。

* [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection) 
   ```kotlin
   val url = URL("https://gmail.com:433/")
   val urlConnection = url.openConnection() as HttpsURLConnection
   urlConnection.connect();
   ```

* [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html)
   ```kotlin
   val socket: SSLSocket = SSLSocketFactory.getDefault().run {
       createSocket("gmail.com", 443) as SSLSocket
   }
   ```

これに違反する場合、以下の可能性がある。
* 機密情報が第三者に漏洩する。

#### 低レベルの API を使用したセキュアな実装（必須）

低レベルの API を使用する場合でも、セキュアな実装が必要である。
SSLSocket はホスト名を検証しない。ホスト名を確認するには getDefaultHostnameVerifier を使用する。

以下は SSLSocket 使用時のホスト名検証サンプルコードの一例。
```kotlin
    // Open SSLSocket directly to gmail.com
    val socket: SSLSocket = SSLSocketFactory.getDefault().run {
        createSocket("gmail.com", 443) as SSLSocket
    }
    val session = socket.session

    // Verify that the certicate hostname is for mail.google.com
    // This is due to lack of SNI support in the current SSLSocket.
    HttpsURLConnection.getDefaultHostnameVerifier().run {
        if (!verify("mail.google.com", session)) {
            throw SSLHandshakeException("Expected mail.google.com, found ${session.peerPrincipal} ")
        }
    }

    // At this point SSLSocket performed certificate verification and
    // we have performed hostname verification, so it is safe to proceed.

    // ... use socket ...
    socket.close()
    
```

これに違反する場合、以下の可能性がある。
* 通信先ホストが信頼できるか保証されない可能性がある。

#### アプリが平文の HTTP トラフィックを許可していないことを確認する（必須）

アプリが平文の HTTP トラフィックを許可していないことを確認する。
Android 9 ( API level 28 ) 以降、平文の HTTP トラフィックはデフォルトでブロックされるが、アプリが平文を送信する方法は複数存在する。

以下はアプリから平文を送信する方法の一例。
* AndroidManifest.xml ファイルの \<application\> タグの [android:usesCleartextTraffic](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) 属性を設定する。Network Security Configuration が設定されている場合、このフラグは無視されることに注意する。
   ```xml
   <application
               android:usesCleartextTraffic="true">
   </application>
   ```

* \<domain-config\> 要素で cleartextTrafficPermitted 属性を true に設定し、 CleartextTraffic を有効にするように Network Security Configuration を設定する。
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <network-security-config>
       <base-config cleartextTrafficPermitted="false" />
       <domain-config cleartextTrafficPermitted="true">
           <domain includeSubdomains="true">secure.example.com</domain>
       </domain-config>
   </network-security-config>
   ```

* 低レベルの API (例： [Socket](https://developer.android.com/reference/java/net/Socket) ) を使用して、カスタム HTTP 接続を設定する。
   ```kotlin
   val address = InetSocketAddress(ip, port)
   val socket = Socket()
   try {
       socket.connect(address)
   } catch (e: Exception) {
   }
   ```

* クロスプラットフォームフレームワーク ( Flutter、Xamarin など ) を使用する。これらには通常、 HTTP ライブラリの独自の実装がある。

これに違反する場合、以下の可能性がある。
* HTTP トラフィックにより平文を送信する。

## MSTG-NETWORK-2
TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨される標準規格をサポートしていない場合には可能な限り近い状態である。

### 推奨される TLS 設定

サーバ側で適切な TLS 設定を行うことも重要である。 SSL プロトコルは非推奨であり、もはや使用するべきではない。また、 TLS v1.0 と TLS v1.1 には[既知の脆弱性](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols)があり、 2020 年までにすべての主要なブラウザでその使用が非推奨となった。 TLS v1.2 および TLS v1.3 は、安全なデータ通信のためのベストプラクティスと考えられている。

Android 10(API level 29) 以降では、TLS v1.3 がデフォルトで有効になり、より高速で安全な通信が可能になる。 [TLS v1.3 の主な変更点](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)は、暗号スイートのカスタマイズができなくなり、 TLS v1.3 を有効にするとすべての暗号スイートが有効になるのに対し、 0-RTT(Zero Round Trip) モードがサポートされない。<br>

クライアントとサーバの両方が同じ組織で管理され、互いに通信するためだけに使用されている場合、[設定を強化](https://dev.ssllabs.com/projects/best-practices/)することでセキュリティを強化できる。<br>

モバイルアプリケーションが特定のサーバに接続する場合、そのネットワークスタックを調整することで、サーバの構成に対して可能な限り高いセキュリティレベルを確保することができる。オペレーティングシステムのサポートが不十分な場合、モバイルアプリケーションはより弱い構成を使用せざるを得なくなる可能性がある。<br>

参考資料
* [owasp-mastg Verifying the TLS Settings (MSTG-NETWORK-2) Recommended TLS Settings](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04f-Testing-Network-Communication.md#recommended-tls-settings)

ルールブック
* [安全な通信プロトコル（必須）](#安全な通信プロトコル必須)

### 推奨される暗号スイート

暗号スイートの構造は以下の通りである。<br>
```txt
Protocol_KeyExchangeAlgorithm_WITH_BlockCipher_IntegrityCheckAlgorithm
```

この構造には以下が含まれる。<br>
* 暗号化で使用されるプロトコル
* TLS ハンドシェイク中にサーバとクライアントが認証に使用する鍵交換アルゴリズム
* メッセージストリームの暗号化に使用されるブロック暗号
* メッセージの認証に使用される完全性保証チェックアルゴリズム

例： TLS_RSA_WITH_3DES_EDE_CBC_SHA<br>

上記の例では、以下の暗号化スイートが使用されている。
* プロトコルとしての TLS
* 認証のための RSA 非対称暗号化
* EDE_CBC モードによる対称暗号化のための 3DES
* 完全性のための SHA ハッシュアルゴリズム

TLSv1.3 では、鍵交換アルゴリズムは暗号スイートの一部ではなく、TLS ハンドシェイク中に決定されることに注意する。<br>

次のリストでは、暗号スイートの各部分のさまざまなアルゴリズムを紹介する。<br>

プロトコル :
* SSL v1
* SSL v2 - [RFC 6176](https://www.rfc-editor.org/rfc/rfc6176)
* SSL v3 - [RFC 6101](https://www.rfc-editor.org/rfc/rfc6101)
* TLS v1.0 - [RFC 2246](https://www.ietf.org/rfc/rfc2246)
* TLS v1.1 - [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346)
* TLS v1.2 - [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)
* TLS v1.3 - [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)

鍵交換アルゴリズム :
* DSA - [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)
* ECDSA - [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)
* RSA - [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)
* DHE - [RFC 2631](https://www.rfc-editor.org/rfc/rfc2631) - [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)
* ECDHE - [RFC 4492](https://www.rfc-editor.org/rfc/rfc4492)
* PSK - [RFC 4279](https://www.rfc-editor.org/rfc/rfc4279)
* DSS - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
* DH_anon - [RFC 2631](https://www.rfc-editor.org/rfc/rfc2631) - [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)
* DHE_RSA - [RFC 2631](https://www.rfc-editor.org/rfc/rfc2631) - [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)
* DHE_DSS - [RFC 2631](https://www.rfc-editor.org/rfc/rfc2631) - [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)
* ECDHE_ECDSA - [RFC 8422](https://www.rfc-editor.org/rfc/rfc8422)
* ECDHE_PSK - [RFC 8422](https://www.rfc-editor.org/rfc/rfc8422) - [RFC 5489](https://www.rfc-editor.org/rfc/rfc5489)
* ECDHE_RSA - [RFC 8422](https://www.rfc-editor.org/rfc/rfc8422)

ブロック暗号 :
* DES - [RFC 4772](https://www.rfc-editor.org/rfc/rfc4772)
* DES_CBC - [RFC 1829](https://www.rfc-editor.org/rfc/rfc1829)
* 3DES - [RFC 2420](https://www.rfc-editor.org/rfc/rfc2420)
* 3DES_EDE_CBC - [RFC 2420](https://www.rfc-editor.org/rfc/rfc2420)
* AES_128_CBC - [RFC 3268](https://www.rfc-editor.org/rfc/rfc3268)
* AES_128_GCM - [RFC 5288](https://www.rfc-editor.org/rfc/rfc5288)
* AES_256_CBC - [RFC 3268](https://www.rfc-editor.org/rfc/rfc3268)
* AES_256_GCM - [RFC 5288](https://www.rfc-editor.org/rfc/rfc5288)
* RC4_40 - [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465)
* RC4_128 - [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465)
* CHACHA20_POLY1305 - [RFC 7905](https://www.rfc-editor.org/rfc/rfc7905) - [RFC 7539](https://www.rfc-editor.org/rfc/rfc7539)

完全性チェックアルゴリズム :
* MD5 - [RFC 6151](https://www.rfc-editor.org/rfc/rfc6151)
* SHA - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)
* SHA256 - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)
* SHA384 - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)

暗号スイートの効率は、そのアルゴリズムの効率に依存することに注意する必要がある<br>

以下のリソースは、 TLS で使用するために推奨される最新の暗号スイートが含まれている。<br>
* IANA が推奨する暗号スイートは、 [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) に記載されている。
* OWASP が推奨する暗号スイートは、 [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md) に記載されている。

Android の一部バージョンでは、推奨する暗号スイートに対応していないものもあるため、互換性のために、 [Android](https://developer.android.com/reference/javax/net/ssl/SSLSocket#cipher-suites) のバージョンでサポートされている暗号スイートを確認し、上位の暗号スイートを選択することが可能である。<br>

サーバが適切な暗号スイートをサポートしているかどうかを確認する場合は、さまざまなツールを使用できる。<br>
* [testssl.sh](https://github.com/drwetter/testssl.sh) は、「 TLS/SSL 暗号、プロトコル、およびいくつかの暗号の欠陥のサポートについて、任意のポートでサーバのサービスをチェックする無料のコマンドラインツール」である。

最後に、 HTTPS 接続が終了するサーバまたは終了プロキシが、ベストプラクティスに従って設定されていることを確認する。 [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md) および [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/) を参照する。<br>

参考資料
* [owasp-mastg Verifying the TLS Settings (MSTG-NETWORK-2) Cipher Suites Terminology](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04f-Testing-Network-Communication.md#cipher-suites-terminology)

ルールブック
* [TLS で推奨される暗号化スイート（推奨）](#tls-で推奨される暗号化スイート推奨)

### ルールブック
1. [安全な通信プロトコル（必須）](#安全な通信プロトコル必須)
1. [TLS で推奨される暗号化スイート（推奨）](#tls-で推奨される暗号化スイート推奨)

#### 安全な通信プロトコル（必須）
サーバ側で適切な TLS 設定を行うことも重要である。 SSL プロトコルは非推奨であり、もはや使用するべきではない。

非推奨プロトコル
* SSL
* TLS v1.0
* TLS v1.1

TLS v1.0 と TLS v1.1 については、2020 年までにすべての主要なブラウザでその使用が非推奨となった。


推奨プロトコル
* TLS v1.2
* TLS v1.3

Android 10(API level 29) 以降では、TLS v1.3 がデフォルトで有効になり、より高速で安全な通信が可能になる。
TLS v1.3 を有効にするとすべての暗号スイートが有効になるのに対し、 0-RTT(Zero Round Trip) モードがサポートされない。

これに違反する場合、以下の可能性がある。
* セキュリティエクスプロイトに対して脆弱である。

#### TLS で推奨される暗号化スイート（推奨）

以下は推奨される暗号化スイートの一例。([TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) で推奨されている暗号化スイートの中で、[Android](https://developer.android.com/reference/javax/net/ssl/SSLEngine)で非推奨ではないものを記載。)
* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
* TLS_AES_128_GCM_SHA256
* TLS_AES_256_GCM_SHA384
* TLS_CHACHA20_POLY1305_SHA256
* TLS_AES_128_CCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_DHE_RSA_WITH_AES_128_CCM
* TLS_DHE_RSA_WITH_AES_256_CCM
* TLS_DHE_PSK_WITH_AES_128_CCM
* TLS_DHE_PSK_WITH_AES_256_CCM
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
* TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256

これに注意しない場合、以下の可能性がある。
* 脆弱な暗号化スイートを使用する可能性がある。

## MSTG-NETWORK-3
セキュアチャネルが確立されたときに、アプリはリモートエンドポイントの X.509 証明書を検証している。信頼された CA により署名された証明書のみが受け入れられている。

### 信頼する証明書の設定

#### ターゲット SDK バージョンごとのデフォルト設定

Android 7.0 (API level 24) 以降をターゲットとするアプリケーションは、ユーザが提供する CA を信頼しないデフォルトのネットワークセキュリティ構成を使用し、ユーザを誘い込んで悪意のあるCAをインストールさせる MITM 攻撃の可能性を低減する。<br>

[apktool を使用してアプリをデコード](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#exploring-the-app-package)し、 apktool.yml の targetSdkVersion が 24 以降であることを確認する。<br>
```txt
grep targetSdkVersion UnCrackable-Level3/apktool.yml
  targetSdkVersion: '28'
```

ただし、 targetSdkVersion >=24 の場合でも、開発者はカスタムネットワークセキュリティ構成を使用してデフォルトの保護を無効にし、ユーザが提供する CA をアプリに強制的に信頼させる custom trust anchor を定義することができる。 「[カスタムトラストアンカーの分析](#カスタムトラストアンカーの分析)」 を参照。<br>

参考資料
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Verifying the Target SDK Version](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#verifying-the-target-sdk-version)

ルールブック
* [ターゲット SDK バージョンによる MITM 攻撃の可能性（必須）](#ターゲット-sdk-バージョンによる-mitm-攻撃の可能性必須)
* [カスタムトラストアンカーの分析（必須）](#カスタムトラストアンカーの分析必須)

#### カスタムトラストアンカーの分析

[Network Security Configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#android-network-security-configuration) ファイルを検索し、 \<certificates src="user"\> を定義しているカスタムの \<trust-anchors\> を調査する ( これは避けるべきである ) 。<br>

[エントリの優先順位](https://developer.android.com/training/articles/security-config#ConfigInheritance)を慎重に分析する必要がある。<br>
* \<domain-config\> のエントリまたは親の \<domain-config\> に値が設定されていない場合、設定は \<base-config\> に基づいて行われる。
* このエントリで定義されていない場合、[デフォルトの設定](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)が使用される。

Android 9 (API level 28) を対象とするアプリのネットワークセキュリティ構成の例は以下の通りである。<br>
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

いくつかの考察を紹介する。 :<br>
* \<base-config\> がないため、Android 9 ( API level 28 ) 以降の[デフォルト設定](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)が他のすべての接続に使用される（原則としてシステム認証 CA のみが信頼される）。
* しかし、 \<domain-config\> はデフォルトの設定を上書きし、指定された \<domain\> (owasp.org) に対して、アプリがシステムとユーザの両方の認証局を信頼することを可能にする。
*  includeSubdomains="false" のため、サブドメインには影響しない。

すべてをまとめると、上記のネットワークセキュリティ構成を次のように説明することができる。<br>
「このアプリは、サブドメインを除く owasp.org ドメインのシステムとユーザの両方の認証局を信頼する。他のドメインでは、アプリはシステムの認証局のみを信頼する。」<br>

参考資料
* [owasp-mastg Testing Endpoint Identify VerificatioTG-NETWORK-3) Static Analysis Analyzing Custom Trust Anchors](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#analyzing-custom-trust-anchors)n (MS

ルールブック
* [カスタムトラストアンカーの分析（必須）](#カスタムトラストアンカーの分析必須)

### サーバ証明書の検証

#### TrustManager による検証

TrustManager は、 Android において信頼できる接続を確立するために必要な条件を確認する手段である。このとき、以下の条件を確認する必要がある。<br>
* 証明書は、信頼できる CA によって署名されているか？
* 証明書の有効期限が切れていないか？
* 自己署名の証明書であるか？

以下のコード スニペットは開発中に使用されることがあり、関数 checkClientTrusted, checkServerTrusted, getAcceptedIssuers をオーバーライドして、どんな証明書でも受け入れてしまう。このような実装は避けるべきであり、必要な場合は、組み込みのセキュリティ上の欠陥を回避するために、 production builds とは明確に分離する必要がある。<br>
```java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

参考資料
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Verifying the Server Certificate](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate)

ルールブック
* [TrustManager による検証（必須）](#trustmanager-による検証必須)

#### WebView でのサーバ証明書の検証

アプリケーションは WebView を使用して、アプリケーションに関連付けられた Web サイトをレンダリングすることがある。これは、アプリケーションのインタラクションに内部 WebView を使用する Apache Cordova などの HTML/JavaScript ベースのフレームワークに当てはまる。WebView が使用される場合、モバイルブラウザはサーバ証明書の検証を実行する。WebView がリモート Web サイトに接続しようとしたときに発生する TLS エラーを無視することは、バッドプラクティスである。<br>

以下のコードは、 WebView に提供される WebViewClient のカスタム実装と全く同じように、TLS エラーを無視する。<br>

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        //Ignore TLS certificate errors and instruct the WebViewClient to load the website
        handler.proceed();
    }
});
```

Apache Cordova フレームワークの内部 WebView 使用の実装は、 application manifest で android:debuggable フラグが有効になっていると、 onReceivedSslError メソッドで [TLS エラー](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java)を無視する。そのため、アプリがデバッグ可能でないことを確認する。

参考資料
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis WebView Server Certificate Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification)
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Apache Cordova Certificate Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#apache-cordova-certificate-verification)

ルールブック
* [WebView でのサーバ証明書の検証のバッドプラクティス（必須）](#webview-でのサーバ証明書の検証のバッドプラクティス必須)

### ホスト名の検証

クライアント側の TLS 実装におけるもう 1 つのセキュリティ上の欠陥は、ホスト名の検証の欠如である。開発環境は通常、有効なドメイン名ではなく内部アドレスを使用するため、開発者はホスト名の検証を無効にし（あるいはアプリケーションに任意のホスト名を許可させ）、アプリケーションが本番稼働するときに変更することを忘れてしまうことがある。<br>
次のコードは、ホスト名検証を無効にするものである。<br>

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

組み込みの HostnameVerifier を使用すると、任意のホスト名を受け入れることができる。

```java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

信頼できる接続を設定する前に、アプリケーションがホスト名を検証していることを確認する。

参考資料
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Hostname Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#hostname-verification)

ルールブック
* [ホスト名の検証（必須）](#ホスト名の検証必須)

### ルールブック
1. [ターゲット SDK バージョンによる MITM 攻撃の可能性（必須）](#ターゲット-sdk-バージョンによる-mitm-攻撃の可能性必須)
1. [カスタムトラストアンカーの分析（必須）](#カスタムトラストアンカーの分析必須)
1. [TrustManager による検証（必須）](#trustmanager-による検証必須)
1. [WebView でのサーバ証明書の検証のバッドプラクティス（必須）](#webview-でのサーバ証明書の検証のバッドプラクティス必須)
1. [ホスト名の検証（必須）](#ホスト名の検証必須)

#### ターゲット SDK バージョンによる MITM 攻撃の可能性（必須）

Android 7.0 (API level 24) 以降をターゲットとするアプリケーションは、ユーザが提供する CA を信頼しないデフォルトのネットワークセキュリティ構成を使用し、ユーザを誘い込んで悪意のあるCAをインストールさせる MITM 攻撃の可能性を低減する。

[apktool を使用してアプリをデコード](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#exploring-the-app-package)し、 apktool.yml の targetSdkVersion が 24 以降であることを確認する。

これに違反する場合、以下の可能性がある。
* 悪意のあるCAをインストールさせる MITM 攻撃の可能性が高まる。

#### カスタムトラストアンカーの分析（必須）

targetSdkVersion >=24 の場合でも、開発者はカスタムネットワークセキュリティ構成を使用してデフォルトの保護を無効にし、ユーザが提供する CA をアプリに強制的に信頼させることをカスタムトラストアンカーで定義することができる。

AndroidManifest.xml に設定されている android:networkSecurityConfig の設定を確認する必要がある。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>
```

android:networkSecurityConfig に設定されている Network Security Configuration ファイルを確認して、以下のタグの状態を確認する必要がある。
* \<base-config>
* \<trust-anchors>
* \<certificates>

※ \<certificates src="user"> の設定は避ける必要がある。

また、固有の構成で設定されていないタグは \<base-config> での設定を継承し、 \<base-config> が設定されていない場合はプラットフォームの既定値が設定される。

[エントリの優先順位](https://developer.android.com/training/articles/security-config#ConfigInheritance)を慎重に分析する必要がある。<br>
* \<domain-config\> のエントリまたは親の \<domain-config\> に値が設定されていない場合、設定は \<base-config\> に基づいて行われる。
* このエントリで定義されていない場合、[デフォルトの設定](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)が使用される。

Android 9 (API level 28) を対象とするアプリのネットワークセキュリティ構成の例は以下の通りである。<br>
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

いくつかの考察を紹介する。 :<br>
* \<base-config\> がないため、Android 9 ( API level 28 ) 以降の[デフォルト設定](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)が他のすべての接続に使用される（原則としてシステム認証 CA のみが信頼される）。
* しかし、 \<domain-config\> はデフォルトの設定を上書きし、指定された \<domain\> (owasp.org) に対して、アプリがシステムとユーザの両方の認証局を信頼することを可能にする。
*  includeSubdomains="false" のため、サブドメインには影響しない。

すべてをまとめると、上記のネットワークセキュリティ構成を次のように説明することができる。<br>
「このアプリは、サブドメインを除く owasp.org ドメインのシステムとユーザの両方の認証局を信頼する。他のドメインでは、アプリはシステムの認証局のみを信頼する。」<br>

これに違反する場合、以下の可能性がある。
* 悪意のあるCAをインストールさせる MITM 攻撃の可能性が高まる。

#### TrustManager による検証（必須）
TrustManager を用いて関数 checkClientTrusted, checkServerTrusted, getAcceptedIssuers をオーバーライドした場合、以下サンプルコードのようにクライアント証明書の検証を行わずに全ての証明書を受け入れてしまうと、安全な通信を保証できない。開発時の場合には、以下サンプルコードにより自己証明書での動作確認が実施できて便利であるが、誤って製品版に組み込まれないようにするために処理を分けるべきである。

```java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

以下サンプルコードは、 特定の CA のセットを信頼するために、 TrustManager を初期化作成して HttpsURLConnection を設定する処理である。
```java
    // Load CAs from an InputStream
    // (could be from a resource or ByteArrayInputStream or ...)
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    // From https://www.washington.edu/itconnect/security/ca/load-der.crt
    InputStream caInput = new BufferedInputStream(new FileInputStream("load-der.crt"));
    Certificate ca;
    try {
        ca = cf.generateCertificate(caInput);
        System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
    } finally {
        caInput.close();
    }

    // Create a KeyStore containing our trusted CAs
    String keyStoreType = KeyStore.getDefaultType();
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    keyStore.load(null, null);
    keyStore.setCertificateEntry("ca", ca);

    // Create a TrustManager that trusts the CAs in our KeyStore
    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(keyStore);

    // Create an SSLContext that uses our TrustManager
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, tmf.getTrustManagers(), null);

    // Tell the URLConnection to use a SocketFactory from our SSLContext
    URL url = new URL("https://certs.cac.washington.edu/CAtest/");
    HttpsURLConnection urlConnection =
        (HttpsURLConnection)url.openConnection();
    urlConnection.setSSLSocketFactory(context.getSocketFactory());
    InputStream in = urlConnection.getInputStream();
    copyInputStreamToOutputStream(in, System.out);
    
```

参考資料
* [HTTPS と SSL を使用したセキュリティ 未知の認証局](https://developer.android.com/training/articles/security-ssl?hl=ja#UnknownCa)

これに違反する場合、以下の可能性がある。
* 自己証明書での検証が含まれる場合、信頼できる証明書であるかの判断がつかない。

#### WebView でのサーバ証明書の検証のバッドプラクティス（必須）

アプリケーションは WebView を使用して、アプリケーションに関連付けられた Web サイトをレンダリングすることがある。これは、アプリケーションのインタラクションに内部 WebView を使用する Apache Cordova などの HTML/JavaScript ベースのフレームワークに当てはまる。WebView が使用される場合、モバイルブラウザはサーバ証明書の検証を実行する。WebView がリモート Web サイトに接続しようとしたときに発生する TLS エラーを無視することは、バッドプラクティスである。

以下のサンプルコードは、 TLS エラーを無視して WebViewClient に Web サイトをロードする処理の一例。
```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        //Ignore TLS certificate errors and instruct the WebViewClient to load the website
        handler.proceed();
    }
});
```

Apache Cordova フレームワークの内部 WebView 使用の実装は、 application manifest で android:debuggable フラグが有効になっていると、 onReceivedSslError メソッドで [TLS エラー](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java)を無視する。そのため、アプリがデバッグ可能でないことを確認する。

これに違反する場合、以下の可能性がある。
* 中間者攻撃に対して脆弱になる。

#### ホスト名の検証（必須）

開発段階において、開発者はホスト名の検証を無効（あるいはアプリケーションに任意のホスト名を許可させ）にして開発を行っていることがある。
本番環境稼働時に変更せず検証を無効としていることがある。


以下は、無効としている場合のものである。

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

以下は、任意のホスト名を受け入れるようにしたものである。

```java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

本番環境接続時にホスト名の検証を行う必要がある。

これに違反する場合、以下の可能性がある。
* ホスト先が信頼される宛先のホストでは無い状態で通信する可能性がある。