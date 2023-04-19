# 認証とセッション管理要件

## MSTG-AUTH-1
アプリがユーザにリモートサービスへのアクセスを提供する場合、ユーザ名/パスワード認証など何らかの形態の認証がリモートエンドポイントで実行されている。

<span style="color: red; ">※本章での適切な認証対応については「[<span style="color: red; ">MSTG-ARCH-2 の 1.2.1.1. 適切な認証対応</span>](0x02-MASDG-Architecture_Design_and_Threat_Modeling_Requirements.md#適切な認証対応)」を参照する。</span>

参考資料
* [owasp-mastg Verifying that Appropriate Authentication is in Place (MSTG-ARCH-2 and MSTG-AUTH-1)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#verifying-that-appropriate-authentication-is-in-place-mstg-arch-2-and-mstg-auth-1)
* [owasp-mastg Testing OAuth 2.0 Flows (MSTG-AUTH-1 and MSTG-AUTH-3)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-oauth-20-flows-mstg-auth-1-and-mstg-auth-3)

## MSTG-AUTH-2

ステートフルなセッション管理を使用する場合、リモートエンドポイントはランダムに生成されたセッション識別子を使用し、ユーザの資格情報を送信せずにクライアント要求を認証している。

### セッション情報の管理

ステートフル(または「セッションベース」)認証は、クライアントとサーバの両方に認証レコードがあることが特徴である。認証の流れは以下の通りである。

1. アプリはユーザの認証情報を含む要求をバックエンドサーバに送信する。
2. サーバは認証情報を確認する。認証情報が有効な場合、サーバはランダムなセッション ID とともに新しいセッションを作成する。
3. サーバはセッション ID を含む応答をクライアントに送信する。
4. クライアントは以降のすべての要求でセッション ID を送信する。サーバはセッション ID を検証し、関連するセッションレコードを取得する。
5. ユーザがログアウトした後、サーバ側のセッションレコードは破棄され、クライアントはセッション ID を破棄する。


セッションの管理が不適切な場合、様々な攻撃に対して脆弱となり、正規のユーザのセッションが侵害され、攻撃者がそのユーザになりすますことが可能になる。その結果、データの損失、機密性の低下、不正な操作が生じる可能性がある。

参考資料
* [owasp-mastg Testing Stateful Session Management (MSTG-AUTH-2)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-stateful-session-management-mstg-auth-2)

#### セッション管理のベストプラクティス
機密情報や機能を提供するサーバ側のエンドポイントを探し出し、一貫した認可の実施を検証する。バックエンドサービスは、ユーザのセッション ID またはトークンを検証し、ユーザがリソースにアクセスするための十分な権限を持っていることを確認する必要がある。セッション ID またはトークンがない、または無効な場合、要求を拒否する必要がある。


確認事項
* セッション ID は、サーバ側でランダムに生成される。
* ID は簡単に推測できないようにする。（適切な長さとエントロピーを使用する）
* セッション ID は常に安全な接続（例 : HTTPS ）で交換される。
* モバイルアプリはセッション ID を永続的なストレージに保存しない。
* サーバは、ユーザが権限を要するアプリケーションにアクセスするたびに、セッションを検証する。（セッション ID は有効で、適切な認証レベルに対応している必要がある）
* セッションはサーバ側で終了し、タイムアウトまたはユーザがログアウトした後にモバイルアプリ内でセッション情報が削除される。

認証は実装するべきでなく、実績のあるフレームワークの上に構築する必要がある。多くの一般的なフレームワークは、既製の認証およびセッション管理機能を提供している。アプリが認証のためにフレームワークのAPIを使用する場合、ベストプラクティスのためにフレームワークのセキュリティドキュメントを確認する。一般的なフレームワークのセキュリティガイドは、以下のリンクで入手できる。

* [Spring  ( Java )](https://spring.io/projects/spring-security)
* [Struts  ( Java )](https://struts.apache.org/security/)
* [Laravel  ( PHP )](https://laravel.com/docs/9.x/authentication)
* [Ruby on Rails](https://guides.rubyonrails.org/security.html)

サーバ側の認証を検証するための最適なリソースは、OWASP Web Testing Guide 、特に、「 [Testing Authentication](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/04-Authentication_Testing/README) 」と「 [Testing Session Management](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) 」の章に掲載されている。

参考資料
* [owasp-mastg Testing Stateful Session Management (MSTG-AUTH-2) Session Management Best Practices](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#session-management-best-practices)

ルールブック
* [モバイルアプリはセッション ID を永続的なストレージに保存しないことを確認する（必須）](#モバイルアプリはセッション-id-を永続的なストレージに保存しないことを確認する必須)

### ルールブック
1. [モバイルアプリはセッション ID を永続的なストレージに保存しないことを確認する（必須）](#モバイルアプリはセッション-id-を永続的なストレージに保存しないことを確認する必須)

#### モバイルアプリはセッション ID を永続的なストレージに保存しないことを確認する（必須）
永続的なストレージにセッション ID を保存すると、ユーザにより読み書きされたり、第三者により利用されたりする恐れがある。そのため、セッション ID はこのようなストレージには保存しないようにする必要がある。

※非推奨なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* セッション ID をユーザにより読み書きされたり、第三者により利用されたりする恐れがある。

## MSTG-AUTH-3
ステートレスなトークンベースの認証を使用する場合、サーバはセキュアなアルゴリズムを使用して署名されたトークンを提供している。

### トークンの管理
トークンベースの認証は、 HTTP 要求ごとに署名されたトークン（サーバによって検証される）を送信することによって実装される。最も一般的に使用されているトークン形式は、 [RFC7519](https://www.rfc-editor.org/rfc/rfc7519) で定義されている JSON Web Token である。 JWT は、完全なセッション状態を JSON オブジェクトとしてエンコードすることができる。そのため、サーバはセッションデータや認証情報を保存する必要がない。

 JWT トークンは、ドットで区切られた 3 つの Base64Url エンコード部分から構成されている。トークンの構造は以下の通りである。

```default
base64UrlEncode(header).base64UrlEncode(payload).base64UrlEncode(signature)
```

次の例は、 [Base64Url でエンコードされた JSON Web Token](https://jwt.io/#debugger) を示している。

```default
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva
G4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

ヘッダーは通常 2 つの部分から構成される。トークンタイプ（ JWT ）と、署名を計算するために使用されるハッシュアルゴリズムである。上の例では、ヘッダーは以下のようにデコードされる。

```json
{"alg":"HS256","typ":"JWT"}
```

トークンの 2 番目の部分はペイロードで、いわゆるクレームを含んでいる。クレームは、あるエンティティ（通常はユーザ）に関するステートメントと、追加のメタデータである。
例を以下に示す。

```json
{"sub":"1234567890","name":"John Doe","admin":true}
```

署名は、符号化されたヘッダー、符号化されたペイロード、および秘密値に対して、 JWT ヘッダーで指定されたアルゴリズムを適用することによって作成される。例えば、 HMAC SHA256 アルゴリズムを使用する場合、署名は以下のように作成される。

```java
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

この秘密情報は、認証サーバとバックエンドサービスの間で共有され、クライアントはそれを認識しないことに注意する。これは、トークンが正当な認証サービスから取得されたことを証明するものである。また、クライアントがトークンに含まれるクレームを改ざんすることも防ぐことができる。


参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-stateless-token-based-authentication-mstg-auth-3)


### 静的解析
サーバとクライアントが使用している JWT ライブラリを特定する。使用している JWT ライブラリに既知の脆弱性があるかどうかを確認する。

実装が JWT の [ベストプラクティス](https://stormpath.com/blog/jwt-the-right-way) を遵守していることを確認する。

* トークンを含むすべての受信要求について、 HMAC が検証されることを確認する。
* 秘密署名鍵または HMAC 秘密鍵の場所を確認する。キーはサーバに保管し、決してクライアントと共有してはならない。発行者と検証者のみが利用可能であるべきである。
*  JWT に個人を特定できる情報のような機密データが埋め込まれていないことを確認する。何らかの理由でトークン内にそのような情報を送信する必要があるアーキテクチャの場合、ペイロードの暗号化が適用されていることを確認する。 [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) にある Java 実装のサンプルを参照する。
*  JWT に一意な識別子を与える jti ( JWT ID ) クレームでリプレイ攻撃に対処していることを確認する。
* クロスサービスリレー攻撃には、トークンがどのアプリケーションのためのものかを定義する aud ( audience ) クレームで対処していることを確認する。
* トークンは、 Keychain (iOS) により、モバイルデバイス上に安全に保管されていることを確認する。

参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#static-analysis-4)

ルールブック
* [使用している JWT ライブラリの特定及び既知の脆弱性があるかどうかを確認する（必須）](#使用している-jwt-ライブラリの特定及び既知の脆弱性があるかどうかを確認する必須)
* [トークンは、 Keychain (iOS) により、モバイルデバイス上に安全に保管されていることを確認する（必須）](#トークンは-keychain-ios-によりモバイルデバイス上に安全に保管されていることを確認する必須)

#### ハッシュアルゴリズムの強制
攻撃者はトークンを変更し、「 none 」キーワードを使って署名アルゴリズムを変更し、トークンの完全性がすでに検証されていることを示すことによってこれを実行する。[ライブラリ](https://stormpath.com/blog/jwt-the-right-way)によっては、「 none 」アルゴリズムで署名されたトークンを、検証済みの署名を持つ有効なトークンであるかのように扱い、アプリケーションは変更されたトークンの要求を信頼する可能性がある。

参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3) Enforcing the Hashing Algorithm](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#enforcing-the-hashing-algorithm)

ルールブック
* [期待するハッシュアルゴリズムを要求する必要がある（必須）](#期待するハッシュアルゴリズムを要求する必要がある必須)

#### トークンの有効期限
署名されたステートレス認証トークンは、署名キーが変更されない限り永久に有効である。トークンの有効期限を制限する一般的な方法は、有効期限を設定することである。トークンに ["exp" expiration claim](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)が含まれ、バックエンドが期限切れのトークンを処理しないことを確認する。


トークンを付与する一般的な方法は、[アクセストークンとリフレッシュトークン](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)を組み合わせることである。ユーザがログインすると、バックエンドサービスは有効期間の短いアクセストークンと有効期間の長いリフレッシュトークンを発行する。アクセストークンの有効期限が切れた場合、アプリケーションはリフレッシュトークンを使って新しいアクセストークンを取得することができる。

機密データを扱うアプリの場合、リフレッシュトークンの有効期限が適切な期間であることを確認する必要がある。次のコード例では、リフレッシュトークンの発行日をチェックするリフレッシュトークン API を紹介する。トークンが 14 日以上経過していない場合、新しいアクセストークンが発行される。それ以外の場合は、アクセスが拒否され、再度ログインするよう促される。

```java
app.post('/renew_access_token', function (req, res) {
    // verify the existing refresh token
    var profile = jwt.verify(req.body.token, secret);
  
    // if refresh token is more than 14 days old, force login
    if (profile.original_iat - new Date() > 14) { // iat == issued at
      return res.send(401); // re-login
    }
  
    // check if the user still exists or if authorization hasn't been revoked
    if (!valid) return res.send(401); // re-logging
  
    // issue a new access token
    var renewed_access_token = jwt.sign(profile, secret, { expiresInMinutes: 60*5 });
    res.json({ token: renewed_access_token });
  });
```

参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3) Token Expiration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#token-expiration)

ルールブック
* [リフレッシュトークンの有効期限に適切な期間を設定する（必須）](#リフレッシュトークンの有効期限に適切な期間を設定する必須)

### 動的解析
動的解析を行いながら、以下の JWT の脆弱性を調査する。

* クライアント上のトークン保存場所
    * JWT を使用するモバイルアプリの場合、トークンの保管場所を確認する必要がある。

* 署名キーのクラック
    * トークン署名は、サーバ上の秘密キーを介して作成される。 JWT を取得した後、[オフラインで秘密鍵をブルートフォースするため](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)のツールを選択する。

* 情報の開示
    *  Base64Url でエンコードされた JWT をデコードし、それがどのようなデータを送信しているか、そのデータが暗号化されているかどうかを調べることができる。

* ハッシュアルゴリズムの改ざん
    * [非対称型アルゴリズム](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)の使用。 JWT は RSA や ECDSA のような非対称アルゴリズムをいくつか提供している。これらのアルゴリズムが使用される場合、トークンは秘密鍵で署名され、検証には公開鍵が使用される。もしサーバが非対称アルゴリズムで署名されたトークンを期待し、 HMAC で署名されたトークンを受け取った場合、サーバは公開鍵を HMAC 秘密鍵として扱う。そして、公開鍵はトークンに署名するために HMAC 秘密鍵として採用され、悪用される可能性がある。

    * トークンヘッダの alg 属性を修正し、 HS256 を削除して none に設定し、空の署名 ( 例えば、 signature = "" ) を使用する。このトークンを使用し、要求で再生する。いくつかのライブラリは、 none アルゴリズムで署名されたトークンを、 検証済みの署名を持つ有効なトークンとして扱う。これにより、攻撃者は自分自身の「署名付き」トークンを作成することができる。

上記のような脆弱性をテストするために、 2 種類の Burp プラグインが用意されている。

* [JSON Web Token Attacker](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61)
* [JSON Web Tokens](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)

また、その他の情報については、 [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) を必ず確認すること。


参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#dynamic-analysis-2)

### OAuth 2.0 のフローテスト
[OAuth 2.0 は、 API やウェブ対応アプリケーションのネットワーク上で認可の決定を伝えるための委任プロトコルを定義している。](https://oauth.net/articles/authentication/)ユーザ認証アプリケーションなど、さまざまなアプリケーションで使用されている。

OAuth2 の一般的な用途は以下の通りである。

* ユーザのアカウントを使用してオンラインサービスにアクセスする許可をユーザから取得する。
* ユーザに代わってオンラインサービスに対する認証を行う。
* 認証エラーの処理。

OAuth 2.0 によると、ユーザのリソースにアクセスしようとするモバイルクライアントは、まずユーザに認証サーバに対する認証を要求する必要がある。ユーザの承認後、認証サーバはユーザに代わってアプリが動作することを許可するトークンを発行する。 OAuth2 仕様では、特定の種類の認証やアクセストークンの形式は定義されていないことに注意する。

OAuth 2.0 では、 4 つの役割が定義されている。

* リソースオーナー：アカウントの所有者
* クライアント：アクセストークンを使ってユーザのアカウントにアクセスしようとするアプリケーション
* リソースサーバ：ユーザアカウントをホストする
* 認可サーバ：ユーザの身元を確認し、アプリケーションにアクセストークンを発行する

注：API はリソースオーナーと認可サーバの両方の役割を果たす。したがって、ここでは両方を API と呼ぶことにする。

<img src="images/0x05/MSTG-AUTH-3/abstract_oath2_flow.png" alt="抽象的なプロトコルのフロー" width="400px" />


図中の各ステップについて、以下でより[詳細に説明](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)する。<br>

1. アプリケーションは、サービス・リソースにアクセスするためのユーザ認証を要求する。
2. ユーザが要求を承認すると、アプリケーションは認証付与を受け取る。認可付与は、いくつかの形式（明示的、暗黙的など）を取ることができる。
3. アプリケーションは、認可サーバ（API）にアクセストークンを要求する際に、認証付与と一緒に自身の ID の認証を提示する。
4. アプリケーションの ID が認証され、認証付与が有効である場合、認可サーバ（ API ）はアプリケーションにアクセストークンを発行し、認可プロセスを完了する。アクセストークンには、リフレッシュトークンが付随している場合がある。
5. アプリケーションはリソースサーバ（ API ）にリソースを要求し、認証のためにアクセストークンを提示する。アクセストークンは、いくつかの方法で使用することができる（ベアラートークンなど）。
6. アクセストークンが有効であれば、リソースサーバ（ API ）はアプリケーションにリソースを提供する。

参考資料
* [owasp-mastg Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-oauth-20-flows-mstg-auth-1-and-mstg-auth-3)



### OAuth 2.0 のベストプラクティス
以下のベストプラクティスが守られていることを確認する。

ユーザエージェント
* ユーザは信頼を視覚的に確認する方法（例： TLS(Transport Layer Security) 確認、ウェブサイトの仕組み）を持つべきである。
* 中間者攻撃を防ぐために、クライアントはサーバの完全修飾ドメイン名を、接続確立時にサーバが提示した公開鍵で検証する必要がある。

付与の種類
* ネイティブアプリでは、暗黙的な付与ではなく、コード付与を使用する必要がある。
* コード付与を使用する場合、コード付与を保護するために PKCE ( Proof Key for Code Exchange ) を実装する必要があります。サーバ側でも実装されていることを確認する。
* 認可「コード」は有効期限が短く、受信後すぐに使用されるべきである。認可コードが一時的なメモリ上にのみ存在し、保存やログに記録されないことを確認する。

クライアントシークレット
* クライアントはなりすまされる可能性があるため、クライアントの ID を証明するために共有シークレットを使うべきではない（「 client_id 」がすでに証明の役目を果たしている）。もし、クライアントシークレットを使用する場合は、安全なローカルストレージに保存されていることを確認する。

エンドユーザの認証情報
* TLS などのトランスポート層方式でエンドユーザ認証情報の送信を保護する。

トークン
* アクセストークンは一時的なメモリに保存する。
* アクセストークンは、暗号化された接続で送信する必要がある。
* エンドツーエンドの機密性が保証されない場合や、トークンが機密情報や取引へのアクセスを提供する場合は、アクセストークンの範囲と期間を縮小する。
* アプリケーションがアクセストークンをベアラートークンとして使用し、クライアントを識別する他の方法がない場合、トークンを盗んだ攻撃者はそのスコープとそれに関連するすべてのリソースにアクセスできることに留意する。
* リフレッシュトークンは、安全なローカルストレージに保管する。

参考資料
* [owasp-mastg Testing OAuth 2.0 Flows (MSTG-AUTH-1 and MSTG-AUTH-3) OAUTH 2.0 Best Practices](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#oauth-20-best-practices)

ルールブック
* [OAuth 2.0 のベストプラクティスの遵守（必須）](#oauth-20-のベストプラクティスの遵守必須)

#### 外部ユーザエージェントと組み込みユーザエージェント
OAuth2 認証は、外部のユーザエージェント（ Chrome や Safari など）を介して行うことも、アプリ自体（アプリに埋め込まれた WebView や認証ライブラリなど）を介して行うこともできる。どちらのモードが本質的に「優れている」ということはなく、どのモードを選択するかはコンテキストに依存する。

外部ユーザエージェントを使用する方法は、ソーシャルメディアアカウント（ Facebook 、 Twitter など）と対話する必要があるアプリケーションで選択される方法である。この方法のメリットは以下の通りである。

* ユーザの認証情報は、決してアプリに直接公開されることはない。このため、ログイン時にアプリが認証情報を取得することはできない（「認証情報のフィッシング」）。

* アプリ自体に認証ロジックをほとんど追加する必要がないため、コーディングミスを防ぐことができる。

マイナス面としては、ブラウザの動作を制御する方法（証明書のピン留めを有効にする等）がないことである。

閉じたエコシステムの中で動作するアプリの場合、埋め込み認証の方が良い選択となる。例えば、 OAuth2 を使って銀行の認証サーバからアクセストークンを取得し、そのアクセストークンを使って多くのマイクロサービスにアクセスする銀行アプリを考える。この場合、クレデンシャルフィッシングは実行可能なシナリオではない。認証プロセスは、外部のコンポーネントを信頼するのではなく、（できれば）慎重に保護されたバンキングアプリの中で行うことが望ましい。

参考資料
* [owasp-mastg Testing OAuth 2.0 Flows (MSTG-AUTH-1 and MSTG-AUTH-3) External User Agent vs. Embedded User Agent](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#external-user-agent-vs-embedded-user-agent)

ルールブック
* [OAuth2 認証で使用される主な推奨ライブラリ（推奨）](#oauth2-認証で使用される主な推奨ライブラリ推奨)
* [OAuth2 認証で外部ユーザエージェントを使用する場合はメリット、デメリットを理解して使用する（推奨）](#oauth2-認証で外部ユーザエージェントを使用する場合はメリットデメリットを理解して使用する推奨)

### その他の OAuth 2.0 のベストプラクティス
その他のベストプラクティスや詳細情報については、以下のソースドキュメントを参照する。

* [RFC6749 - The OAuth 2.0 Authorization Framework (October 2012)](https://www.rfc-editor.org/rfc/rfc6749)
* [RFC8252 - OAuth 2.0 for Native Apps (October 2017)](https://www.rfc-editor.org/rfc/rfc8252)
* [RFC6819 - OAuth 2.0 Threat Model and Security Considerations (January 2013)](https://www.rfc-editor.org/rfc/rfc6819)

参考資料
* [owasp-mastg Testing OAuth 2.0 Flows (MSTG-AUTH-1 and MSTG-AUTH-3) Other OAuth2 Best Practices](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#other-oauth2-best-practices)

### ルールブック
1. [使用している JWT ライブラリの特定及び既知の脆弱性があるかどうかを確認する（必須）](#使用している-jwt-ライブラリの特定及び既知の脆弱性があるかどうかを確認する必須)
1. [トークンは、 Keychain (iOS) により、モバイルデバイス上に安全に保管されていることを確認する（必須）](#トークンは-keychain-ios-によりモバイルデバイス上に安全に保管されていることを確認する必須)
1. [期待するハッシュアルゴリズムを要求する必要がある（必須）](#期待するハッシュアルゴリズムを要求する必要がある必須)
1. [リフレッシュトークンの有効期限に適切な期間を設定する（必須）](#リフレッシュトークンの有効期限に適切な期間を設定する必須)
1. [OAuth 2.0 のベストプラクティスの遵守（必須）](#oauth-20-のベストプラクティスの遵守必須)
1. [OAuth2 認証で使用される主な推奨ライブラリ（推奨）](#oauth2-認証で使用される主な推奨ライブラリ推奨)
1. [OAuth2 認証で外部ユーザエージェントを使用する場合はメリット、デメリットを理解して使用する（推奨）](#oauth2-認証で外部ユーザエージェントを使用する場合はメリットデメリットを理解して使用する推奨)

#### 使用している JWT ライブラリの特定及び既知の脆弱性があるかどうかを確認する（必須）

以下の内容を確認して、脆弱性があるか確認する必要がある。

* 使用している JWT ライブラリを特定し、既知の脆弱性があるかどうかを確認する。
* トークンを含むすべての受信要求について、 HMAC が検証されることを確認する。
* 秘密署名鍵または HMAC 秘密鍵の場所を確認する。キーはサーバに保管し、決してクライアントと共有してはならない。発行者と検証者のみが利用可能であるべきである。
* JWT に個人を特定できる情報のような機密データが埋め込まれていないことを確認する。何らかの理由でトークン内にそのような情報を送信する必要があるアーキテクチャの場合、ペイロードの暗号化が適用されていることを確認する。 [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) にある Java 実装のサンプルを参照する。
* JWT に一意な識別子を与える jti ( JWT ID ) クレームでリプレイ攻撃に対処していることを確認する。
* クロスサービスリレー攻撃には、トークンがどのアプリケーションのためのものかを定義する aud ( audience ) クレームで対処していることを確認する。
* トークンは、 Keychain (iOS) により、モバイルデバイス上に安全に保管されていることを確認する。

以下サンプルコードは、 Keychain からトークンを検索し、トークンが Keychain に存在しない場合は Keychain へ保存する処理の一例。<br>

```swift
import Foundation

class Keychain {

    let group: String = "group_1" // グループ
    var id: String = "id"

    let backgroundQueue = DispatchQueue.global(qos: .userInitiated)

    func addKeychain(token: Data) {

        // API　を実行する際の引数設定
        let dic: [String: Any] = [kSecClass as String: kSecClassGenericPassword, // クラス：パスワードクラス
            kSecAttrGeneric as String: group,                // 自由項目
            kSecAttrAccount as String: id,                 // アカウント（ログインID）
            kSecValueData as String: token,                // パスワードなどの保存情報
            kSecAttrService as String: "key"]            // サービス名

        // 検索用の　Dictionary
        let search: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                     kSecAttrService as String: "key",
                                     kSecReturnAttributes as String: kCFBooleanTrue as Any,
                                     kSecMatchLimit as String: kSecMatchLimitOne]as [String : Any]

        // keychain からトークンを検索
        findKeychainItem(attributes: search as CFDictionary, { status, item in
            switch status {
                case errSecItemNotFound: // keychain　にトークンが存在しない
                    // keychain に保存
                    _ = SecItemAdd(dic as CFDictionary, nil)
                default:
                    break
            }
        })

    }

    /// keychainからアイテムが存在するかを検索する
    /// - Parameters:
    ///   - attrs: 検索用のトークン
    ///   - completion: 検索結果
    func findKeychainItem(attributes attrs: CFDictionary, _ completion: @escaping (OSStatus, CFTypeRef?) -> Void) {

        // 呼び出しスレッドをブロックするため、メイン スレッドから呼び出された場合にアプリの UI がハングする可能性がある。
        // 別スレッドで実行することを推奨。
        backgroundQueue.async {
            var item: CFTypeRef?
            let result = SecItemCopyMatching(attrs, &item)
            completion(result, item)
        }
    }

}
```

これに違反する場合、以下の可能性がある。
* 使用する JWT ライブラリに関する脆弱性を悪用される。

#### トークンは、 Keychain (iOS) により、モバイルデバイス上に安全に保管されていることを確認する（必須）
トークンは Keychain によりモバイルデバイス上に安全に保管する必要がある。これを怠った場合、第三者によるトークンを利用したサーバ認証が可能になる恐れがある。

Keychain の使用方法は以下ルールを参照する。

データストレージとプライバシー要件ルールブック
* [Keychain Services API を使用してセキュアに値を保存する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#keychain-services-api-を使用してセキュアに値を保存する必須)

これに違反する場合、以下の可能性がある。
* 第三者によるトークンを利用したサーバ認証が可能になる

#### 期待するハッシュアルゴリズムを要求する必要がある（必須）
攻撃者はトークンを変更し、「 none 」キーワードを使って署名アルゴリズムを変更し、トークンの完全性がすでに検証されていることを示す場合がある。以下は JWTDecode.swift を使って JWT をデコードする実装である。

```swift
import JWTDecode

class JWTSample {
    func jwtSample() {
        // JWT
        let jwtText = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        // ヘッダー、ボディの値を取り出す
        guard let jwt = try? decode(jwt: jwtText),
              let algorithm = jwt.header["alg"],
              let type = jwt.header["typ"],
              let subject = jwt.body["sub"] as? String,
              let name = jwt.body["name"] as? String,
              let issuedAt = jwt.body["iat"] as? Int else {
            return
        }
    }
}
```

Podfile:
```default
# Uncomment the next line to define a global platform for your project
# platform :ios, '9.0'

target 'SampleApp' do
  # Comment the next line if you don't want to use dynamic frameworks
  use_frameworks!

  # Pods for SampleApp

  target 'SampleAppTests' do
    # Pods for testing
  end

  pod 'JWTDecode'

end
```

これに違反する場合、以下の可能性がある。
* 「 none 」アルゴリズムで署名されたトークンを、検証済みの署名を持つ有効なトークンであるかのように扱い、アプリケーションは変更されたトークンの要求を信頼する可能性がある。

#### リフレッシュトークンの有効期限に適切な期間を設定する（必須）

リフレッシュトークンの有効期限が適切な期間であることを確認する必要がある。リフレッシュトークンの有効期限内の場合は、新しいアクセストークンの発行をし、有効期限外の場合は、アクセスを拒否してユーザに再ログインを促す必要性がある。

これに違反する場合、以下の可能性がある。
* 有効期限が不適切な場合はログインユーザを第三者が利用できる可能性がある。

#### OAuth 2.0 のベストプラクティスの遵守（必須）
以下の OAuth 2.0 のベストプラクティスを遵守すること。

**ユーザエージェント**
* ユーザは信頼を視覚的に確認する方法（例： TLS(Transport Layer Security) 確認、ウェブサイトの仕組み）を持つべきである。
* 中間者攻撃を防ぐために、クライアントはサーバの完全修飾ドメイン名を、接続確立時にサーバが提示した公開鍵で検証する必要がある。

**付与の種類**
* ネイティブアプリでは、暗黙的な付与ではなく、コード付与を使用する必要がある。
* コード付与を使用する場合、コード付与を保護するために PKCE ( Proof Key for Code Exchange ) を実装する必要があります。サーバ側でも実装されていることを確認する。
* 認可「コード」は有効期限が短く、受信後すぐに使用されるべきである。認可コードが一時的なメモリ上にのみ存在し、保存やログに記録されないことを確認する。

**クライアントシークレット**
* クライアントはなりすまされる可能性があるため、クライアントの ID を証明するために共有シークレットを使うべきではない（「 client_id 」がすでに証明の役目を果たしている）。もし、クライアントシークレットを使用する場合は、安全なローカルストレージに保存されていることを確認する。

**エンドユーザの認証情報**
* TLS などのトランスポート層方式でエンドユーザ認証情報の送信を保護する。

**トークン**
* アクセストークンは一時的なメモリに保存する。
* アクセストークンは、暗号化された接続で送信する必要がある。
* エンドツーエンドの機密性が保証されない場合や、トークンが機密情報や取引へのアクセスを提供する場合は、アクセストークンの範囲と期間を縮小する。
* アプリケーションがアクセストークンをベアラートークンとして使用し、クライアントを識別する他の方法がない場合、トークンを盗んだ攻撃者はそのスコープとそれに関連するすべてのリソースにアクセスできることに留意する。
* リフレッシュトークンは、安全なローカルストレージに保管する。

これに違反する場合、以下の可能性がある。
* 脆弱な OAuth 2.0 の実装となる可能性がある。

#### OAuth2 認証で使用される主な推奨ライブラリ（推奨）
OAuth2 認証の実装を独自開発しないことが重要となる。  
OAuth2 認証を実現するために利用されるライブラリは主に以下である。
* GTMAppAuth ( Google )

gtm-oauth2 ( Google ) は現在非推奨となっている。代替に [GTMAppAuth](https://github.com/google/GTMAppAuth) ( Google ) を使用となる。

Podfile の指定:
```default
platform :ios, '10.0'

target 'helloworld' do
  use_frameworks!
  project 'helloworld'

  # In production, you would use:
  pod 'GTMAppAuth', '~> 2.0'

  pod 'AppAuth', '~> 1.0'
  pod 'GTMSessionFetcher/Core', '>= 1.0', '< 4.0'
end
```

**認証フロー**

認可リクエストを開始するには authStateByPresentingAuthorizationRequest 関数を使用する。この関数内で OAuth トークンの交換が自動的に実行され、すべてが PKCE で保護される動作となる。 (サーバサポートしている場合)。
この関数の戻り値で OIDExternalUserAgentSession インスタンスを取得する。

認証フローではカスタム URL スキーマで承認用のリダイレクト URI ( 認証応答 URL )が渡ってくる。
認証フロー中で取得した OIDExternalUserAgentSession インスタンスに 認証応答 URL を設定する必要がある。

以下サンプルコードは、 gtm-oauth2 での OAuth2 認証の一例。
```objectivec
- (IBAction)authWithAutoCodeExchange:(nullable id)sender {
  NSURL *issuer = [NSURL URLWithString:kIssuer];
  NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];

  // discovers endpoints
  [OIDAuthorizationService discoverServiceConfigurationForIssuer:issuer
      completion:^(OIDServiceConfiguration *_Nullable configuration, NSError *_Nullable error) {

    if (!configuration) {
      [self setGtmAuthorization:nil];
      return;
    }

    // builds authentication request
    OIDAuthorizationRequest *request =
        [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                      clientId:kClientID
                                                        scopes:@[OIDScopeOpenID, OIDScopeProfile]
                                                   redirectURL:redirectURI
                                                  responseType:OIDResponseTypeCode
                                          additionalParameters:nil];
    // performs authentication request
    AppDelegate *appDelegate = (AppDelegate *)[UIApplication sharedApplication].delegate;

    appDelegate.currentAuthorizationFlow =
        [OIDAuthState authStateByPresentingAuthorizationRequest:request
            presentingViewController:self
                            callback:^(OIDAuthState *_Nullable authState,
                                       NSError *_Nullable error) {
      if (authState) {
        GTMAppAuthFetcherAuthorization *authorization =
          [[GTMAppAuthFetcherAuthorization alloc] initWithAuthState:authState];

        [self setGtmAuthorization:authorization];
        [self logMessage:@"Got authorization tokens. Access token: %@",
                         authState.lastTokenResponse.accessToken];
      } else {
        [self setGtmAuthorization:nil];
        [self logMessage:@"Authorization error: %@", [error localizedDescription]];
      }
    }];
  }];
}


// AppDelegate
- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<NSString *, id> *)options {
  // Sends the URL to the current authorization flow (if any) which will process it if it relates to
  // an authorization response.
  if ([_currentAuthorizationFlow resumeExternalUserAgentFlowWithURL:url]) {
    _currentAuthorizationFlow = nil;
    return YES;
  }

  // Your additional URL handling (if any) goes here.

  return NO;
}
```

**authorization インスタンスの Keychain 保存**

GTMAppAuthFetcherAuthorization 含まれている機能を使用して、OIDExternalUserAgentSession インスタンスを Keychain に簡単に保存できる
保存したインスタンスをリストアすることも簡単にできる。

Keychain の保存と削除:
```objectivec
- (void)saveState {
    
    if (_authorization.canAuthorize) {
        // save
        [GTMAppAuthFetcherAuthorization saveAuthorization:_authorization toKeychainForName:kAuthorizerKey];

    } else {
        // remove
        [GTMAppAuthFetcherAuthorization removeAuthorizationFromKeychainForName:kAuthorizerKey];

    }

}
```

Keychain から読み込み:
```objectivec
- (void)loadState {
 
    // Restore from Keychain
    GTMAppAuthFetcherAuthorization *authorization = [GTMAppAuthFetcherAuthorization authorizationFromKeychainForName:kAuthorizerKey];
    [self setGtmAuthorization:authorization];
}
```

**実装全体の例**

AppDelegate.h:
```objectivec
#import <UIKit/UIKit.h>

@protocol OIDExternalUserAgentSession;

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property(nonatomic, strong, nullable) id<OIDExternalUserAgentSession> currentAuthorizationFlow;

@end
```

AppDelegate.m:
```objectivec
#import "AppDelegate.h"

@import AppAuth;

#import "GTMAppAuthExampleViewController.h"

@implementation AppDelegate

@synthesize window = _window;

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  UIWindow *window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
  UIViewController *mainViewController =
      [[GTMAppAuthExampleViewController alloc] init];
  window.rootViewController = mainViewController;

  _window = window;
  [_window makeKeyAndVisible];

  return YES;
}

- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<NSString *, id> *)options {
  // Sends the URL to the current authorization flow (if any) which will process it if it relates to
  // an authorization response.
  if ([_currentAuthorizationFlow resumeExternalUserAgentFlowWithURL:url]) {
    _currentAuthorizationFlow = nil;
    return YES;
  }

  // Your additional URL handling (if any) goes here.

  return NO;
}

- (BOOL)application:(UIApplication *)application
              openURL:(NSURL *)url
    sourceApplication:(NSString *)sourceApplication
           annotation:(id)annotation {
    
  return [self application:application
                   openURL:url
                   options:@{}];
}

@end
```

GTMAppAuthExampleViewController.h:
```objectivec
#import <UIKit/UIKit.h>

@class OIDAuthState;
@class GTMAppAuthFetcherAuthorization;
@class OIDServiceConfiguration;

NS_ASSUME_NONNULL_BEGIN

/*! @brief The example application's view controller.
 */
@interface GTMAppAuthExampleViewController : UIViewController

/*! @brief The authorization state.
 */
@property(nonatomic, nullable) GTMAppAuthFetcherAuthorization *authorization;

- (IBAction)authWithAutoCodeExchange:(nullable id)sender;

- (IBAction)userinfo:(nullable id)sender;

- (IBAction)clearAuthState:(nullable id)sender;


@end

NS_ASSUME_NONNULL_END
```

GTMAppAuthExampleViewController.m
```objectivec
#import "GTMAppAuthExampleViewController.h"
#import <QuartzCore/QuartzCore.h>

@import AppAuth;
@import GTMSessionFetcher;
@import GTMAppAuth;

#import "AppDelegate.h"

static NSString *const kIssuer = @"https://accounts.google.com";

static NSString *const kClientID = @"xxxxx.apps.googleusercontent.com";


static NSString *const kRedirectURI =
    @"com.googleusercontent.apps.YOUR_CLIENT:/oauthredirect";

static NSString *const kAuthorizerKey = @"authorizationkey";

@interface GTMAppAuthExampleViewController () <OIDAuthStateChangeDelegate,
                                               OIDAuthStateErrorDelegate>
@end

@implementation GTMAppAuthExampleViewController

- (void)viewDidLoad {
  [super viewDidLoad];

  [self loadState];
}


- (void)saveState {
    
  if (_authorization.canAuthorize) {
      [GTMAppAuthFetcherAuthorization saveAuthorization:_authorization toKeychainForName:kAuthorizerKey];

  } else {
      [GTMAppAuthFetcherAuthorization removeAuthorizationFromKeychainForName:kAuthorizerKey];

  }

}

- (void)loadState {
 
    // Restore from Keychain
    GTMAppAuthFetcherAuthorization *authorization = [GTMAppAuthFetcherAuthorization authorizationFromKeychainForName:kAuthorizerKey];
    [self setGtmAuthorization:authorization];
}

- (void)setGtmAuthorization:(GTMAppAuthFetcherAuthorization*)authorization {
    if ([_authorization isEqual:authorization]) {
        return;
    }
    
    _authorization = authorization;
    [self stateChanged];
}

- (void)stateChanged {
  [self saveState];
}

- (void)didChangeState:(OIDAuthState *)state {
  [self stateChanged];
}

- (void)authState:(OIDAuthState *)state didEncounterAuthorizationError:(NSError *)error {
    // error
}

- (IBAction)authWithAutoCodeExchange:(nullable id)sender {
  NSURL *issuer = [NSURL URLWithString:kIssuer];
  NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];

  // discovers endpoints
  [OIDAuthorizationService discoverServiceConfigurationForIssuer:issuer
      completion:^(OIDServiceConfiguration *_Nullable configuration, NSError *_Nullable error) {

    if (!configuration) {
      [self setGtmAuthorization:nil];
      return;
    }

    // builds authentication request
    OIDAuthorizationRequest *request =
        [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                      clientId:kClientID
                                                        scopes:@[OIDScopeOpenID, OIDScopeProfile]
                                                   redirectURL:redirectURI
                                                  responseType:OIDResponseTypeCode
                                          additionalParameters:nil];
    // performs authentication request
    AppDelegate *appDelegate = (AppDelegate *)[UIApplication sharedApplication].delegate;

    appDelegate.currentAuthorizationFlow =
        [OIDAuthState authStateByPresentingAuthorizationRequest:request
            presentingViewController:self
                            callback:^(OIDAuthState *_Nullable authState,
                                       NSError *_Nullable error) {
      if (authState) {
        GTMAppAuthFetcherAuthorization *authorization =
          [[GTMAppAuthFetcherAuthorization alloc] initWithAuthState:authState];

        [self setGtmAuthorization:authorization];
        [self logMessage:@"Got authorization tokens. Access token: %@",
                         authState.lastTokenResponse.accessToken];
      } else {
        [self setGtmAuthorization:nil];
        [self logMessage:@"Authorization error: %@", [error localizedDescription]];
      }
    }];
  }];
}

- (IBAction)clearAuthState:(nullable id)sender {
  [self setGtmAuthorization:nil];
}

- (IBAction)userinfo:(nullable id)sender {
  [self logMessage:@"Performing userinfo request"];

  GTMSessionFetcherService *fetcherService = [[GTMSessionFetcherService alloc] init];
  fetcherService.authorizer = self.authorization;

  // Creates a fetcher for the API call.
  NSURL *userinfoEndpoint = [NSURL URLWithString:@"https://www.googleapis.com/oauth2/v3/userinfo"];
  GTMSessionFetcher *fetcher = [fetcherService fetcherWithURL:userinfoEndpoint];
  [fetcher beginFetchWithCompletionHandler:^(NSData *data, NSError *error) {
      
    // Checks for an error.
    if (error) {
        
      // OIDOAuthTokenErrorDomain indicates an issue with the authorization.
      if ([error.domain isEqual:OIDOAuthTokenErrorDomain]) {
        [self setGtmAuthorization:nil];
        [self logMessage:@"Authorization error during token refresh, clearing state. %@", error];
      // Other errors are assumed transient.
      } else {
        [self logMessage:@"Transient error during token refresh. %@", error];
      }
      return;
    }

    // Parses the JSON response.
    NSError *jsonError = nil;
    id jsonDictionaryOrArray =
        [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];

    // JSON error.
    if (jsonError) {
      [self logMessage:@"JSON decoding error %@", jsonError];
      return;
    }

    // Success response!
    [self logMessage:@"Success: %@", jsonDictionaryOrArray];
  }];
}


- (void)logMessage:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2) {
  // gets message as string
  va_list argp;
  va_start(argp, format);
  NSString *log = [[NSString alloc] initWithFormat:format arguments:argp];
  va_end(argp);

  // outputs to stdout
  NSLog(@"%@", log);
}

@end
```

これに注意しない場合、以下の可能性がある。
* 脆弱な OAuth 2.0 の実装となる可能性がある。

#### OAuth2 認証で外部ユーザエージェントを使用する場合はメリット、デメリットを理解して使用する（推奨）

OAuth2 認証は、外部のユーザエージェント（ Chrome や Safari など）を介して行うことできる。
外部ユーザエージェントを利用時のメリット、デメリットは以下である。

**メリット**
* ユーザの認証情報は、決してアプリに直接公開されることはない。このため、ログイン時にアプリが認証情報を取得することはできない（「認証情報のフィッシング」）。

* アプリ自体に認証ロジックをほとんど追加する必要がないため、コーディングミスを防ぐことができる。

**デメリット**
* ブラウザの動作を制御する方法（証明書のピン留めを有効にする等）がない。

これに注意しない場合、以下の可能性がある。
* 証明書のピン留めを有効にする必要がある際に、利用することができない。

## MSTG-AUTH-4
ユーザがログアウトする際に、リモートエンドポイントは既存のセッションを終了している。

### リモートセッション情報の破棄
このテストケースの目的は、ログアウト機能を検証し、それがクライアントとサーバの両方で効果的にセッションを終了させ、ステートレストークンを無効にするかどうかを判断することである。

サーバ側セッションの破棄に失敗することは、ログアウト機能の実装で最もよくあるエラーの一つである。このエラーは、ユーザがアプリケーションからログアウトした後も、セッションやトークンを保持し続ける。有効な認証情報を取得した攻撃者は、その情報を使い続け、ユーザのアカウントを乗っ取ることが可能である。

多くのモバイルアプリは、ユーザを自動的にログアウトさせない。顧客にとって不便だから、あるいはステートレス認証の実装時に決定されたからなど、さまざまな理由が考えられる。しかし、アプリケーションにはログアウト機能が必要であり、ベストプラクティスに従って実装し、ローカルに保存されたトークンやセッション識別子をすべて破棄する必要がある。セッション情報がサーバに保存されている場合、そのサーバにログアウト要求を送信することによっても破棄されなければならない。リスクの高いアプリケーションの場合、トークンを無効にする必要がある。トークンやセッション識別子を破棄しないと、トークンが流出した場合にアプリケーションに不正にアクセスされる可能性がある。なお、適切に消去されない情報は、デバイスのバックアップ時など、後で流出する可能性があるため、他の機密情報も同様に破棄する必要がある。

### 静的解析
サーバコードが利用可能な場合は、ログアウト機能によってセッションが正しく終了することを確認する。この検証は、テクノロジーによって異なる。以下は、サーバ側のログアウトが正しく行われるためのセッション終了の様々な例である。

* [Spring (Java)](https://docs.spring.io/spring-security/site/docs/4.1.x/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html)
* [Ruby on Rails](https://guides.rubyonrails.org/security.html)
* [PHP](https://www.php.net/manual/en/function.session-destroy.php)

ステートレス認証でアクセストークンやリフレッシュトークンを使用する場合は、モバイルデバイスから破棄する必要がある。[リフレッシュトークンはサーバ上で無効化する必要がある](https://auth0.com/blog/denylist-json-web-token-api-keys/)。


### 動的解析
動的アプリケーション解析用のインターセプションプロキシを使用し、以下の手順を実行して、ログアウトが正しく実装されているかどうかを確認する。

1. アプリケーションにログインする。
2. 認証を必要とするリソースにアクセスする。通常は、アカウントに属する個人情報の要求である。
3. アプリケーションからログアウトする。
4. 手順 2 の要求を再送信して、再度データにアクセスする。

サーバ上でログアウトが正しく実装されている場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに返される。一方、手順 2 で得たのと同じレスポンスを受け取る場合、トークンあるいはセッション ID はまだ有効で、サーバ上で正しく終了していない。OWASP ウェブテストガイド ( [WSTG-SESS-06](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality ) には、詳しい説明とより多くのテストケースが含まれている。

参考資料
* [owasp-mastg Testing User Logout (MSTG-AUTH-4)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-user-logout-mstg-auth-4)

ルールブック
* [アプリにログイン機能が存在する場合のリモートセッション情報の破棄のベストプラクティス（推奨）](#アプリにログイン機能が存在する場合のリモートセッション情報の破棄のベストプラクティス推奨)

### ルールブック
1. [アプリにログイン機能が存在する場合のリモートセッション情報の破棄のベストプラクティス（推奨）](#アプリにログイン機能が存在する場合のリモートセッション情報の破棄のベストプラクティス推奨)

#### アプリにログイン機能が存在する場合のリモートセッション情報の破棄のベストプラクティス（推奨）

アプリにログイン機能が存在する場合、以下のベストプラクティスに従いリモートセッション情報を破棄する。
* アプリケーションにログアウト機能を用意する。
* ログアウト時にローカルに保存されたトークンやセッション識別子をすべて破棄する。
* セッション情報がサーバに保存されている場合、サーバにログアウト要求を送信して破棄する。
* リスクの高いアプリの場合、トークンを無効にする。

トークンやセッション識別子を破棄しないと、トークンが流出した場合にアプリケーションに不正にアクセスされる可能性がある。
破棄されない情報は、デバイスのバックアップ時など、後で流出する可能性があるため、他の機密情報も同様に破棄する必要がある。

これに注意しない場合、以下の可能性がある。
* ログイン情報がメモリ内に残り、第三者に利用される。

## MSTG-AUTH-5

パスワードポリシーが存在し、リモートエンドポイントで実施されている。

### パスワードポリシー遵守

パスワードの強度は、認証にパスワードが使用される場合の重要な懸念事項である。パスワードポリシーは、エンドユーザが遵守すべき要件を定義するものである。パスワードポリシーは通常、パスワードの長さ、パスワードの複雑さ、およびパスワードのトポロジーを指定する。「強力な」パスワードポリシーは、手動または自動によるパスワードクラッキングを困難または不可能にする。以下のセクションでは、パスワードのベストプラクティスに関するさまざまな領域をカバーする。より詳細な情報は、 [OWASP Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls) を参照する。

参考資料
* [owasp-mastg Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-best-practices-for-passwords-mstg-auth-5-and-mstg-auth-6)

### 静的解析

パスワードポリシーの存在を確認し、長さと無制限の文字セットに焦点を当てた [OWASP Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls) に従って、実装されたパスワードの複雑さの要件を検証すること。ソースコードに含まれるパスワード関連の関数をすべて特定し、それぞれで検証チェックが行われていることを確認する。パスワード検証機能を確認し、パスワードポリシーに違反するパスワードが拒否されることを確認する。

参考資料
* [owasp-mastg Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#static-analysis)

ルールブック
* [「強力な」パスワードポリシー（推奨）](#強力なパスワードポリシー推奨)

#### zxcvbn

[zxcvbn](https://github.com/dropbox/zxcvbn) は、パスワードクラッカーにヒントを得て、パスワードの強度を推定するために使用できる一般的なライブラリである。 JavaScript で利用可能であるが、サーバ側では他の多くのプログラミング言語でも利用可能である。インストール方法は様々なので、 Github のリポジトリを確認する。インストールすると、 zxcvbn を使って、パスワードの複雑さと解読に必要な推測回数を計算することができる。


HTML ページに zxcvbn JavaScript ライブラリを追加した後、ブラウザのコンソールで zxcvbn コマンドを実行すると、スコアを含むパスワードのクラックの可能性に関する詳細情報を取得できる。

<img src="images/0x05/MSTG-AUTH-5/zxcvbn.png" alt="zxcvbn コマンド例" width="100%" />

スコアは以下のように定義され、例えばパスワードの強度バーに使用することができる。

```html
0 # too guessable: risky password. (guesses < 10^3)

1 # very guessable: protection from throttled online attacks. (guesses < 10^6)

2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)

3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)

4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
```

なお、 zxcvbn はアプリ開発者が Java（または他の）実装を使って実装することもでき、ユーザに強力なパスワードを作成するように導くことができる。


参考資料
* [owasp-mastg Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6) zxcvbn](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#zxcvbn)

### Have I Been Pwned : PwnedPasswords

一要素認証スキーム（パスワードのみなど）に対する辞書攻撃の成功の可能性をさらに低くするために、パスワードがデータ漏洩で流出したかどうかを検証することができる。これは、 Troy Hunt 氏による Pwned Passwords API をベースにしたサービス（ api.pwnedpasswords.com で入手可能）を使って行うことができる。例えば、コンパニオンウェブサイトの「 [Have I been pwned ?](https://haveibeenpwned.com/)  」である。この API は、パスワード候補の SHA-1 ハッシュをもとに、指定されたパスワードのハッシュが、このサービスが収集したさまざまなデータ漏洩の事例の中で見つかった回数を返す。
ワークフローは以下のステップを実行する。

* ユーザ入力を UTF-8 にエンコードする。 ( 例：the password test )
* ステップ 1 の結果の SHA-1 ハッシュを取得する。（ 例： test のハッシュは A94A8FE5CC... ）
* 最初の 5 文字（ハッシュプレフィックス）をコピーし、次の API を用いて範囲検索に使用する： http GET https://api.pwnedpasswords.com/range/A94A8
* 結果を繰り返し、ハッシュの残りを探す。（たとえば、 FE5CC... が返されたリストの一部であるかどうか）もしそれが返されたリストの一部でなければ、与えられたハッシュのパスワードは見つからない。そうでなければ、 FE5CC... のように、それが違反で見つかった回数を示すカウンターを返す。（例： FE5CC... ： 76479 ）

Pwned Passwords APIに関する詳細なドキュメントは、[オンライン](https://haveibeenpwned.com/API/v3)で確認できる。

なお、この API は、ユーザが登録やパスワードの入力を行う際に、推奨パスワードかどうかを確認するために、アプリ開発者が使用するのが最適である。


参考資料
* [owasp-mastg Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6) Have I Been Pwned: PwnedPasswords](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#have-i-been-pwned-pwnedpasswords)

ルールブック
* [推奨パスワードかの確認（推奨）](#推奨パスワードかの確認推奨)

#### ログイン制限

スロットリングの手順をソースコードで確認する：

指定されたユーザ名で短時間にログインを試行した場合のカウンタと、最大試行回数に達した後にログインを試行しない方法を提供する。認証されたログイン試行後は、エラーカウンターをリセットすること。


ブルートフォース対策として、以下のベストプラクティスを遵守する。

* ログインに数回失敗したら、対象のアカウントをロックし（一時的または恒久的に）、それ以降のログイン試行を拒否すべき。
* 一時的なアカウントロックには、 5 分間のアカウントロックが一般的に使用される。
* クライアント側の制御は簡単にバイパスされるため、制御はサーバ上で行う必要がある。
* 不正なログインの試行は、特定のセッションではなく、対象となるアカウントについて集計する必要がある。

その他のブルートフォース軽減技術については、 OWASP の[ブルートフォース攻撃の阻止](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)のページに記載されている。


参考資料
* [owasp-mastg Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6) Login Throttling](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#login-throttling)

ルールブック
* [ブルートフォース対策として、以下のベストプラクティスを遵守する（必須）](#ブルートフォース対策として以下のベストプラクティスを遵守する必須)

### ルールブック
1. [「強力な」パスワードポリシー（推奨）](#強力なパスワードポリシー推奨)
1. [推奨パスワードかの確認（推奨）](#推奨パスワードかの確認推奨)
1. [ブルートフォース対策として、以下のベストプラクティスを遵守する（必須）](#ブルートフォース対策として以下のベストプラクティスを遵守する必須)

#### 「強力な」パスワードポリシー（推奨）

以下は「強力な」パスワードを設定するためのポリシーの一例である。

* パスワードの長さ
  * 最小： 8 文字未満のパスワードは脆弱であると見なされる。
  * 最大：一般的な最大長は 64 文字である。 long password Denial of Service attacks による攻撃を防ぐために最大長を設定することは必要である。
* パスワードをユーザに通知なしで切り捨てない。
* パスワードの構成規則<br>Unicode と空白を含むすべての文字の使用を許可する。
* 資格情報のローテーション<br>パスワードの漏洩が発生、または特定されたときに資格情報のローテーションを行う必要がある。
* パスワード強度メーター<br>ユーザが複雑なパスワードを作成する、過去に特定されたパスワードの設定をブロックするためにパスワード強度メーターを用意する。

以下サンプルコードは、 iOS アプリで対応すべき最大入力制限と、バリデーションチェックの処理の一例。<br>

**最大入力制限**

```swift
import UIKit

class ClassSample {
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {

        if let text = textField.text,
           let textRange = Range(range, in: text) {
            let updatedText = text.replacingCharacters(in: textRange,with: string)
            if updatedText.count > 64{
                return false
            }
        }
        return true
    }
}
```

**バリデーションチェック**

```swift
import Foundation

class ValidateSample {
    func validate(text: String, with regex: String) -> Bool {
            // 長さチェック
            if text.count <= 64 || text.count >= 8 {
                return true
            }
            return false
    }
}
```

参考資料
* [OWASP CheatSheetSeries Implement Proper Password Strength Controls](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls)

これに注意しない場合、以下の可能性がある。
* 脆弱なパスワードとなり予測される。

#### 推奨パスワードかの確認（推奨）
[Pwned Passwords API](https://haveibeenpwned.com/API/v3) を使用することで、ユーザが登録やパスワードの入力を行う際に、推奨パスワードかどうかを確認することができる。

これに注意しない場合、以下の可能性がある。
* 脆弱なパスワードとなり予測される。

#### ブルートフォース対策として、以下のベストプラクティスを遵守する（必須）
ブルートフォース対策として、以下のベストプラクティスを遵守する。

* ログインに数回失敗したら、対象のアカウントをロックし（一時的または恒久的に）、それ以降のログイン試行を拒否すべき。
* 一時的なアカウントロックには、 5 分間のアカウントロックが一般的に使用される。
* クライアント側の制御は簡単にバイパスされるため、制御はサーバ上で行う必要がある。
* 不正なログインの試行は、特定のセッションではなく、対象となるアカウントについて集計する必要がある。

その他のブルートフォース軽減技術については、 OWASP の[ブルートフォース攻撃の阻止](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)のページに記載されている。

※サーバ側のルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* ブルートフォース攻撃に脆弱になる。

## MSTG-AUTH-6
リモートエンドポイントは過度な資格情報の送信に対する保護を実装している。

<span style="color: red; ">※リモートサービス側での対応に関する章であるため、本資料ではガイド記載を省略</span>

参考資料
* [owasp-mastg Dynamic Testing (MSTG-AUTH-6)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#dynamic-testing-mstg-auth-6)

## MSTG-AUTH-7
事前に定義された非アクティブ期間およびアクセストークンの有効期限が切れた後に、セッションはリモートエンドポイントで無効にしている。

<span style="color: red; ">※リモートサービス側での対応に関する章であるため、本資料ではガイド記載を省略</span>

参考資料
* [owasp-mastg Testing Session Timeout (MSTG-AUTH-7)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#testing-session-timeout-mstg-auth-7)


## MSTG-AUTH-12
認可モデルはリモートエンドポイントで定義および実施されている。

<span style="color: red; ">※リモートサービス側での対応に関する章であるため、本資料ではガイド記載を省略</span>