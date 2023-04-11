# データストレージとプライバシー要件

## MSTG-STORAGE-1
個人識別情報、ユーザ資格情報、暗号化鍵などの機密データを格納するために、システムの資格情報保存機能を使用している。

### ハードウェア格納型 Android KeyStore

ハードウェア格納型 Android KeyStore は、Android の多層防御のセキュリティ概念に新たなレイヤーを提供する。
Keymaster Hardware Abstraction Layer(HAL) は、Android 6 (API level 23)で導入された。

アプリケーションは、キーがセキュリティハードウェアの内部に保存されているかどうかを確認することができる (KeyInfo.isinsideSecureHardware が true を返すかどうかをチェックすることで確認できる)。
Android 9 (API level 28) 以上のデバイスは StrongBoxKeymaster module を持つことができる。なお、 KeyInfo.isinsideSecureHardware は API level 31で廃止され、getSecurityLevelが推奨されている。

Android 9 (API level 28) 以降を実行しているデバイスは、StrongBox Keymaster モジュールを搭載できる。これは、独自の CPU 、Secure ストレージ、真の乱数ジェネレーター、パッケージ改ざんに対抗するメカニズムを持つハードウェアセキュリティモジュールに常駐する Keymaster HAL の実装である。
この機能を使用するには、Android Keystore を使用してキーを生成またはインポートする際に、KeyGenParameterSpec.Builder クラスまたは KeyProtection.Builder クラスの setIsStrongBoxBacked メソッドに true を渡す必要がある。

実行時に StrongBox が使われるようにするには、isInsideSecureHardware (現在は非推奨) が true を返し、システムが StrongBoxUnavailableException を throw しないことを確認する。
この Exception は StrongBox Keymaster が特定のアルゴリズムおよびキーに関連付けられたキーサイズで使用できない場合に throw される。
ハードウェアベースの KeyStore の機能説明は、 [AOSP](https://source.android.com/docs/security/keystore) のページにある。

Keymaster HAL は、Android Keystore が使用する Trusted Execution Environment(TEE) や Secure Element (SE)  といったハードウェアベースのコンポーネントへのインターフェースである。 [Titan M](https://android-developers.googleblog.com/2018/10/building-titan-better-security-through.html) は、そのようなハードウェアを搭載したコンポーネントの一例である。

参考資料
* [owasp-mastg Data Storage Methods Overview Hardware-backed Android KeyStore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#hardware-backed-android-keystore)

ルールブック
* [キーがセキュリティハードウェアの内部に保存されているかどうかを確認する（推奨）](#キーがセキュリティハードウェアの内部に保存されているかどうかを確認する推奨)
* [StrongBox の利用方法（推奨）](#strongbox-の利用方法推奨)

### キー認証

暗号プリミティブによる多要素認証、クライアント側での機密データの安全な保存など、ビジネスに不可欠な操作のために Android Keystore に大きく依存するアプリケーションの場合、 Android は Android Keystore を通じて管理される暗号材料のセキュリティを分析するのに役立つ [Key Attestation](https://developer.android.com/training/articles/security-key-attestation) の機能を提供する。<br>
Android 8.0 (API level 26) から、Google アプリの端末認証が必要な新しい端末（Android 7.0以上）には、キーの認証が必須となった。このようなデバイスは、 [Google Hardware Attestation Root 証明書](https://developer.android.com/training/articles/security-key-attestation#root_certificate)によって署名された認証キーが使用され、キー認証プロセスを通じて同じことを検証される。

キー認証の際、対称鍵のエイリアスを指定すると、その対称鍵のプロパティを検証するために使用できる証明書チェーンを得ることができる。このチェーンのルート証明書が [Google Hardware Attestation Root 証明書](https://developer.android.com/training/articles/security-key-attestation#root_certificate)で、ハードウェアへの対称鍵の保存に関するチェックが行われていれば、そのデバイスがハードウェアレベルのキー認証に対応しており、Google が安全であると考える hardware-backed keystore にキーがあることが保証される。あるいは、認証チェーンに他のルート証明書がある場合、Google はハードウェアのセキュリティについて主張しない。

キー認証プロセスはアプリケーション内に直接実装することもできるが、セキュリティ上の理由からサーバ側で実装することが推奨される。<br>
以下は、キー認証の安全な実装のためのハイレベルなガイドラインである。
* サーバは、CSPRNG（Cryptographically Secure Random Number Generator）を用いて乱数を安全に生成し、キー認証プロセスを開始する必要があり、同じものをチャレンジとしてユーザに送信する必要がある。
* クライアントは、サーバから受け取ったチャレンジで setAttestationChallenge API を呼び出し、KeyStore.getCertificateChain メソッドで証明書チェーンを取得する必要がある。
* 認証応答は検証のためにサーバに送信され、キー認証応答の検証のために以下のチェックが行われる必要がある。
  * ルートまでの証明書チェーンを検証し、有効性、完全性、信頼性などの証明書の sanity check を実行する。チェーン内の証明書がいずれも失効していないことを確認するために、Google が管理する[証明書失効ステータスリスト](https://developer.android.com/training/articles/security-key-attestation#root_certificat)を確認する。
  * ルート証明書が、認証プロセスを信頼できるようにする Google 認証ルートキーで署名されているかどうかを確認する。
  * 証明書チェーンの最初の要素に表示される[証明書拡張データ](https://developer.android.com/training/articles/security-key-attestation#certificate_schema)を抽出し、以下のチェックを実行する。
    * 認証チャレンジが、認証プロセスを開始する際にサーバで生成されたものと同じ値であることを確認する。
    * キー認証応答で署名を確認する。
    * デバイスに安全なキーの保存メカニズムがあるかどうかを判断するために、Keymaster のセキュリティレベルを確認する。Keymaster はセキュリティコンテキストで動作するソフトウェアの一部であり、すべての安全なキーストア操作を提供する。セキュリティレベルは Software, TrustedEnvironment, StrongBox のいずれかになる。セキュリティレベルが TrustedEnvironment あるいは StrongBox で、かつ証明書チェーンに Google 証明書ルートキーで署名されたルート証明書が含まれている場合、クライアントはハードウェアレベルのキー認証に対応する。
    * クライアントのステータスを確認し、完全な信頼チェーン（検証済みのブートキー、ロックされたブートローダ、検証済みのブートステート）を確保する。
    * さらに、目的、アクセス時間、認証要件など、対称鍵の属性を確認することができる。

注意：何らかの理由でこのプロセスが失敗した場合、キーがセキュリティハードウェアにないことを意味する。これは、キーが危険にさらされていることを意味するものではない。

Android Keystore の認証応答の典型的な例は、以下のようになる。
```json
{
    "fmt": "android-key",
    "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bd...",
    "attStmt": {
        "alg": -7,
        "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53...",
        "x5c": [
            "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130...",
            "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b300906035504061...",
            "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b3..."
        ]
    }
}
```
上記の JSON スニペットにおいて、キーは以下の意味を持つ。
* fmt ：認証文のフォーマット識別子
* authData ：認証のための authenticator データを表す
* alg ：署名に使用されるアルゴリズム
* sig ：署名
* x5c ：証明書チェーン

注： sig は authData と clientDataHash （サーバから送られたチャレンジ）を連結して生成し、credential な秘密鍵を通して署名アルゴリズム（ alg ）を用いて署名し、同じものをサーバ側で最初の証明書の公開鍵を使って検証する。

実装ガイドラインの詳細については、[Google のサンプルコード](https://github.com/google/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java)を参照すること。

セキュリティ解析の観点から、アナリストはキー認証の安全な実装のために、以下のチェックを行うこと。
* キー認証がクライアント側で完全に実装されているかどうかを確認する。このようなシナリオでは、アプリケーションを改ざんしたり、メソッドをフックしたりすることで、同じことを簡単に回避できる。
* キー認証を開始する際に、サーバがランダムチャレンジを使用しているかどうかを確認する。これを怠ると、安全でない実装となり、リプレイ攻撃に対して脆弱になる。また、チャレンジのランダム性に関してもチェックする必要がある。
* サーバがキー認証応答の完全性を検証しているかどうかを確認する。
* サーバがチェーン内の証明書に対して、完全性検証、信頼性検証、有効性などの基本的なチェックを実行しているかどうかを確認する。

参考資料
* [owasp-mastg Data Storage Methods Overview Key Attestation](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#key-attestation)

ルールブック
* [安全なキー認証をする場合は、サーバから受け取ったチャレンジによりデバイス内の証明書を提供する（推奨）](#安全なキー認証をする場合はサーバから受け取ったチャレンジによりデバイス内の証明書を提供する推奨)
* [セキュリティ解析の観点から、キー認証の安全な実装のためのチェック（必須）](#セキュリティ解析の観点からキー認証の安全な実装のためのチェック必須)

### KeyStore へのセキュアキーのインポート

Android 9 (API level 28) では、 Android Keystore にキーを安全にインポートする機能が追加された。<br>
Android Keystore は、まず PURPOSE_WRAP_KEY を使用して、認証証明書で保護する必要のある対称鍵を生成する。この対称鍵は、 Android Keystore にインポートされるキーの保護を目的としている。暗号化されたキーは、インポートされたキーの使用方法の説明を含む SecureKeyWrapper 形式で ASN.1 エンコードされたメッセージとして生成される。その後、暗号化されたキーは、ラッピングキーを生成した特定のデバイスに属する Android Keystore ハードウェア内で復号されるため、デバイスのホストメモリに平文として表示されることはない。

<img src="images\0x03\MSTG-STORAGE-1/Android9_secure_key_import_to_keystore.jpg" alt="安全なキーのインポートフロー" width="500px" />

Java での例:
```java
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

上記のコードでは、SecureKeyWrapper 形式で暗号鍵を生成する際に設定する各種パラメータを示している。詳細は、Android の [WrappedKeyEntry](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry) のドキュメントを参照。

KeyDescription AuthorizationList を定義する際、以下のパラメータが暗号化されたキーのセキュリティに影響を与える。
* algorithm : キーで使用する暗号化方式を指定
* keySize : キーのアルゴリズムの通常の方法で測定して、鍵のサイズをビット単位で指定
* digest : 署名および検証操作のためにキーとともに使用できるダイジェストアルゴリズムを指定

参考資料
* [owasp-mastg Data Storage Methods Overview Secure Key Import into Keystore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#secure-key-import-into-keystore)


### 古い KeyStore 実装

古いバージョンの Android には KeyStore は含まれていないが、JCA (Java Cryptography Architecture) の KeyStore インターフェースは含まれる。 このインターフェースを実装した KeyStore を使用することで、KeyStore に保存されたキーの機密性と完全性を確保できる。 BouncyCastle KeyStore (BKS) が推奨される。


すべての実装は、ファイルがファイルシステム上に保存されているという事実に基づく。すべてのファイルはパスワードで保護されている。 作成するには、KeyStore.getInstance("BKS", "BC") メソッドを使用する。"BKS" は KeyStore 名 (BouncyCastle Keystore) で、"BC" は provider (BouncyCastle) を意味する。 SpongyCastle をラッパーとして使用して、以下のように KeyStore を初期化することも可能となる。

KeyStore.getInstance("BKS", "SC")

すべての KeyStore が、KeyStore ファイルに保存されたキーを適切に保護するわけではないことに注意する必要がある。

参考資料
* [owasp-mastg Data Storage Methods Overview Older KeyStore Implementations](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#older-keystore-implementations)

ルールブック
* [古い Android OS では BouncyCastle KeyStore によりキーを保存する（推奨）](#古い-android-os-では-bouncycastle-keystore-によりキーを保存する推奨)

### Key Chain

[Keychain](https://developer.android.com/reference/android/security/KeyChain) クラスは、システム全体の秘密鍵とそれに対応する証明書 (チェーン) を保存および取得するために使用される。Keychain に何かを初めてインポートする場合、ユーザは証明書ストレージを保護するためにロック画面の PIN またはパスワードを設定するよう促される。 Keychain はシステム全体であり、すべてのアプリケーションが Keychain に保存されている materials にアクセスできることに注意する必要がある。

ソースコードを調べて、Android のネイティブなメカニズムが機密情報を特定するかどうかを判断する。 機密情報は暗号化し、平文で保存してはいけない。 デバイスに保存する必要がある機密情報については、Keychain クラスを介してデータを保護するために、いくつかの API 呼び出しを利用できる。 以下のステップを完了する。

* アプリが Android KeyStore と Cipher のメカニズムを使用して、暗号化された情報をデバイスに安全に保存していることを確認する。 AndroidKeystore, import java.security.KeyStore, import javax.crypto.Cipher, import java.security.SecureRandom, and corresponding usages というパターンを探してみる。

* store(OutputStream stream, char[] password) 関数を使用して、KeyStore をパスワード付きでディスクに保存する。 パスワードはハードコードされたものではなく、ユーザによって提供されるものであることを確認する。

参考資料
* [owasp-mastg Data Storage Methods Overview Keychain](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#keychain)

ルールブック
* [Keychain に初めてインポートする場合、ユーザへ証明書ストレージを保護するためにロック画面の PIN またはパスワードを設定するよう促す（必須）](#keychain-に初めてインポートする場合ユーザへ証明書ストレージを保護するためにロック画面の-pin-またはパスワードを設定するよう促す必須)
* [Android のネイティブなメカニズムが機密情報を特定するかどうかを判断する（必須）](#android-のネイティブなメカニズムが機密情報を特定するかどうかを判断する必須)

### 暗号化キーの保存

Android KeyStore では、Android デバイス上でのキーの不正利用を防ぐため、キーの生成時やインポート時に、アプリが許可したキーの用途を指定できるようになっている。<br>
一度指定した内容は、変更することができない。

以下はキーの最も安全な保存方法から最も安全でない保存方法である。
* ハードウェアで格納された Android KeyStore にキーを保存する。
* 全てのキーをサーバに保存し、強力な認証の後に利用可能にする。
* マスターキーをサーバに保存し、 Android の SharedPreferences に保存された他のキーを暗号化するために使用する。
* キーに十分な長さと Salt を持たせ、ユーザが提供する強力なパスフレーズから毎回導き出す。
* キーを Android KeyStore のソフトウェア実装に格納する。
* マスターキーを Android Keystore のソフトウェア実装に格納し、 SharedPreferences に格納された他のキーを暗号化するために使用する。
* [非推奨] 全てのキーを SharedPreferences に保存する。
* [非推奨] キーをソースコードにハードコードする。
* [非推奨] 安定した属性に基づく予測可能な難読化関数または鍵導出関数を使用する。
* [非推奨] 生成されたキーを public な場所 (/sdcard/ など) に保存する。

参考資料
* [owasp-mastg Data Storage Methods Overview Storing a Cryptographic Key: Techniques](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-a-cryptographic-key-techniques)

ルールブック
* [暗号化キーの保存方法（必須）](#暗号化キーの保存方法必須)


#### ハードウェア格納型 Android KeyStore によるキーの保存

Android 7.0 (API level 24) 以上のデバイスで、利用可能なハードウェアコンポーネント (Trusted Execution Environment (TEE) または Secure Element (SE)) があれば、[ハードウェア格納型 Android KeyStore](#ハードウェア格納型-android-keystore) を使用できる。<br>
また、[安全なキー認証の実装のために提供されるガイドライン](#キー認証)を使用することで、キーがハードウェアで保護されていることを確認することができる。<br>
ハードウェアコンポーネントが利用できない場合や、 Android 6.0 (API level 23) 以下のサポートが必要な場合は、キーをリモートサーバに保存し、認証後に利用できるようにすることが推奨される。

参考資料
* [owasp-mastg Data Storage Methods Overview Storing Keys Using Hardware-backed Android KeyStore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-using-hardware-backed-android-keystore)

#### サーバへの保存

キー管理サーバにキーを安全に保存することは可能だが、データを復号するにはアプリをオンラインにする必要がある。 これは、特定のモバイル アプリのユース ケースでは制限となる可能性があり、アプリのアーキテクチャの一部となり、ユーザビリティに大きな影響を与える可能性があるため、慎重に検討する必要がある。

参考資料
* [owasp-mastg Data Storage Methods Overview Storing Keys on the Server](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-on-the-server)

#### ユーザ入力によるキーの導出

ユーザが入力したパスフレーズからキーを生成することは一般的な解決策だが（使用する Android API level によって異なる。）、ユーザビリティに影響し、攻撃対象に影響を与え、さらなる弱点をもたらす可能性がある。

アプリケーションが暗号化操作を行うたびに、ユーザのパスフレーズが必要になる。
パスフレーズを毎回入力させるのは理想的なユーザエクスペリエンスとは言えない。パスフレーズはユーザが認証されている間、メモリに保持される。パスフレーズをメモリ内に保持することは、ベストプラクティスではない。キーをゼロにすることは、[「キーマテリアルの消去」](#キーマテリアルの消去)で説明したように、非常に困難な作業であることが多い。

さらに、パスフレーズから派生したキーには弱点があることを考慮する。例えば、パスワードやパスフレーズはユーザによって再利用されたり、簡単に推測されたりする可能性がある。詳しくは[「暗号のテスト」](0x04-MASDG-Cryptography_Requirements.md#弱いキー生成関数)の章を参照。

参考資料
* [owasp-mastg Data Storage Methods Overview Deriving Keys from User Input](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#deriving-keys-from-user-input)

#### キーマテリアルの消去

キーマテリアルは、不要になったらすぐにメモリから消去する必要がある。 ガベージコレクタ（Java）や不変文字列（Kotlin）を使用する言語では、秘密データを実際にクリーンアップするには一定の限界がある。 [Java Cryptography Architecture Reference Guide](https://docs.oracle.com/en/java/javase/16/security/java-cryptography-architecture-jca-reference-guide.html#GUID-C9F76AFB-6B20-45A7-B84F-96756C8A94B4) では、機密データを格納するために String の代わりに char[] を使用し、使用後に配列を null にすることを提案する。

一部の暗号はバイト配列のクリーンアップを適切に行わないことに注意する。例えば、 BouncyCastle の AES 暗号は、常に最新の作業キーをクリーンアップするわけではなく、メモリ上にバイト配列のコピーをいくつか残している。次に、BigIntegerベースのキー（例えば秘密鍵）は、追加の労力なしにヒープから削除したり、ゼロにしたりすることはできない。バイト配列のクリアは、 [Destroyable](https://docs.oracle.com/javase/8/docs/api/javax/security/auth/Destroyable.html#destroy--) を実装したラッパーを作成することで実現できる。

参考資料
* [owasp-mastg Data Storage Methods Overview Cleaning out Key Material](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#cleaning-out-key-material)

ルールブック
* [キーマテリアルは、不要になったらすぐにメモリから消去する必要がある（必須）](#キーマテリアルは不要になったらすぐにメモリから消去する必要がある必須)

#### Android KeyStore API を使用したキーの保存

よりユーザフレンドリーで推奨される方法は、 [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html) システム（それ自体または Keychain を経由して）を使用してキーマテリアルを保存することである。可能であれば、ハードウェア格納型ストレージを使用すべきである。
そうでない場合は、Android KeyStore のソフトウェア実装にフォールバックする必要がある。ただし、Android KeyStore API は、Android のさまざまなバージョンで大幅に変更されていることに注意が必要である。

以前のバージョンでは、Android KeyStore API は公開鍵/秘密鍵ペア（例： RSA ）の保存のみをサポートしている。対称鍵のサポートは、Android 6.0（API level 23）以降に追加された。そのため、開発者は、対称鍵を安全に保存するために、さまざまな Android API levelを扱う必要がある。


参考資料
* [owasp-mastg Data Storage Methods Overview Storing Keys using Android KeyStore API](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-using-android-keystore-api)


ルールブック
* [キーマテリアルを保存する（推奨）](#キーマテリアルを保存する推奨)

#### キーを他のキーで暗号化して保存する

Android 5.1（API level 22）以下のデバイスで対称鍵を安全に保存するには、公開鍵と秘密鍵のペアを生成する必要がある。公開鍵を用いて共通鍵を暗号化し、秘密鍵を Android KeyStore に保存する。暗号化された共通鍵は、 base64 でエンコードして SharedPreferences に格納することが可能となる。対称鍵が必要なときはいつでも、アプリケーションが Android KeyStore から秘密鍵を取り出し、対称鍵を復号する。

エンベロープ暗号化またはキーラッピングは、共通鍵暗号方式を使用してキー マテリアルをカプセル化する同様のアプローチである。 Data encryption keys(DEKs) は、安全に保管されている key encryption key (KEKs) で暗号化できる。暗号化された DEKs は、SharedPreferences に保存するか、ファイルに書き込むことができる。 必要に応じて、アプリケーションは KEK を読み取り、DEK を復号する。
暗号化キーの暗号化の詳細については、 [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys) を参照。

また、このアプローチの説明として、[androidx.security.crypto パッケージの EncryptedSharedPreferences](https://developer.android.com/jetpack/androidx/releases/security) を参照。

参考資料
* [owasp-mastg Data Storage Methods Overview Storing keys by encrypting them with other keys](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-by-encrypting-them-with-other-keys)

ルールブック
* [Android OS 5.1 以下で対称鍵を安全に保管する場合は公開鍵と秘密鍵のペアを生成する（必須）](#android-os-51-以下で対称鍵を安全に保管する場合は公開鍵と秘密鍵のペアを生成する必須)
* [EncryptedSharedPreferences の利用方法（推奨）](#encryptedsharedpreferences-の利用方法推奨)


#### キーを保存するための安全でないオプション

暗号化キーの保存方法として、Android の SharedPreferences に保存する方法があるが、これはあまり安全ではない。 [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html) を使用する場合、ファイルを作成したアプリケーションのみがファイルを読み取ることができる。
しかし、 root 化されたデバイスでは、ルートアクセス権を持つ他のアプリケーションは、他のアプリケーションの SharedPreferences ファイルを簡単に読み取ることができる。 Android KeyStore には当てはまらない。Android KeyStore のアクセスはカーネルレベルで管理されているため、 Android KeyStore がキーを消去したり破壊したりせずにバイパスするには、かなり多くの作業とスキルが必要となる。

最後の 3 つのオプションは、ソースコードにハードコードされた暗号鍵を使用すること、安定した属性に基づく予測可能な難読化機能または鍵導出関数機能を持つこと、生成したキーを /sdcard/ などの public の場所に格納することである。ハードコードされた暗号化キーは、アプリケーションのすべてのインスタンスが同じ暗号化キーを使用することを意味するため、問題となる。攻撃者は、アプリケーションのローカルコピーをリバースエンジニアリングして暗号鍵を取り出し、そのキーを使って、どのデバイス上でもアプリケーションによって暗号化されたデータを復号することができる。


次に、他のアプリケーションからアクセス可能な識別子に基づく予測可能な鍵導出関数がある場合、攻撃者は KDF を見つけてデバイスに適用するだけでキーを見つけることができる。
最後に、他のアプリケーションが public パーティションを読み取る権限を持ち、キーを盗むことができるため、暗号化キーを public に保存することも強く推奨しない。

参考資料
* [owasp-mastg Data Storage Methods Overview Insecure options to store keys](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#insecure-options-to-store-keys)

ルールブック
* [安全性の低い暗号化キーの保存方法は利用しない（必須）](#安全性の低い暗号化キーの保存方法は利用しない必須)


### サードパーティライブラリ

Android プラットフォームに特化した暗号化機能を提供するオープンソースのライブラリがいくつか存在する。

* [Java AES Crypto](https://github.com/tozny/java-aes-crypto) - 文字列を暗号化・復号するためのシンプルな Android クラス。
* [SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/) - SQLCipher は、SQLite のオープンソース拡張機能で、データベースファイルの透過的な 256 ビット AES 暗号化を提供する。
* [Secure Preferences](https://github.com/scottyab/secure-preferences) - Android Shared preference wrapper は Shared Preferences の keys と values の暗号化を提供する。
* [Themis](https://github.com/cossacklabs/themis) - 認証、ストレージ、メッセージングなどのデータを保護するために、多くのプラットフォームで同じ API を提供するクロスプラットフォームの高レベル暗号化ライブラリ。

キーが KeyStore に保存されていない限り、 root 化されたデバイスでキーを簡単に取得し、保護しようとしている値を復号することが常に可能であることを念頭におく必要がある。

参考資料
* [owasp-mastg Data Storage Methods Overview Third Party libraries](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-libraries)


ルールブック
* [サードパーティライブラリでの暗号化（非推奨）](#サードパーティライブラリでの暗号化非推奨)

### ルールブック
1. [キーがセキュリティハードウェアの内部に保存されているかどうかを確認する（推奨）](#キーがセキュリティハードウェアの内部に保存されているかどうかを確認する推奨)
1. [StrongBox の利用方法（推奨）](#strongbox-の利用方法推奨)
1. [安全なキー認証をする場合は、サーバから受け取ったチャレンジによりデバイス内の証明書を提供する（推奨）](#安全なキー認証をする場合はサーバから受け取ったチャレンジによりデバイス内の証明書を提供する推奨)
1. [セキュリティ解析の観点から、キー認証の安全な実装のためのチェック（必須）](#セキュリティ解析の観点からキー認証の安全な実装のためのチェック必須)
1. [古い Android OS では BouncyCastle KeyStore によりキーを保存する（推奨）](#古い-android-os-では-bouncycastle-keystore-によりキーを保存する推奨)
1. [Keychain に初めてインポートする場合、ユーザへ証明書ストレージを保護するためにロック画面の PIN またはパスワードを設定するよう促す（必須）](#keychain-に初めてインポートする場合ユーザへ証明書ストレージを保護するためにロック画面の-pin-またはパスワードを設定するよう促す必須)
1. [Android のネイティブなメカニズムが機密情報を特定するかどうかを判断する（必須）](#android-のネイティブなメカニズムが機密情報を特定するかどうかを判断する必須)
1. [暗号化キーの保存方法（必須）](#暗号化キーの保存方法必須)
1. [キーマテリアルは、不要になったらすぐにメモリから消去する必要がある（必須）](#キーマテリアルは不要になったらすぐにメモリから消去する必要がある必須)
1. [キーマテリアルを保存する（推奨）](#キーマテリアルを保存する推奨)
1. [Android OS 5.1 以下で対称鍵を安全に保管する場合は公開鍵と秘密鍵のペアを生成する（必須）](#android-os-51-以下で対称鍵を安全に保管する場合は公開鍵と秘密鍵のペアを生成する必須)
1. [EncryptedSharedPreferences の利用方法（推奨）](#encryptedsharedpreferences-の利用方法推奨)
1. [安全性の低い暗号化キーの保存方法は利用しない（必須）](#安全性の低い暗号化キーの保存方法は利用しない必須)
1. [サードパーティライブラリでの暗号化（非推奨）](#サードパーティライブラリでの暗号化非推奨)

#### キーがセキュリティハードウェアの内部に保存されているかどうかを確認する（推奨）

キーがセキュリティハードウェアの内部に保存されているかどうかを確認することができる (KeyInfo.isinsideSecureHardware が true を返すかどうかをチェックすることで確認できる)。

確認方法は以下である。
API level 31 以降は、 isinsideSecureHardware は非推奨であるため
API level 31 以降をターゲットとするアプリは [getSecurityLevel](https://developer.android.com/reference/android/security/keystore/KeyInfo#getSecurityLevel()) を使用する必要がある。

```java
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      SecretKey secretKey = (SecretKey) keyStore.getKey("ALIAS", null);
      SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      KeyInfo keyInfo = (KeyInfo) secretKeyFactory.getKeySpec(secretKey, KeyInfo.class);
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
         int securityLevel = keyInfo.getSecurityLevel();
      } else {
         boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();
      }
```

これに注意しない場合、以下の可能性がある。
* キーがユーザにより読み書きされ、悪用される可能性がある。

#### StrongBox の利用方法（推奨）

Android 9 (API level 28) 以降を実行しているデバイスは、StrongBox Keymaster モジュールを搭載できる。これは、独自の CPU 、Secure ストレージ、真の乱数ジェネレーター、パッケージ改ざんに対抗するメカニズムを持つハードウェアセキュリティモジュールに常駐する Keymaster HAL の実装である。
この機能を使用するには、Android Keystore を使用してキーを生成またはインポートする際に、KeyGenParameterSpec.Builder クラスまたは KeyProtection.Builder クラスの setIsStrongBoxBacked メソッドに true を渡す必要がある。
実行時に StrongBox が使われるようにするには、isInsideSecureHardware が true を返し、システムが StrongBoxUnavailableException を throw しないことを確認する。なお、isinsideSecureHardware は API level 31で廃止され、getSecurityLevelが推奨されている。


```java
      KeyGenParameterSpec builder = new KeyGenParameterSpec.Builder("ALIAS", KeyProperties.PURPOSE_VERIFY)
              .setIsStrongBoxBacked(true)
              .build();
```

これに注意しない場合、以下の可能性がある。
* キーがユーザにより読み書きされ、悪用される可能性がある。

#### 安全なキー認証をする場合は、サーバから受け取ったチャレンジによりデバイス内の証明書を提供する（推奨）
キー認証はクライアント側のみで実装可能であるが、より安全な認証を行うためにはサーバ側で実装することが推奨される。
その場合クライアント側では、サーバから受け取ったチャレンジで setAttestationChallenge API を呼び出し、KeyStore.getCertificateChain メソッドで証明書チェーンを取得し、証明書をサーバへ提供する必要がある。
サーバは提供された証明書により、キー認証を行う。

以下へ上記処理のサンプルコードを示す。
```java
final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);
final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS_SAMPLE,
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setAlgorithmParameterSpec(new ECGenParameterSpec(AttestationProtocol.EC_CURVE))
    .setDigests(AttestationProtocol.KEY_DIGEST)
    .setAttestationChallenge(challenge);
AttestationProtocol.generateKeyPair(KEY_ALGORITHM_EC, builder.build());
final Certificate[] certs = keyStore.getCertificateChain(KEYSTORE_ALIAS_SAMPLE);
```

これに注意しない場合、以下の可能性がある。
* チャレンジを受け取ったデバイスが該当デバイスであることを証明できず、安全なキー認証を出来ない可能性がある。

#### セキュリティ解析の観点から、キー認証の安全な実装のためのチェック（必須）

セキュリティ解析の観点から、アナリストはキー認証の安全な実装のために、以下のチェックを行うこと。
* キー認証がクライアント側で完全に実装されていないことを確認する。完全に実装されている場合、アプリケーションを改ざんしたり、メソッドをフックしたりすることで、同じことを簡単に回避できてしまう。
* キー認証を開始する際に、サーバがランダムチャレンジを使用していることを確認する。これを怠ると、安全でない実装となり、リプレイ攻撃に対して脆弱になる。また、チャレンジのランダム性に関してもチェックする必要がある。
* サーバがキー認証応答の完全性を検証していることを確認し、検証していない場合は安全でない実装となるため対応が必要である。
* サーバがチェーン内の証明書に対して、完全性検証、信頼性検証、有効性などの基本的なチェックを実行していることを確認し、チェックしていない場合は安全でない実装となるため対応が必要である。

これに注意しない場合、以下の可能性がある。
* 安全なキー認証を保証できない。

#### 古い Android OS では BouncyCastle KeyStore によりキーを保存する（推奨）
古いバージョンの Android には KeyStore は含まれていないが、 JCA (Java Cryptography Architecture) の KeyStore インターフェースは含まれる。 このインターフェースを実装した KeyStore を使用することで、KeyStore に保存されたキーの機密性と完全性を確保できる。 
その中で、 BouncyCastle KeyStore (BKS) が推奨される。

BouncyCastle KeyStore (BKS) を使用したKeyStoreの実装を以下に記載する。
"BKS" は KeyStore 名 (BouncyCastle Keystore) で、"BC" は provider (BouncyCastle) を意味する。 SpongyCastle をラッパーとして使用して、以下のように KeyStore を初期化することも可能となる。

すべての KeyStore が、KeyStore ファイルに保存されたキーを適切に保護するわけではないことに注意する必要がある。

```java
KeyStore.getInstance("BKS", "SC")
```

これに注意しない場合、以下の可能性がある。
* 使用するキーの機密性と完全性を確保できない可能性がある。

#### Keychain に初めてインポートする場合、ユーザへ証明書ストレージを保護するためにロック画面の PIN またはパスワードを設定するよう促す（必須）

Keychain に何かを初めてインポートする場合、ユーザへ証明書ストレージを保護するためにロック画面の PIN またはパスワードを設定するよう促す。 Keychain はシステム全体であり、すべてのアプリケーションが Keychain に保存されている materials にアクセスできることに注意する必要がある。

これに違反する場合、以下の可能性がある。
* Keychain にインポートされた情報はシステムレベルで利用できてしまうため、第三者にデバイスを使用されると意図しない用途で使用される可能性がある。

#### Android のネイティブなメカニズムが機密情報を特定するかどうかを判断する（必須）

ソースコードを調べて、Android のネイティブなメカニズムが機密情報を特定するかどうかを判断する。 機密情報は暗号化し、平文で保存してはいけない。 デバイスに保存する必要がある機密情報については、Keychain クラスを介してデータを保護するために、いくつかの API 呼び出しを利用できる。 以下のステップを完了する。

* アプリが暗号化された情報をデバイスに保存しているか確認する。
* アプリが Android KeyStore と Cipher のメカニズムを使用して、暗号化された情報をデバイスに安全に保存していることを確認する。
  
  以下のパターンを探してみる。
  * AndroidKeystore
  * import java.security.KeyStore
  * import javax.crypto.Cipher
  * import java.security.SecureRandom, and corresponding usages

* store(OutputStream stream, char[] password) 関数を使用して、KeyStore をパスワード付きでディスクに保存する。 パスワードはハードコードされたものではなく、ユーザによって提供されるものであることを確認する。以下へサンプルコードを示す。
   ```java
   public static void main(String args[]) throws Exception {
    char[] oldpass = args[0].toCharArray();
    char[] newpass = args[1].toCharArray();
    String name = "mykeystore";
    FileInputStream in = new FileInputStream(name);
    KeyStore ks = KeyStore.getInstance(/*jca name*/);
    ks.load(in, oldpass);
    in.close();
    FileOutputStream output = new FileOutputStream(name);
    ks.store(output, newpass);
    output.close();
   }
   ```

Keychain クラスでの資格情報のインストール方法を以下サンプルコードへ示す。
```kotlin
    private val launcher = registerForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        //...
    }

    fun startPiyoActivity() {
        val bis = BufferedInputStream(assets.open(/*PKCS12 filename*/))
        val keychain = ByteArray(bis.available())
        bis.read(keychain)
        val installIntent = Keychain.createInstallIntent()
        installIntent.putExtra(Keychain.EXTRA_PKCS12, keychain)
        installIntent.putExtra(Keychain.EXTRA_NAME, /*alias*/)
        val intent = Intent(this, /*Activity name*/::class.java)
        launcher.launch(intent)
    }
```

これに違反する場合、以下の可能性がある。
* 機密情報が平文で保存され、第三者に漏洩する可能性がある。

#### 暗号化キーの保存方法（必須）

暗号化キーの安全な保存方法、安全でない保存方法は以下である。

**推奨**

以下にキーの推奨される保存方法を安全な順に記載する。
* ハードウェアで格納された Android KeyStore にキーを保存する。

   以下は Android KeyStore にキーを保存するサンプルコード。
   ```java
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      SecretKey secretKey = (SecretKey) keyStore.getKey("ALIAS", null);
      SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      KeyInfo keyInfo = (KeyInfo) secretKeyFactory.getKeySpec(secretKey, KeyInfo.class);
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
         int securityLevel = keyInfo.getSecurityLevel();
      } else {
         boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();
      }
   ```
* 全てのキーをサーバに保存し、強力な認証の後に利用可能にする。※詳細・注意事項については「[サーバへの保存](#サーバへの保存)」を参照。
* マスターキーをサーバに保存し、 Android の SharedPreferences に保存された他のキーを暗号化するために使用する。※詳細・注意事項については「[サーバへの保存](#サーバへの保存)」を参照。
* キーに十分な長さと Salt を持たせ、ユーザが提供する強力なパスフレーズから毎回導き出す。※詳細・注意事項については「[ユーザ入力によるキーの導出](#ユーザ入力によるキーの導出)」を参照。
* キーを Android KeyStore のソフトウェア実装に格納する。※詳細・注意事項については「[キーマテリアルの消去](#キーマテリアルの消去)」と「[Android KeyStore API を使用したキーの保存](#android-keystore-api-を使用したキーの保存)」を参照。
* マスターキーを Android Keystore のソフトウェア実装に格納し、 SharedPreferences に格納された他のキーを暗号化するために使用する。※詳細・注意事項については「[キーマテリアルの消去](#キーマテリアルの消去)」と「[Android KeyStore API を使用したキーの保存](#android-keystore-api-を使用したキーの保存)」を参照。

**非推奨**<br>
* 全てのキーを SharedPreferences に保存する。
* キーをソースコードにハードコードする。
* 安定した属性に基づく予測可能な難読化関数または鍵導出関数を使用する。
* 生成されたキーを public な場所 (/sdcard/ など) に保存する。

これに違反する場合、以下の可能性がある。
* Android デバイス上でのキーを不正利用される。

#### キーマテリアルは、不要になったらすぐにメモリから消去する必要がある（必須）

キーマテリアルは、不要になったらすぐにメモリから消去する必要がある。 ガベージコレクタ（Java）や不変文字列（Kotlin）を使用する言語では、秘密データを実際にクリーンアップするには一定の限界がある。 Java Cryptography Architecture Reference Guide では、機密データを格納するために String の代わりに char[] を使用し、使用後に配列を null にすることを提案する。


Java での例:
```java

         // Salt
         byte[] salt = new SecureRandom().nextBytes(/*salt*/);

         // Iteration count
         int count = 1000;

         // Create PBE parameter set
         pbeParamSpec = new PBEParameterSpec(salt, count);

         // Prompt user for encryption password.
         // Collect user password as char array, and convert
         // it into a SecretKey object, using a PBE key
         // factory.
         char[] password = /*cleartext string*/.toCharArray();
         pbeKeySpec = new PBEKeySpec(password);
         keyFac = SecretKeyFactory.getInstance(/*algorithm*/);
         SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

         // Create PBE Cipher
         Cipher pbeCipher = Cipher.getInstance(/*algorithm*/);

         // Initialize PBE Cipher with key and parameters
         pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

         // Our cleartext
         byte[] cleartext = /*cleartext string*/.getBytes();

         // Encrypt the cleartext
         byte[] ciphertext = pbeCipher.doFinal(cleartext);


         cleartext = null;
         ciphertext = null;
```

一部の暗号はバイト配列のクリーンアップを適切に行わないことに注意する。例えば、 BouncyCastle の AES 暗号は、常に最新の作業キーをクリーンアップするわけではなく、メモリ上にバイト配列のコピーをいくつか残している。次に、BigIntegerベースのキー（例えば秘密鍵）は、追加の労力なしにヒープから削除したり、ゼロにしたりすることはできない。バイト配列のクリアは、 Destroyable を実装したラッパーを作成することで実現できる。


Java での例:
```java
KeyStore.PasswordProtection ks = new KeyStore.PasswordProtection("password".toCharArray());
ks.destroy();

if(ks.isDestroyed()){
   cleartext = null;
   ciphertext = null;
}
```

これに違反する場合、以下の可能性がある。
* メモリ内のキーマテリアルが、別の用途で使用される可能性がある。
* ガベージコレクタ（Java）や不変文字列（Kotlin）を使用する言語ではクリーンアップされない可能性がある。

#### キーマテリアルを保存する（推奨）

よりユーザフレンドリーで推奨される方法は、 [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html) システム（それ自体または Keychain を経由して）を使用してキーマテリアルを保存することである。

KeyStore APIを使用する保存方法は以下となる。

Java での例:
```java
   // save my secret key
    javax.crypto.SecretKey mySecretKey;
    KeyStore.SecretKeyEntry skEntry =
        new KeyStore.SecretKeyEntry(mySecretKey);
    ks.setEntry("secretKeyAlias", skEntry, protParam);
```

これに注意しない場合、以下の可能性がある。
* キーを安全に保存できず、悪用される可能性がある。

#### Android OS 5.1 以下で対称鍵を安全に保管する場合は公開鍵と秘密鍵のペアを生成する（必須）

Android 5.1（API level 22）以下のデバイスで対称鍵を安全に保存するには、公開鍵と秘密鍵のペアを生成する必要がある。公開鍵を用いて共通鍵を暗号化し、秘密鍵を Android KeyStore に保存する。暗号化された共通鍵は、 base64 でエンコードして SharedPreferences に格納することが可能となる。対称鍵が必要なときはいつでも、アプリケーションが Android KeyStore から秘密鍵を取り出し、対称鍵を復号する。<br>

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* 対称鍵を安全に保存できず、悪用される可能性がある。

#### EncryptedSharedPreferences の利用方法（推奨）

キーを他のキーで暗号化を行う場合の androidx.security.crypto パッケージの EncryptedSharedPreferences の
対応方法は以下となる。

Java での例:
```java
 MasterKey masterKey = new MasterKey.Builder(context)
     .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
     .build();

 SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
     context,
     "secret_shared_prefs",
     masterKey,
     EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
     EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
 );

 // use the shared preferences and editor as you normally would
 SharedPreferences.Editor editor = sharedPreferences.edit();
```

これに違反する場合、以下の可能性がある。
* 対称鍵を安全に保存できず、悪用される可能性がある。

#### 安全性の低い暗号化キーの保存方法は利用しない（必須）
安全性の低い暗号化キーの保存方法とされる SharedPreferences やハードコードなどの利用は危険であるため利用しない。

暗号化キーを格納する安全性の低い方法は、以下である。

* SharedPreferences への格納。root 化されたデバイスでは、ルートアクセス権を持つ他のアプリケーションは、他のアプリケーションの SharedPreferences ファイルを簡単に読み取ることができる。
* ソースコードにハードコードする。攻撃者は、アプリケーションのローカルコピーをリバースエンジニアリングして暗号鍵を取り出し、そのキーを使って、どのデバイス上でもアプリケーションによって暗号化されたデータを復号することができる
* 他のアプリケーションからアクセス可能な識別子に基づく予測可能な鍵導出関数がある場合、攻撃者は KDF を見つけてデバイスに適用するだけでキーを見つけることができる。
* 暗号化キーを public に保存する。他のアプリケーションが public パーティションを読み取る権限を持ち、キーを盗むことができるため推奨しない。

これに違反する場合、以下の可能性がある。
* root 化されたデバイスの場合、 SharedPreferences ファイルの暗号化キーを他のアプリケーションから読み取られる。
* リバースエンジニアリングにより、ハードコードされた暗号化キーを読み取られる。
* 他のアプリケーションからアクセス可能な識別子に基づく予測可能な鍵導出関数がある場合、攻撃者は KDF を見つけてデバイスに適用するだけでキーを見つけることができる。
* 暗号化キーを public に保存すると、他のアプリケーションが public パーティションを読み取る権限を持つ場合に、キーを盗むことができる。

#### サードパーティライブラリでの暗号化（非推奨）

Android プラットフォームに特化した暗号化機能を提供するオープンソースのライブラリとして、以下のライブラリが存在する。ライブラリは便利であるが、キーが KeyStore に保存されていない限り、 root 化されたデバイスではキーを簡単に取得でき、保護しようとしている値を復号することが常に可能であるため、利用は推奨されない。

* Java AES Crypto：文字列を暗号化および復号するためのシンプルな Android クラス。
* SQL Cipher：SQLCipher は、SQLite のオープンソース拡張機能で、データベースファイルの透過的な 256 ビット AES 暗号化を提供する。
* Secure Preferences：Android Shared preference wrapper は Shared Preferences の keys と values の暗号化を提供する。
* Themis：認証、ストレージ、メッセージングなどのデータを保護するために、多くのプラットフォームで同じ API を提供するクロスプラットフォームの高レベル暗号化ライブラリ。

これが非推奨である理由は以下である。
* キーが KeyStore に保存されていない限り、root 化されたデバイスではキーを簡単に取得でき、保護しようとしている値を復号することが常に可能である。

## MSTG-STORAGE-2
機密データはアプリコンテナまたはシステムの資格情報保存機能の外部に保存されていない。

### 内部ストレージ

デバイスの[内部ストレージ](https://developer.android.com/training/data-storage#filesInternal)にファイルを保存することができる。<br>
内部ストレージに保存されたファイルは、デフォルトでコンテナ化され、デバイス上の他のアプリからアクセスすることはできない。ユーザがアプリをアンインストールすると、これらのファイルは削除される。以下のコードでは、機密データを内部ストレージに永続的に保存する。

Java での例:
```java
FileOutputStream fos = null;
try {
   fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
   fos.write(test.getBytes());
   fos.close();
} catch (FileNotFoundException e) {
   e.printStackTrace();
} catch (IOException e) {
   e.printStackTrace();
}
```

Kotlin での例:
```Kotlin
var fos: FileOutputStream? = null
fos = openFileOutput("FILENAME", Context.MODE_PRIVATE)
fos.write(test.toByteArray(Charsets.UTF_8))
fos.close()
```

ファイルモードを確認し、アプリだけがファイルへアクセスできるようにする必要がある。このアクセスは MODE_PRIVATE で設定することができる。 MODE_WORLD_READABLE （非推奨）や MODE_WORLD_WRITEABLE （非推奨）などのモードは、セキュリティ上のリスクをもたらす可能性がある。

FileInputStream クラスを検索して、アプリ内でどのファイルが開かれ、読み取られるかを見つける。

参考資料
* [owasp-mastg Data Storage Methods Overview Internal Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#internal-storage)

ルールブック
* [機密データはアプリコンテナまたはシステムの資格情報保存機能へ保存する（必須）](#機密データはアプリコンテナまたはシステムの資格情報保存機能へ保存する必須)

### 外部ストレージ

すべての Android 互換デバイスは、[共有の外部ストレージ](https://developer.android.com/training/data-storage#filesExternal)をサポートしている。このストレージは、リムーバブル（ SD カードなど）または内蔵（非リムーバブル）である。<br>
外部ストレージに保存されたファイルは誰でも読み取り可能である。 USB 大容量ストレージが有効な場合、ユーザはそれらを変更することができる。 以下のコードを使用することで、機密情報を password.txt の内容として外部ストレージに永続的に保存することができる。

Java での例:
```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

Kotlin での例:
```Kotlin
val password = "SecretPassword"
val path = context.getExternalFilesDir(null)
val file = File(path, "password.txt")
file.appendText(password)
```

アクティビティが呼び出されると、ファイルが作成されデータが外部ストレージの平文ファイルに保存される。

また、ユーザがアプリケーションをアンインストールしても、アプリケーションフォルダ（ data/data/\<package-name\>/ ）の外側に保存されたファイルは削除されないことも理解しておく必要がある。最後に、攻撃者が外部ストレージを使用して、場合によってはアプリケーションを任意に制御できることに注意する必要がある。詳細については、 [Checkpoint 社のブログ](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/)を参照する。

参考資料
* [owasp-mastg Data Storage Methods Overview External Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#external-storage)

### SharedPreferences

[SharedPreferences](https://developer.android.com/training/data-storage/shared-preferences) API は、通常、キーと値のペアの小さなコレクションを永続的に保存するために使用される。<br>
SharedPreferences オブジェクトに格納されたデータは、プレーンテキストの XML ファイルに書き込まれる。SharedPreferences オブジェクトは、誰でも読み取り可能 (すべてのアプリからアクセス可能) または非公開として宣言できる。
SharedPreferences APIを誤って使用すると、機密データが流出する可能性がある。<br>
利用する場合は次の例を参考に検討する必要がある。

Java での例:
```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Kotlin での例:
```kotlin
var sharedPref = getSharedPreferences("key", Context.MODE_WORLD_READABLE)
var editor = sharedPref.edit()
editor.putString("username", "administrator")
editor.putString("password", "supersecret")
editor.commit()
```

アクティビティが呼び出されると、提供されたデータを使用して key.xml ファイルが作成される。このコードは、いくつかのベストプラクティスに違反している。

* ユーザ名とパスワードは平文で /data/data/\<package-name\>/shared_prefs/key.xml に保存される。
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

* MODE_WORLD_READABLE は、すべてのアプリケーションが key.xml のコンテンツにアクセスして読み取ることを許可する。
```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118    170 2016-04-23 16:51 key.xml
```

※ MODE_WORLD_READABLE と MODE_WORLD_WRITEABLE は、API level 17 以降では非推奨になっていることに注意する。新しいデバイスはこの影響を受けない可能性があるが、 android:targetSdkVersion の値が 17 未満でコンパイルされたアプリケーションは、 Android 4.2 （ API level 17 ）より前にリリースされた OS バージョンで実行される場合、影響を受ける可能性がある。

参考資料
* [owasp-mastg Data Storage Methods Overview Shared Preferences](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#shared-preferences)

### データベース

Android プラットフォームは、前のリストで前述したように、多数のデータベースオプションを提供する。各データベースオプションには、理解する必要のある独自の癖やメソッドが存在する。

参考資料
* [owasp-mastg  Data Storage Methods Overview Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#databases)

#### SQLite

**SQLite データベース（非暗号化）**<br>
SQLite は、.db ファイルにデータを格納する SQL データベースエンジンである。 Android SDK には、 SQLite データベースの[サポートが組み込まれている](https://developer.android.com/training/data-storage/sqlite)。データベースの管理に使用される主なパッケージは android.database.sqlite である。例えば、次のコードを使用して、機密情報を Activity 内に格納できる。

Java での例：
```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure", MODE_PRIVATE, null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Kotlin での例：
```Kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
notSoSecure.close()
```

Activity が呼び出されると、提供されたデータを使用してデータベースファイル privateNotSoSecure が作成され、平文ファイル /data/data/\<package-name\>/databases/privateNotSoSecure に保存される。

データベースのディレクトリには、SQLite データベース以外にいくつかのファイルが含まれる場合がある。
* [Journal files](https://www.sqlite.org/tempfiles.html)：アトミックコミットとロールバックを実装するために使用される一時ファイル。
* [Lock files](https://www.sqlite.org/lockingv3.html)：ロックおよびジャーナリング機能の一部で、 SQLite の同時実行性を向上させ、 writer 不足の問題を軽減するように設計されている。

機密情報は、暗号化されていない SQLite データベースに保存しないこと。

**SQLite データベース（暗号化）**<br>
ライブラリ [SQLCipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/) を使用すると、 SQLite データベースをパスワードで暗号化できる。

Java での例：
```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();
```

Kotlin での例：
```Kotlin
var secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null)
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);")
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');")
secureDB.close()
```

データベースキーを安全に取得するには、次の方法がある。
* アプリを起動すると、 PIN またはパスワードを使用してデータベースを復号するようにユーザに要求する（脆弱なパスワードと PIN はブルートフォース攻撃に対して脆弱である）。
* キーをサーバに保存し、Web サービスからのみアクセスできるようにする（デバイスがオンラインの場合にのみアプリを使用できるようにする）。

参考資料
* [owasp-mastg Data Storage Methods Overview SQLite Databases (Encrypted)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#sqlite-databases-encrypted)
* [owasp-mastg Data Storage Methods Overview SQLite Database (Unencrypted)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#sqlite-database-unencrypted)

#### Firebase

Firebase は 15 を超える製品を備えた開発プラットフォームであり、その内の 1 つが Firebase Real-time Database である。アプリケーション開発者が活用することで、 NoSQL のクラウドホスティングデータベースにデータを保存し、同期させることができる。データは JSON として保存され、接続されているすべてのクライアントとリアルタイムで同期し、アプリケーションがオフラインになっても引き続き利用できる。

誤って構成された Firebase インスタンス、は次のネットワーク呼び出しを行うことで識別できる。

`https://_firebaseProjectName_.firebaseio.com/.json`

firebaseProjectName は、アプリケーションをリバースエンジニアリングすることにより、モバイルアプリケーションから取得できる。または、アナリストは以下に示すように、上記のタスクを自動化する Python スクリプトである [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner) を使用できる。

```bash
python FirebaseScanner.py -p <pathOfAPKFile>

python FirebaseScanner.py -f <commaSeperatedFirebaseProjectNames>
```

参考資料
* [owasp-mastg Data Storage Methods Overview Firebase Real-time Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#firebase-real-time-databases)

#### Realm

[Realm Database for Java](https://www.mongodb.com/docs/realm-sdks/java/latest/index.html) は、開発者の間でますます人気が高まっている。データベースとそのコンテンツは、構成ファイルに格納されているキーを使用して暗号化できる。

```java
//the getKey() method either gets the key from the server or from a KeyStore, or is derived from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
  .encryptionKey(getKey())
  .build();

Realm realm = Realm.getInstance(config);

```

データベースが暗号化されていない場合は、データを取得できてしまうため確認が必要。データベースが暗号化されている場合は、キーがソースまたはリソースにハードコードされているかどうか、共有設定またはその他の場所に保護されずに保存されているかどうかを確認すること。

参考資料
* [owasp-mastg Data Storage Methods Overview Realm Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#realm-databases)

### ルールブック

1. [機密データはアプリコンテナまたはシステムの資格情報保存機能へ保存する（必須）](#機密データはアプリコンテナまたはシステムの資格情報保存機能へ保存する必須)

#### 機密データはアプリコンテナまたはシステムの資格情報保存機能へ保存する（必須）
機密データを安全に保存するためには、システムの資格情報保存機能（ Android Keystore ）で管理されたキーによるデータの暗号化と、暗号化されたデータをアプリコンテナ(内部ストレージ)へ保存を徹底する必要がある。 Android Keystore の利用方法については、「[暗号化キーの保存方法（必須）](#暗号化キーの保存方法必須)」を参照。

また、外部からの読み取りを避けるために、アプリだけが内部ストレージ内のファイルを読み書きできるように実装する必要がある。
内部ストレージ内のファイルを作成する方法として、ストリームを使用する方法がある。この方法では、 [Context#openFileOutput](https://developer.android.com/reference/android/content/Context?hl=ja#openFileOutput(java.lang.String,%20int)) を呼び出して、 filesDir ディレクトリ内のファイルへアクセスするための [FileOutputStream](https://developer.android.com/reference/java/io/FileOutputStream?hl=ja) オブジェクトを取得する。 指定のファイルが存在しない場合は、 新規でファイルが作成される。

Context#openFileOutput の呼び出しでは、ファイルモードを指定する必要がある。指定するファイルモードによって、作成されるファイルの読み書き可能な範囲が決まる。<br>
下記は主なファイルモードである。

* MODE_PRIVATE
* MODE_WORLD_READABLE
* MODE_WORLD_WRITEABLE

下記は Context#openFileOutput 呼び出しの一例。なお、 Android 7.0 （ API level 24 ）以降を搭載したデバイスでは、ファイルモードに MODE_PRIVATE を指定しない場合、呼び出し時に [SecurityException](https://developer.android.com/reference/java/lang/SecurityException?hl=ja) が発生する。

```java
String filename = "myfile";
String fileContents = "Hello world!";
try (FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE)) {
    fos.write(fileContents.toByteArray());
}
```

**ファイルモード設定 MODE_PRIVATE**<br>
デフォルトのモードで、作成されたファイルは呼び出し元のアプリケーション、又は同じユーザ ID を共有するすべてのアプリケーションがアクセスできる。

```java
public static final int MODE_PRIVATE
```

**ファイルモード設定 MODE_WORLD_READABLE**<br>
作成されたファイルへの読み取りアクセスを、他のすべてのアプリケーションが可能となる。<br>
なお、 MODE_WORLD_READABLE の使用は API level 17 以降非推奨となっている。

```java
public static final int MODE_WORLD_READABLE
```

**ファイルモード設定 MODE_WORLD_WRITEABLE**<br>
作成されたファイルへの読み取りアクセスを、他のすべてのアプリケーションが可能となる。<br>
なお、 MODE_WORLD_WRITEABLE の使用は API level 17 以降非推奨となっている。

```java
public static final int MODE_WORLD_WRITEABLE
```

これに違反する場合、以下の可能性がある。
* 他のアプリや第三者に機密データを読み取られる。

## MSTG-STORAGE-3
機密データはアプリケーションログに書き込まれていない。

### ログ出力

このテストケースでは、システムログとアプリケーションログの両方から、機密性の高いアプリケーションデータを特定することに重点を置いている。<br>
以下のチェックを実施すること。

* ソースコードを解析し、ロギングに関連するコードを確認する。
* アプリケーションデータディレクトリにログファイルがあるかどうか確認する。
* システムメッセージとログを収集し、機密データが含まれていないかを分析する。

機密性の高いアプリケーションデータの漏洩を防ぐための一般的な推奨事項として、アプリケーションで必要と見なされる又はセキュリティ監査の結果などで安全であると明示されない限り、ログ記録は本番リリースから削除するべきである。

参考資料
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#testing-logs-for-sensitive-data-mstg-storage-3)

#### ファイル書き込み

アプリケーションは、ログを作成するために [Log クラス](https://developer.android.com/reference/android/util/Log)と [Logger クラス](https://developer.android.com/reference/java/util/logging/Logger.html)を使用する。これを見つけるには、アプリケーションのソースコードを検証し、そのようなロギングクラスがないかを調べる。<br>
これらは多くの場合、以下のキーワードで検索することで見つけることができる。

* 関数/クラスでのキーワード
  * android.util.Log
  * Log.d | Log.e | Log.i | Log.v | Log.w | Log.wtf
  * Logger

* システム出力に関するキーワード
  * System.out.print | System.err.print
  * logfile
  * logging
  * logs

参考資料
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#static-analysis-2)

ルールブック
* [ログを出力する場合は出力内容に機密情報を含めない（必須）](#ログを出力する場合は出力内容に機密情報を含めない必須)

#### Logcat 出力

モバイルアプリケーションのすべての機能を少なくとも一度は使用し、アプリケーションのデータディレクトリを特定し、ログファイル（/data/data/<パッケージ名>）を探す。<br>
アプリケーションのログを確認し、ログデータが生成されているかどうかを判断する。<br>
一部のモバイルアプリケーションでは、データディレクトリに独自のログを作成し保存している。

多くのアプリケーション開発者は、適切なロギングクラスの代わりに System.out.println または printStackTrace を使用している。<br>
したがって、テスト戦略にはアプリケーションの起動、実行、終了時に生成される全ての出力を含める必要がある。<br>
System.out.println または printStackTrace によって直接出力されるデータを特定する場合は [Logcat](https://developer.android.com/studio/command-line/logcat) を使用する。

以下のように Logcat の出力をフィルタリングすることで、特定のアプリをターゲットにすることができる。
```bash
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

※アプリの PID が既にわかっている場合は、 --pid フラグを使用して直接指定が可能。

ログに特定の文字列またはパターンが表示される場合は、さらにフィルタまたは正規表現を適用することも可能である（例. Logcat の正規表現フラグ -e <expr>, --regex=<expr> ）。

参考資料
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#dynamic-analysis-1)

#### ProGuard によるログ機能削除

本番リリースの準備として、[ProGuard](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#proguard) (Android Studio に含まれる ) などのツールを使用することができる。<br>
android.util.Log クラスのすべてのロギング機能が削除されたかどうかを判断するには、ProGuard 構成ファイル (proguard-rules.pro) で次のオプションを確認する（[ロギングコードを削除するこの例](https://www.guardsquare.com/manual/configuration/examples#logging)と、[Android Studio プロジェクトでの ProGuard の有効化](https://developer.android.com/studio/build/shrink-code#enable)に関するこの記事に従うこと)。

```default
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

上記の例では、Log クラスのメソッドの呼び出しが削除されることだけが保証されていることに注意する。<br>
ログに記録される文字列が動的に生成される場合、その文字列を生成するコードはバイトコードに残る可能性がある。<br>
例えば、次のコードは暗黙のうちに StringBuilder を発行してログステートメントを生成する。

Java での例：
```java
Log.v("Private key tag", "Private key [byte format]: " + key);
```

Kotlin での例：
```Kotlin
Log.v("Private key tag", "Private key [byte format]: $key")
```

ただし、コンパイルされたバイトコードは、文字列を明示的に生成する次のログステートメントのバイトコードと同等である。

Java での例：
```java
Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

Kotlin での例：
```Kotlin
Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
```

ProGuard は、Log.v メソッド呼び出しの削除を保証する。 残りのコード (new StringBuilder ...) が削除されるかは、コードの複雑さと [ProGuard のバージョン](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation)に依存する。<br>
これは、（未使用の）文字列が平文データをメモリ上に漏洩させ、デバッガやメモリダンプによってアクセスされる可能性があるため、セキュリティ上のリスクとなる。<br>
この問題に対するクリティカルな対処法は存在しないが、1つの選択肢としては単純な引数を取得し、ログステートメントを内部的に構築するカスタムロギング機能を実装する方法がある。

```java
SecureLog.v("Private key [byte format]: ", key);
```

その後、ProGuard がその呼び出しを除去するように設定する。

参考資料
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#static-analysis-2)

### ルールブック

1. [ログを出力する場合は出力内容に機密情報を含めない（必須）](#ログを出力する場合は出力内容に機密情報を含めない必須)

#### ログを出力する場合は出力内容に機密情報を含めない（必須）
ログ出力をする場合は、出力内容に機密情報が含まれていないことを確認する必要がある。

一般的なログ出力用クラスとしては、以下が存在する。

* Log
* Logger

**Log クラス**

android.util パッケージに含まれるログ出力用のクラスで、Log.v(), Log.d(), Log.i(), Log.w(), Log.e() メソッドを使用してログを書き込む。書き込んだログは Logcat 上で確認することができる。

各メソッドはログのレベルごとに区分けされている。
以下はログのレベルと、それに紐づくメソッドの一覧である。
| No | ログレベル | メソッド |
| :--- | :--- | :--- |
| 1 | DEBUG | Log.d |
| 2 | ERROR | Log.e |
| 3 | INFO | Log.i |
| 4 | VERBOSE | Log.v |
| 5 | WARN | Log.w |
| 6 | What a Terrible Failure | Log.wtf |

下記は Log クラスによるログ出力コードの一例。
```java
private static final String TAG = "MyActivity";
Log.v(TAG, "index=" + i);
```

**Logger クラス**

java.util.logging に含まれるログ出力用のクラスで、特定のシステムまたはアプリケーションコンポーネントのメッセージをログに記録するために使用する。通常、階層的なドット区切りの名前空間を使用して名前が付けられる。 Logger 名は任意の文字列にすることができるが、通常はログに記録されるコンポーネントのパッケージ名またはクラス名（ java.net や javax.swing など）に基づいている必要がある。

下記は Logger クラスによるログ出力コードの一例。
```java
class DiagnosisMessages {
  static String systemHealthStatus() {
    // collect system health information
    ...
  }
}
...
logger.log(Level.FINER, DiagnosisMessages.systemHealthStatus());
```

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

## MSTG-STORAGE-4
機密データはアーキテクチャに必要な部分でない限りサードパーティと共有されていない。

### アプリデータの共有

機密情報がサードパーティに漏洩する可能性の一例として、以下のような手段がある。

参考資料
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#overview-3)

#### サードパーティサービスへのデータの共有

サードパーティサービスが提供する機能には、アプリ使用中のユーザの行動を監視するためのトラッキングサービス、バナー広告の販売、またはユーザエクスペリエンスの向上が含まれる。

欠点として、通常開発者は利用するサードパーティライブラリを介して実行されるコードの詳細を把握することができない。したがって、必要以上の情報をサービスに送信したり、機密情報を公開すべきではない。

サードパーティサービスの多くは、以下の 2 つの方法で実装されている。
* スタンドアローンライブラリ
* full SDK を使用

**静的解析**<br>
サードパーティライブラリが提供する API 呼び出しと関数がベストプラクティスに従って使用されているかどうかを判断するには、ソースコードを確認し、アクセス許可を要求し、既知の脆弱性が存在しないかを確認する（「[サードパーティライブラリ使用時の注意点（ MSTG-CODE-5 ）](0x08-MASDG-Code_Quality_and_Build_Setting_Requirements.md#サードパーティライブラリ使用時の注意点)」を参照）。

サードパーティサービスに送信される全てのデータは、サードパーティがユーザアカウントを識別できるようにする PII （個人識別情報）の公開を防ぐために、匿名化する必要がある。 その他のデータ（ユーザアカウントまたはセッションにマッピングできる ID など）をサードパーティに送信しないようにすること。

**動的解析**<br>
機密情報が埋め込まれていないか、外部サービスへのすべてのリクエストを確認する。 クライアントとサーバ間のトラフィックを傍受するには、[Burp Suite](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#burp-suite) Professional または [OWASP ZAP](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#owasp-zap) を使用して中間者（ MITM ）攻撃を開始することにより、動的分析を実行できる。<br>
傍受プロキシを介してトラフィックをルーティングすることで、アプリとサーバの間を通過するトラフィックを傍受できる。メイン関数がホストされているサーバに直接送信されない全てのアプリリクエストは、トラッカーや広告サービスの PII などの機密情報についてチェックする必要がある。

参考資料
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app-1)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app-2)

ルールブック
* [サードパーティライブラリへ必要のない機密情報を共有しない（必須）](#サードパーティライブラリへ必要のない機密情報を共有しない必須)

#### アプリの通知によるデータの共有

[通知](https://developer.android.com/guide/topics/ui/notifiers/notifications)はプライベートで利用すべきではないことを理解することが重要である。通知が Android システムによって処理されると、システム全体にブロードキャストされ、 [NotificationListenerService](https://developer.android.com/reference/kotlin/android/service/notification/NotificationListenerService) で実行されているアプリケーションはこれらの通知を受信し、必要に応じて処理することができる。

[Joker](https://research.checkpoint.com/2020/new-joker-variant-hits-google-play-with-an-old-trick/) や [Alien](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise.html) など、 NotificationListenerService を悪用してデバイスの通知を受信し、攻撃者が管理する C2 インフラストラクチャに送信するマルウェアのサンプルが多数存在する。一般的にこれは、デバイス上の通知として表示される二要素認証（ 2FA ）コードを受信し、それを攻撃者に送信する。ユーザにとってより安全な代替手段は、通知を生成しない 2FA アプリケーションを使用することである。

さらに、Google Play ストアには、基本的に Android システム上の全ての通知をローカルに記録する通知ログを提供するアプリが多数存在する。これは、 Android では通知が決してプライベートなものではなく、デバイス上の他のアプリからアクセス可能なことを強調している。

そのため、悪意のあるアプリケーションによって使用される可能性のある機密情報やリスクの高い情報がないか、全ての通知の使用を検証する必要がある。

**静的解析**<br>
何らかの通知管理処理に用いられる可能性のある NotificationManager クラスの使用を確認する。このクラスが使用されている場合は、次にアプリケーションがどのように[通知を生成](https://developer.android.com/training/notify-user/build-notification#SimpleNotification)し、どのデータが最終的に表示されるかを理解する必要がある。

**動的解析**<br>
アプリケーションを実行し、[NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) の setContentTitle や setContentText など、通知の作成に関連する関数の全呼び出しをトレースする。その後トレース結果を確認し、他のアプリが盗聴した可能性のあるデータに機密情報が含まれているかどうかを評価する。

参考資料
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-1)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-2)

ルールブック
* [通知に機密情報を含めない（必須）](#通知に機密情報を含めない必須)

### ルールブック
1. [サードパーティライブラリへ必要のない機密情報を共有しない（必須）](#サードパーティライブラリへ必要のない機密情報を共有しない必須)
1. [通知に機密情報を含めない（必須）](#通知に機密情報を含めない必須)

#### サードパーティライブラリへ必要のない機密情報を共有しない（必須）
サードパーティライブラリを使用する場合は、ライブラリへ渡すパラメータとして、必要でない機密情報が設定されていないことを確認する。
必要でない機密情報が設定されている場合、ライブラリ内の処理で悪質に利用される可能性があるため注意する。

通信用のライブラリでは必要とされる場合があるため、上記懸念を考慮する場合は、事前にサーバ・クライアント間で決めた暗号化方式により機密情報を暗号化して、ライブラリに渡す等の対応が必要である。

これに違反する場合、以下の可能性がある。
* サードパーティライブラリの処理で悪用される可能性がある。

#### 通知に機密情報を含めない（必須）
発生したイベントをユーザに通知するためには [NotificationManager](https://developer.android.com/reference/android/app/NotificationManager) クラスを使用する。

通知の構成要素（表示内容）は [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) オブジェクトに指定する。<br>
NotificationCompat.Builder クラスには通知の構成要素を指定するためのメソッドが用意されている。下記は指定用メソッドの一例。

* setContentTitle ： 標準通知で、通知のタイトル (最初の行) を指定する。
* setContentText ： 標準通知で、通知のテキスト ( 2 行目) を指定する。

通知を使用する場合は、 setContentTitle, setContentText に機密情報が設定されていないことに注意する。

下記は NotificationCompat.Builder クラスへ通知の構成要素を指定し、 NotificationManager クラスにより通知を表示するソースコードの一例。

```kotlin
    var builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.notification_icon)
            .setContentTitle(textTitle)
            .setContentText(textContent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
    with(NotificationManagerCompat.from(this)) {
        // notificationIDとbuilder.build()を渡します
        notify(notificationID, builder.build())
    }
```

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

## MSTG-STORAGE-5
機密データを処理するテキスト入力では、キーボードキャッシュが無効にされている。

### 機密データの自動入力

ユーザが入力フィールドに入力すると、ソフトウェアが自動的にデータをサジェストする。この機能は、メッセージアプリにおいて非常に便利である。しかし、ユーザがこのタイプの情報を取得する入力フィールドを選択した場合、キーボードキャッシュが機密情報を開示する可能性がある。

**静的解析**<br>
Activity のレイアウト定義では、XML 属性を持つ TextView を定義できる。 XML 属性 android:inputType に値 textNoSuggestions が指定されている場合、入力フィールドが選択されたときにキーボードキャッシュは表示されなくなる。そのため、ユーザは全てを手動で入力する必要がある。

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

機密情報を入力するすべての入力フィールドのコードには、[キーボードによるサジェストを無効](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_FLAG_NO_SUGGESTIONS)にするために、この XML 属性を含める必要がある。

**動的解析**<br>
アプリを起動し、機密データを取得する入力フィールドをクリックする。その際に文字列がサジェストされた場合、これらのフィールドのキーボードキャッシュは無効になっていない。

参考資料
* [owasp-mastg Determining Whether the Keyboard Cache Is Disabled for Text Input Fields MSTG-STORAGE-5)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#determining-whether-the-keyboard-cache-is-disabled-for-text-input-fields-mstg-storage-5)

ルールブック
* [機密情報を入力するすべての入力フィールドのコードは、キーボードによるサジェストが無効となるように実装する（必須）](#機密情報を入力するすべての入力フィールドのコードはキーボードによるサジェストが無効となるように実装する必須)
* [機密情報を入力するすべての入力フィールドのレイアウトは、キーボードによるサジェストが無効となるように実装する（必須）](#機密情報を入力するすべての入力フィールドのレイアウトはキーボードによるサジェストが無効となるように実装する必須)

### ルールブック
1. [機密情報を入力するすべての入力フィールドのコードは、キーボードによるサジェストが無効となるように実装する（必須）](#機密情報を入力するすべての入力フィールドのコードはキーボードによるサジェストが無効となるように実装する必須)
1. [機密情報を入力するすべての入力フィールドのレイアウトは、キーボードによるサジェストが無効となるように実装する（必須）](#機密情報を入力するすべての入力フィールドのレイアウトはキーボードによるサジェストが無効となるように実装する必須)

#### 機密情報を入力するすべての入力フィールドのコードは、キーボードによるサジェストが無効となるように実装する（必須）

テキスト入力および変更をする場合に EditText クラスを使用する。テキスト編集ウィジェットを定義する場合、 android.R.styleable#TextView_inputType 属性を設定する必要がある。

機密情報を入力するフィールドのコードでは、 inputType 属性へ TYPE_TEXT_FLAG_NO_SUGGESTIONS フラグを設定する。
ただし、パスワードや PIN を入力するフィールドの場合には、マスキング用に inputType 属性へ TYPE_TEXT_VARIATION_PASSWORD フラグを設定([入力テキスト](#入力テキスト)参照)する。

下記はコード上で inputType 属性のフラグとして TYPE_TEXT_FLAG_NO_SUGGESTIONS を設定するコードの一例。

```kotlin
val editText1: EditText = findViewById(R.id.editText1)
editText1.apply {
    inputType = InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
}
```

また、キャッシュを再度有効にする値で上書きしていないか確認する必要がある。

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

#### 機密情報を入力するすべての入力フィールドのレイアウトは、キーボードによるサジェストが無効となるように実装する（必須）
機密情報を入力するフィールドのレイアウト（ EditText ）では、inputType 属性へ "textNoSuggestions" を設定する。
ただし、パスワードや PIN を入力するフィールドの場合には、マスキング用に inputType 属性へ "textPassword" を設定([入力テキスト](#入力テキスト)参照)する。

下記はコード上で inputType 属性として "textNoSuggestions" を設定するコードの一例。

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

## MSTG-STORAGE-6
機密データはIPCメカニズムを介して公開されていない。

### ContentProvider による機密データへのアクセス

Android の IPC メカニズムの一部として、 ContentProvider はアプリの保存データに他のアプリがアクセスして変更できるよう許可する。適切に設定されていない場合、これらのメカニズムから機密データが漏洩する可能性がある。

**静的解析**<br>
AndroidManifest.xml を調べることで、アプリが公開する ContentProvider を検出することができる。 ContentProvider は、 \<provider\> 要素で特定できる。

* exportタグ (android:exported) の値が 「 true 」であるかどうかを判定する。そうでない場合でも、タグに \<intent-filter\> が定義されていれば、タグは自動的に「 true 」が設定される。アプリからのアクセスのみを想定している場合は、 android:exported を「 false 」に設定する。そうでない場合は、フラグを「 true 」に設定し、適切な読み取り/書き込み権限を定義する。
* データが permission タグ (android:permission) によって保護されているかどうかを判断する。 permission タグは、他のアプリへの公開を制限する。
* android:protectionLevel 属性の値に signature があるかどうかを判断する。この設定は、同じ企業のアプリのみがデータにアクセスすることを意図していることを示す (つまり、同じキーで signature されている)。他のアプリからデータにアクセスできるようにするには、 \<permission\> 要素でセキュリティポリシーを適用し、適切な android:protectionLevel を設定する。
android:permission を使用する場合、他のアプリケーションは ContentProvider にアクセスするために、 manifest で対応する \<uses-permission\> 要素を宣言する必要がある。 android:grantUriPermissions 属性を使用して、他のアプリケーションにより具体的なアクセスを許可することができる。 \<grant-uri-permission\> 要素を使用してアクセスを制限することができる。

ソースコードを調べて、 ContentProvider の使用方法を把握する。次のキーワードを検索する。
* android.content.ContentProvider
* android.database.Cursor
* android.database.sqlite
* .query
* .update
* .delete

※アプリ内での SQL インジェクション攻撃を回避するには、query, update, delete などのパラメータ化されたクエリメソッドを使用する。すべてのメソッド引数を適切にサニタイズすること。 例えば、selection 引数が連結されたユーザ入力で構成されている場合、SQL インジェクションにつながる可能性がある。

ContentProvider を公開する場合は、パラメータ化された[クエリメソッド](https://developer.android.com/reference/android/content/ContentProvider#query%28android.net.Uri%2C%20java.lang.String%5B%5D%2C%20java.lang.String%2C%20java.lang.String%5B%5D%2C%20java.lang.String%29)（ query, update, delete ）を使用して SQL インジェクションを防止しているかどうかを確認する。その場合は、すべての引数が適切にサニタイズされていることを確認すること。

脆弱性のある ContentProvider の例として、脆弱性のあるパスワードマネージャアプリ「 [Sieve](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk) 」が存在する。

**Android Manifest の検証**<br>
定義された全ての \<provider\> 要素を特定する。

```xml
<provider
      android:authorities="com.mwr.example.sieve.DBContentProvider"
      android:exported="true"
      android:multiprocess="true"
      android:name=".DBContentProvider">
    <path-permission
          android:path="/Keys"
          android:readPermission="com.mwr.example.sieve.READ_KEYS"
          android:writePermission="com.mwr.example.sieve.WRITE_KEYS"
     />
</provider>
<provider
      android:authorities="com.mwr.example.sieve.FileBackupProvider"
      android:exported="true"
      android:multiprocess="true"
      android:name=".FileBackupProvider"
/>
```

上記の AndroidManifest.xml に示されているように、アプリケーションは 2 つの ContentProvider をエクスポートする。<br>
その内パス（ "/Keys" ）は、読み取りと書き込みのアクセス許可によって保護されていることに注意すること。

**ソースコードの検証**<br>
DBContentProvider.java ファイルのクエリ関数を調べて、機密情報が漏洩していないかどうかを確認する。

Java での例：
```java
public Cursor query(final Uri uri, final String[] array, final String s, final String[] array2, final String s2) {
    final int match = this.sUriMatcher.match(uri);
    final SQLiteQueryBuilder sqLiteQueryBuilder = new SQLiteQueryBuilder();
    if (match >= 100 && match < 200) {
        sqLiteQueryBuilder.setTables("Passwords");
    }
    else if (match >= 200) {
        sqLiteQueryBuilder.setTables("Key");
    }
    return sqLiteQueryBuilder.query(this.pwdb.getReadableDatabase(), array, s, array2, (String)null, (String)null, s2);
}
```

Kotlin での例：
```Kotlin
fun query(uri: Uri?, array: Array<String?>?, s: String?, array2: Array<String?>?, s2: String?): Cursor {
        val match: Int = this.sUriMatcher.match(uri)
        val sqLiteQueryBuilder = SQLiteQueryBuilder()
        if (match >= 100 && match < 200) {
            sqLiteQueryBuilder.tables = "Passwords"
        } else if (match >= 200) {
            sqLiteQueryBuilder.tables = "Key"
        }
        return sqLiteQueryBuilder.query(this.pwdb.getReadableDatabase(), array, s, array2, null as String?, null as String?, s2)
    }
```

ここでは、実際には "/Keys" と "/Passwords" の2つのパスがあり、後者は manifest で保護されていないため、脆弱性があることが確認できる。

URIにアクセスする場合、クエリ文はすべてのパスワードとパス "Passwords/" を返す。これについては「動的解析」セクションで説明し、必要な正確な URI を示す。

**動的解析**<br>
**ContentProvider のテスト**<br>
アプリケーションの ContentProvider を動的に解析するには、まず攻撃対象領域を列挙する。アプリのパッケージ名を Drozer モジュール app.provider.info に渡す。

```bash
dz> run app.provider.info -a com.mwr.example.sieve
  Package: com.mwr.example.sieve
  Authority: com.mwr.example.sieve.DBContentProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.DBContentProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
  Path Permissions:
  Path: /Keys
  Type: PATTERN_LITERAL
  Read Permission: com.mwr.example.sieve.READ_KEYS
  Write Permission: com.mwr.example.sieve.WRITE_KEYS
  Authority: com.mwr.example.sieve.FileBackupProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.FileBackupProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
```

この例では、2 つのコンテンツ プロバイダーがエクスポートされている。 DBContentProvider の "/Keys" パスを除いて、どちらも許可なくアクセスができる。 この情報を使用して、コンテンツ URI の一部を再構築して DBContentProvider にアクセスできる（ URI は content:// で始まる）。

アプリケーション内で ContentProvider の URI を識別するには、Drozer の scanner.provider.finduris モジュールを使用する。 このモジュールは、いくつかの方法でパスを推測し、アクセス可能なコンテンツ URI を決定する。

```bash
dz> run scanner.provider.finduris -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Unable to Query content://com.mwr.example.sieve.DBContentProvider/
...
Unable to Query content://com.mwr.example.sieve.DBContentProvider/Keys
Accessible content URIs:
content://com.mwr.example.sieve.DBContentProvider/Keys/
content://com.mwr.example.sieve.DBContentProvider/Passwords
content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

アクセス可能な ContentProvider のリストを取得したら、 app.provider.query モジュールを使用して各プロバイダからデータを抽出してみること。

```bash
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
_id: 1
service: Email
username: incognitoguy50
password: PSFjqXIMVa5NJFudgDuuLVgJYFD+8w== (Base64 - encoded)
email: incognitoguy50@gmail.com
```

また Drozer を使用して、脆弱な ContentProvider からレコードを insert, update、および delete することもできる。

* Insert レコード
  ```bash
  dz> run app.provider.insert content://com.vulnerable.im/messages
                --string date 1331763850325
                --string type 0
                --integer _id 7
  ```
* Update レコード
  ```bash
  dz> run app.provider.update content://settings/secure
                --selection "name=?"
                --selection-args assisted_gps_enabled
                --integer value 0
  ```
* Delete レコード
  ```bash
  dz> run app.provider.delete content://settings/secure
                --selection "name=?"
                --selection-args my_setting
  ```

**ContentProvider における SQL インジェクション**<br>
Android プラットフォームは、ユーザデータを格納するために SQLite データベースを推進している。これらのデータベースは SQL に基づいているため、SQL インジェクションに対して脆弱である可能性がある。<br>
Drozer モジュール app.provider.query を使用して、 ContentProvider に渡される射影および選択フィールドを操作することにより、 SQL インジェクションをテストできる。

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"
unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')
```

アプリケーションが SQL インジェクションに対して脆弱な場合、詳細なエラーメッセージが返される。 Android の SQL インジェクションは、脆弱な ContentProvider からのデータの変更、またはクエリするために使用される可能性がある。次の例では、Drozer モジュール app.provider.query を使用して、全てのデータベーステーブルを一覧表示する。

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "*
FROM SQLITE_MASTER WHERE type='table';--"
| type  | name             | tbl_name         | rootpage | sql              |
| table | android_metadata | android_metadata | 3        | CREATE TABLE ... |
| table | Passwords        | Passwords        | 4        | CREATE TABLE ... |
| table | Key              | Key              | 5        | CREATE TABLE ... |
```

SQL インジェクションを使用して、保護されていないテーブルからデータを取得することもできる。

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
| Password | pin |
| thisismypassword | 9876 |
```

アプリ内の脆弱な ContentProvider を自動的に検出する scanner.provider.injection モジュールを使用して、これらの手順を自動化できる。

```default
dz> run scanner.provider.injection -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Injection in Projection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
Injection in Selection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

**ファイルシステムベースの ContentProvider**<br>
ContentProvider は、基盤となるファイルシステムへのアクセスを提供できる。これにより、アプリはファイルを共有できる（通常、 Android サンドボックスはこれを防ぐことができる）。<br>
Drozer モジュール app.provider.read および app.provider.download を使用して、エクスポートされたファイルベースの ContentProvider からファイルをそれぞれ読み取りおよびダウンロードできる。<br>
これらの ContentProvider はディレクトリトラバーサルの影響を受けやすく、ターゲットアプリケーションのサンドボックス内で保護されているファイルが読み取られる可能性がある。

```default
dz> run app.provider.download content://com.vulnerable.app.FileProvider/../../../../../../../../data/data/com.vulnerable.app/database.db /home/user/database.db
Written 24488 bytes
```

scanner.provider.traversal モジュールを使用して、ディレクトリトラバーサルの影響を受けやすい ContentProvider を見つけるプロセスを自動化することができる。

```default
dz> run scanner.provider.traversal -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Vulnerable Providers:
  content://com.mwr.example.sieve.FileBackupProvider/
  content://com.mwr.example.sieve.FileBackupProvider
```

adb は、 ContentProvider のクエリにも使用できることに注意すること。
```bash
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
Row: 0 id=1, username=admin, password=StrongPwd
Row: 1 id=2, username=test, password=test
...
```

参考資料
* [owasp-mastg Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms (MSTG-STORAGE-6)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#determining-whether-sensitive-stored-data-has-been-exposed-via-ipc-mechanisms-mstg-storage-6)

ルールブック
* [ContentProvider のアクセス権限を適切に設定する（必須）](#contentprovider-のアクセス権限を適切に設定する必須)
* [SQL データベース利用時は SQL インジェクションを対策する（必須）](#sql-データベース利用時は-sql-インジェクションを対策する必須)
* [ContentProvider 利用時はディレクトリトラバーサルを対策する（必須）](#contentprovider-利用時はディレクトリトラバーサルを対策する必須)

### ルールブック
1. [ContentProvider のアクセス権限を適切に設定する（必須）](#contentprovider-のアクセス権限を適切に設定する必須)
1. [SQL データベース利用時は SQL インジェクションを対策する（必須）](#sql-データベース利用時は-sql-インジェクションを対策する必須)
1. [ContentProvider 利用時はディレクトリトラバーサルを対策する（必須）](#contentprovider-利用時はディレクトリトラバーサルを対策する必須)

#### ContentProvider のアクセス権限を適切に設定する（必須）

アプリ内のすべての ContentProvider は、 AndroidManifest.xml 内の \<provider\> 要素で定義する必要がある。未定義の場合、システムは ContentProvider を認識せず、実行しない。

対象アプリの一部である ContentProvider のみを宣言し、対象アプリ内で使用している ContentProvider であっても、他のアプリの一部であるものは宣言しないこと。

下記は AndroidManifest.xml での \<provider\> 要素の定義の一例。
```xml
<provider android:authorities="list"
          android:directBootAware=["true" | "false"]
          android:enabled=["true" | "false"]
          android:exported=["true" | "false"]
          android:grantUriPermissions=["true" | "false"]
          android:icon="drawable resource"
          android:initOrder="integer"
          android:label="string resource"
          android:multiprocess=["true" | "false"]
          android:name="string"
          android:permission="string"
          android:process="string"
          android:readPermission="string"
          android:syncable=["true" | "false"]
          android:writePermission="string" >
    . . .
</provider>
```
アクセス対象のデータを考慮してコンテンツプロバイダーの設定を適切に行う必要がある。

**ContentProvider を他のアプリが使用できるか設定するタグ android:exported**<br>
このタグでは、他のアプリが ContentProvider を使用できるか設定できる。
下記が設定できる設定値である。
* true ：他のアプリが ContentProvider を使用できる。どのようなアプリでも、 ContentProvider に指定されている権限に従い、 ContentProvider のコンテンツ URI を使用して ContentProvider にアクセスできる。
* false ：他のアプリが ContentProvider を使用できません。 android:exported="false" を設定すると、 ContentProvider へのアクセスが対象アプリに限定される。これが設定されている場合に ContentProvider へアクセスできるアプリは、 ContentProvider と同じユーザ ID（ UID ）を持つアプリか、 android:grantUriPermissions タグによって一時的にアクセス権を付与されたアプリに限定される。

このタグは API level 17 で導入されたため、API level 16 以下を搭載しているすべてのデバイスは、このタグが "true" に設定されている場合と同じに動作となる。<br>
android:targetSdkVersion を 17 以上に設定した場合、API level 17 以上を搭載しているデバイスでは、デフォルト値が "false" となる。

※ exported が false の場合でも、 \<intent-filter> が定義されている場合は exported に true が設定されている場合と同じ状態となるため、注意する。

**ContentProvider のデータ読み書きで必要とする \<permission\> 要素名を設定するタグ android:permission**

ContentProvider のデータを読み書きする際にクライアントが必要とする \<permission\> 要素名を設定する。この属性は、読み取りと書き込みの両方に対して 1 つの権限を設定する際に便利である。ただし、この属性よりも [android:readPermission](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#rprmsn) 属性、 [android:writePermission](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#wprmsn) 属性、 [android:grantUriPermissions](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#gprmsn) 属性の方が優先される。 android:readPermission 属性も設定した場合、 ContentProvider に対してクエリを行うためのアクセスが制御される。また、 android:writePermission 属性を設定した場合、 ContentProvider のデータを変更するためのアクセスが制御される。

\<permission\> 要素内の [android:protectionLevel](https://developer.android.com/guide/topics/manifest/permission-element?hl=ja#plevel) タグへ保護レベルを設定することで、権限に含まれている可能性があるリスクと、権限をリクエスト元のアプリに付与するかどうかを決める際にシステムが従う必要がある手順を指定できる。

各保護レベルは、基本権限タイプと [protectionLevel](https://developer.android.com/reference/android/R.attr?hl=ja#protectionLevel) を指定する。<br>
下記が基本権限タイプの一覧である。

| 基本権限タイプ | 説明 |
| :--- | :--- |
| normal | デフォルト値。分離されたアプリレベルの機能へのアクセスをリクエスト元のアプリに提供する低リスクの権限。 |
| dangerous | リクエスト元のアプリによる個人データへのアクセスあるいはデバイスの管理を許し、ユーザに悪影響を及ぼしかねない高リスクの権限。 |
| signature | 権限を宣言したアプリと同じ証明書がリクエスト元のアプリの署名に使用されている場合にのみシステムから付与される権限。 |
| signatureOrSystem | Android システムイメージの専用フォルダにインストールされているアプリ、または権限を宣言したアプリと同じ証明書を使用して署名されたアプリにのみシステムから付与される権限。なお、API level 23 で非推奨になった。 |

**一時的に ContentProvider のデータへのアクセスを許可するタグ android:grantUriPermissions**

 ContentProvider のデータにアクセスする権限を持たないユーザに対して、そのような権限を付与できるかを設定する。付与した場合、 [android:readPermission](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#rprmsn) 属性、 [android:writePermission](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#wprmsn) 属性、 [android:permission](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#prmsn) 属性、 [android:exported](https://developer.android.com/guide/topics/manifest/provider-element?hl=ja#exported) 属性によって課される制限が一時的に解除される。権限を付与できる場合は「 true 」、そうでない場合は「 false 」に設定する。「 true 」に設定した場合、 ContentProvider の任意のデータに対して権限を付与できる。「 false 」に設定した場合、 [<grant-uri-permission>](https://developer.android.com/guide/topics/manifest/grant-uri-permission-element?hl=ja) サブ要素内にリストされるデータサブセット（存在する場合）に対してのみ権限を付与できる。デフォルト値は「false」である。

これに違反する場合、以下の可能性がある。
* 意図せず他のアプリに機密データが漏洩する可能性がある。

#### SQL データベース利用時は SQL インジェクションを対策する（必須）
ContentProvider で SQL データベースを利用する場合は SQL インジェクションを対策する必要がある。

以下へ対策方法を記載する。
1. ContentProvider を他のアプリにエクスポーズする必要がない場合:
   * マニフェスト内で、対象 ContentProvider の [\<provider\>](https://developer.android.com/guide/topics/manifest/provider-element) タグを変更して、[android:exported="false"](https://developer.android.com/guide/topics/manifest/provider-element.html#exported) に設定する。これにより、他のアプリは対象 ContentProvider にインテントを送信できなくなる。
   * [android:permission](https://developer.android.com/guide/topics/manifest/provider-element.html#prmsn) 属性を [android:protectionLevel="signature"](https://developer.android.com/guide/topics/manifest/permission-element.html#plevel) の [permission](https://developer.android.com/guide/topics/manifest/permission-element.html) に設定することで、他のデベロッパーが記述したアプリが対象の ContentProvider にインテントを送信できないようにすることもできる。
1. ContentProvider を他のアプリにエクスポーズする必要がある場合:

   rawQuery() メソッドへ渡す sql を事前にバリデーションチェックし、不要な文字のエスケープを行う。また、置換可能なパラメータとして ? を選択句と独立した選択引数の配列で使用すると、ユーザ入力が SQL ステートメントの一部として解釈されるのではなくクエリに直接束縛され、これによりリスクが軽減される。以下へサンプルコードを示す。
   ```java
   public boolean validateOrderDetails(String email, String orderNumber) {
    boolean result = false;

    // Proprietary validation check
    if (!validationParam(email, orderNumber)) {
        // For violation parameters
        return result;
    }

    Cursor cursor = db.rawQuery(
      "select * from purchases where EMAIL = ? and ORDER_NUMBER = ?",
      new String[]{email, orderNumber});
    if (cursor != null) {
        if (cursor.moveToFirst()) {
            result = true;
        }
        cursor.close();
    }
    return result;
   }
   ```

これに違反する場合、以下の可能性がある。
* SQL インジェクションの脆弱性を悪用される可能性がある。

#### ContentProvider 利用時はディレクトリトラバーサルを対策する（必須）
ContentProvider を利用する場合はディレクトリトラバーサルを対策する必要がある。

以下へ対策方法を記載する。
1. ContentProvider を他のアプリにエクスポーズする必要がない場合:
   * マニフェスト内で、対象 ContentProvider の [\<provider\>](https://developer.android.com/guide/topics/manifest/provider-element) タグを変更して、[android:exported="false"](https://developer.android.com/guide/topics/manifest/provider-element.html#exported) に設定する。これにより、他のアプリは対象 ContentProvider にインテントを送信できなくなる。
   * [android:permission](https://developer.android.com/guide/topics/manifest/provider-element.html#prmsn) 属性を [android:protectionLevel="signature"](https://developer.android.com/guide/topics/manifest/permission-element.html#plevel) の [permission](https://developer.android.com/guide/topics/manifest/permission-element.html) に設定することで、他のデベロッパーが記述したアプリが対象の ContentProvider にインテントを送信できないようにすることもできる。
1. ContentProvider を他のアプリにエクスポーズする必要がある場合:

   openFile に対する入力がパス トラバーサル文字を含むときに、アプリが絶対に想定外のファイルを返すことのないように、正しく設定する必要がある。そのためには、ファイルの正規パス（ canonical path ）をチェックする。以下へサンプルコードを示す。
   ```java
   public ParcelFileDescriptor openFile (Uri uri, String mode) throws FileNotFoundException {
    File f = new File(DIR, uri.getLastPathSegment());
    if (!f.getCanonicalPath().startsWith(DIR)) {
        throw new IllegalArgumentException();
    }
    return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
   }
   ```

これに違反する場合、以下の可能性がある。
* ディレクトリトラバーサルの脆弱性を悪用される可能性がある。

## MSTG-STORAGE-7
パスワードや PIN などの機密データは、ユーザインタフェースを介して公開されていない。

### ユーザインターフェースでの機密データの公開

アカウント登録や支払いなど、多くのアプリケーションを利用する際に、機密情報を入力することは不可欠である。このデータは、クレジットカードのデータやユーザアカウントのパスワードなどの金融情報である場合がある。このようなデータは、入力中にアプリが適切にマスクしなければ、漏洩する可能性がある。

情報漏洩を防ぎ、 [shoulder surfing](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) のようなリスクを軽減するために、明示的に要求されない限り（例：パスワードの入力）、ユーザインターフェースを通じて機密データが公開されないことを確認する必要がある。必要なデータについては、平文の代わりにアスタリスクやドットを表示するなどして、適切にマスキングする必要がある。

そのような情報を表示する、あるいは入力として受け取るすべてのUIコンポーネントを注意深く確認すること。機密情報の痕跡を探し、それをマスクするか完全に削除するかを評価する


参考資料
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#checking-for-sensitive-data-disclosure-through-the-user-interface-mstg-storage-7)

#### 入力テキスト

**静的解析**<br>
アプリケーションが機密性の高いユーザ入力をマスキングしているかどうかを確認するには、EditTextの定義に以下の属性があるかを確認する。

```xml
android:inputType="textPassword"
```

この設定により、テキストフィールドに（入力文字ではなく）ドットが表示され、アプリからユーザインターフェースへのパスワードや PIN の漏洩を防ぐことができる。

**動的解析**<br>
入力をアスタリスクやドットに置き換えることで情報がマスクされている場合、アプリはユーザインターフェースにデータを漏洩していないことになる。

参考資料
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7) Text Fields](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#text-fields)

ルールブック
* [機密情報であるパスワードや PIN を入力するフィールドではマスキングを行う（必須）](#機密情報であるパスワードや-pin-を入力するフィールドではマスキングを行う必須)

#### アプリ通知

**静的解析**<br>
アプリケーションを静的に評価する場合、何らかの通知管理の形式である可能性のある NotificationManager クラスの使用を検索することを推奨する。
このクラスが使用されている場合、次のステップは、アプリケーションがどのように[通知を生成](https://developer.android.com/training/notify-user/build-notification#SimpleNotification)しているかを理解することである。

これらのコード位置は、以下の動的解析セクションに入力することができ、アプリケーションのどこで通知が動的に生成されるかを把握することができる。

**動的解析**<br>

通知の使い方を特定するために、アプリケーション全体とその利用可能なすべての機能を通じて、通知をトリガーする方法を探す。特定の通知をトリガーするために、アプリケーションの外部でアクションを実行する必要があるかもしれないことを考慮すること。

アプリケーションの実行中に、 [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) の setContentTitleやsetContentText など、通知の作成に関連する関数へのすべての呼び出しをトレースし始めるとよい。
最終的にトレースを観察し、機密情報が含まれているかどうかを評価すること。

参考資料
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7) App Notifications](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-3)

ルールブック
* [アプリケーションがどのように通知を生成し、どのデータを表示するか理解した上で実装する（必須）](#アプリケーションがどのように通知を生成しどのデータを表示するか理解した上で実装する必須)

### ルールブック
1. [機密情報であるパスワードや PIN を入力するフィールドではマスキングを行う（必須）](#機密情報であるパスワードや-pin-を入力するフィールドではマスキングを行う必須)
1. [アプリケーションがどのように通知を生成し、どのデータを表示するか理解した上で実装する（必須）](#アプリケーションがどのように通知を生成しどのデータを表示するか理解した上で実装する必須)

#### 機密情報であるパスワードや PIN を入力するフィールドではマスキングを行う（必須）
機密情報であるパスワードや PIN は表示されることで漏洩に繋がる。そのため、フィールドではマスキング・非表示にする必要がある。

以下へ入力フィールドをマスキングする方法を示す。

レイアウトの場合：
```xml
   <EditText
        android:id= @+id/Password
        android:inputType="textPassword" />
```

コードの場合：
```kotlin
val editText1: EditText = findViewById(R.id.editText1)
editText1.apply {
    inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD
}
```

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

#### アプリケーションがどのように通知を生成し、どのデータを表示するか理解した上で実装する（必須）

発生したイベントをユーザに通知するためには [NotificationManager](https://developer.android.com/reference/android/app/NotificationManager) クラスを使用する。

通知の構成要素（表示内容）は [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) オブジェクトに指定する。<br>
NotificationCompat.Builder クラスには通知の構成要素を指定するためのメソッドが用意されている。下記は指定用メソッドの一例。

* setContentTitle ： 標準通知で、通知のタイトル (最初の行) を指定する。
* setContentText ： 標準通知で、通知のテキスト ( 2 行目) を指定する。

下記は NotificationCompat.Builder クラスへ通知の構成要素を指定し、 NotificationManager クラスにより通知を表示するソースコードの一例。

```kotlin
    var builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.notification_icon)
            .setContentTitle(textTitle)
            .setContentText(textContent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
    with(NotificationManagerCompat.from(this)) {
        // notificationIDとbuilder.build()を渡します
        notify(notificationID, builder.build())
    }
```

これに違反する場合、以下の可能性がある。
* 第三者に機密情報を読み取られる。

## MSTG-STORAGE-12
アプリは処理される個人識別情報の種類をユーザに通知しており、同様にユーザがアプリを使用する際に従うべきセキュリティのベストプラクティスについて通知している。

### アプリマーケットプレイスでのデータプライバシーに関するユーザ教育のテスト
現時点では、どのプライバシー関連情報が開発者によって開示されているかを知り、それが妥当であるかどうかを評価しようとしているだけである (アクセス許可をテストするときと同様)。

実際に収集または共有されている特定の情報を開発者が宣言していない可能性があるが、それはここでこのテストを拡張する別のトピックのためのものである。このテストの一環として、プライバシー違反の保証を提供することは想定されていない。

参考資料
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Testing User Education on Data Privacy on the App Marketplace](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#testing-user-education-on-data-privacy-on-the-app-marketplace)

### 静的解析
以下の手順で実行できる。

1. 対応するアプリマーケットプレイス（ Google Play, App Store など）でアプリを検索する。
1. ["Privacy Details"](https://developer.apple.com/app-store/app-privacy-details/) セクション（ App Store ）または ["Safety Section"](https://developer.android.com/guide/topics/data/collect-share) セクション（ Google Play ）に移動する。
1. 利用可能な情報があるかどうかを確認する。

開発者がアプリマーケットプレイスのガイドラインに従ってコンパイルし、必要なラベルと説明を含めた場合、テストは合格である。アプリマーケットプレイスから取得した情報を証拠として保存・提供し、後でそれを使用してプライバシーまたはデータ保護の潜在的な違反を評価できるようにする。

参考資料
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#static-analysis)

### 動的解析
オプションの手順として、このテストの一部として何らかの証拠を提供することもできる。例えば、 iOS アプリをテストしている場合、アプリのアクティビティの記録を有効にして、写真、連絡先、カメラ、マイク、ネットワーク接続などのさまざまなリソースへの詳細なアプリアクセスを含む[プライバシーレポート](https://developer.apple.com/documentation/network/privacy_management/inspecting_app_activity_data)を簡単にエクスポートできる。

これを行うと、実際には他の MASVS カテゴリをテストする際に多くの利点がある。これは、 MASVS-NETWORK での[ネットワーク通信のテスト](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md)や、 MASVS-PLATFORM での[アプリのパーミッションのテスト](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05h-Testing-Platform-Interaction.md#testing-app-permissions-mstg-platform-1)に使用できる非常に役立つ情報を提供する。これらの他のカテゴリをテストしているときに、他のテストツールを使用して同様の測定を行った可能性がある。これをこのテストの証拠として提供することもできる。

理想的には、利用可能な情報を、アプリが実際に意図していることと比較する必要がある。ただし、リソースや自動化されたツールのサポートによっては、完了するまでに数日から数週間かかる可能性がある簡単なタスクではない。また、アプリの機能とコンテキストに大きく依存するため、理想的には、アプリ開発者と密接に連携するホワイトボックスセットアップで実行する必要がある。

参考資料
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Dynamic analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#dynamic-analysis)

### セキュリティのベストプラクティスに関するユーザ教育のテスト
このテストは、自動化を意図している場合は特に難しいかもしれない。アプリを広く使い、以下の質問に答えられるようにすることを推奨する。

* 指紋の使用：高リスクの取引／情報へのアクセスを提供する認証に指紋が使用される。
    アプリケーションは、デバイスに他の人の指紋が複数登録されている場合に起こりうる問題について、ユーザに通知しているか？
* Root化 /Jailbreak ： root化またはJailbreak検出が実装されている。
    アプリケーションは、特定のリスクの高いアクションがデバイスの Jailbreak/root 化ステータスのために追加のリスクを伴うという事実をユーザに通知しているか？
* 特定の認証情報：ユーザがアプリケーションからリカバリーコード、パスワード、PIN を取得する（または設定）。
    アプリケーションからリカバリーコード、パスワード、 PIN を取得（または設定）した場合、アプリケーションはこれを他のユーザと決して共有せず、アプリケーションのみが要求するようユーザに指示しているか？
* アプリケーションの配布：リスクの高いアプリケーションの場合、ユーザが危険なバージョンのアプリケーションをダウンロードするのを防ぐため。
    アプリケーションの製造元は、アプリケーション配布する正式な方法 （ Google Play ）を適切に伝えているか？
* Prominent Disclosure ：全てのケース。
    アプリケーションは、データへのアクセス、収集、使用、共有について、目立つように開示しているか？例えば、アプリケーションは、 Android 上で許可を求めるために [Best practices for prominent disclosure and consent](https://support.google.com/googleplay/android-developer/answer/11150561?hl=en) を使用しているか。

参考資料
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Testing User Education on Security Best Practices](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#testing-user-education-on-security-best-practices)

ルールブック
* [アプリを広く使い、セキュリティのベストプラクティスに関する質問に答えられるようにする（推奨）](#アプリを広く使いセキュリティのベストプラクティスに関する質問に答えられるようにする推奨)

### ルールブック
1. [アプリを広く使い、セキュリティのベストプラクティスに関する質問に答えられるようにする（推奨）](#アプリを広く使いセキュリティのベストプラクティスに関する質問に答えられるようにする推奨)

#### アプリを広く使い、セキュリティのベストプラクティスに関する質問に答えられるようにする（推奨）

アプリを広く使い、セキュリティのベストプラクティスに関する以下の質問に答えられるようにすることを推奨する。

* 指紋の使用：高リスクの取引／情報へのアクセスを提供する認証に指紋が使用される。
    アプリケーションは、デバイスに他の人の指紋が複数登録されている場合に起こりうる問題について、ユーザに通知しているか？
* Root化 /Jailbreak ： root化またはJailbreak検出が実装されている。
    アプリケーションは、特定のリスクの高いアクションがデバイスの Jailbreak/root 化ステータスのために追加のリスクを伴うという事実をユーザに通知しているか？
* 特定の認証情報：ユーザがアプリケーションからリカバリーコード、パスワード、PIN を取得する（または設定）。
    アプリケーションからリカバリーコード、パスワード、 PIN を取得（または設定）した場合、アプリケーションはこれを他のユーザと決して共有せず、アプリケーションのみが要求するよう指示しているか？
* アプリケーションの配布：リスクの高いアプリケーションの場合、ユーザが危険なバージョンのアプリケーションをダウンロードするのを防ぐため。
    アプリケーションの製造元は、アプリケーション配布する正式な方法 （ Google Play ）を適切に伝えているか？
* Prominent Disclosure ：全てのケース。
    アプリケーションは、データへのアクセス、収集、使用、共有について、目立つように開示しているか？例えば、アプリケーションは、 Android 上で許可を求めるために [Best practices for prominent disclosure and consent](https://support.google.com/googleplay/android-developer/answer/11150561?hl=en) を使用しているか。

これに注意しない場合、以下の可能性がある。
* 機密情報が想定していない処理で利用される。
* 第三者に機密情報を読み取られる。