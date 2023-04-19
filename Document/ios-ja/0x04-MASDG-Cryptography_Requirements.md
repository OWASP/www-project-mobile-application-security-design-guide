# 暗号化要件

## MSTG-CRYPTO-1
アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。

<a id="mstg-crypto-1-overview"></a>
### 問題のある暗号化構成

#### 不十分なキーの長さ

最も安全な暗号化アルゴリズムであっても、不十分なキーサイズを使用すると、ブルートフォースアタックに対して脆弱になる。<br>

キーの長さが[業界標準](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014)を満たしていることを確認する。なお日本国内においては[「電子政府推奨暗号リスト」掲載の暗号仕様書一覧](https://www.cryptrec.go.jp/method.html)を確認する。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Insufficient Key Length](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#insufficient-key-length)

ルールブック
* [業界標準を満たしたキーの長さを設定する（必須）](#業界標準を満たしたキーの長さを設定する必須)

#### ハードコードされた暗号化鍵による対称暗号化

対称暗号化とキー付きハッシュ (MAC) のセキュリティは、キーの機密性に依存する。キーが公開されると、暗号化によって得られたセキュリティが失われる。これを防ぐには、作成に関与した暗号化データと同じ場所に秘密鍵を保存しないことである。よくある間違いは、静的なハードコードされた暗号化鍵を使用してローカルに保存されたデータを暗号化し、そのキーをアプリにコンパイルすることである。この場合、逆アセンブラを使用できる人であれば誰でもそのキーにアクセスできるようになる。<br>

ハードコードされた暗号化鍵とは、次のことを意味する。
* アプリケーションリソースの一部であること
* 既知の値から導出可能な値であること
* コードにハードコードされていること

まず、ソースコード内にキーやパスワードが保存されていないことを確認する。つまり、 Objective-C/Swift をチェックする必要がある。難読化は動的インストルメンテーションによって容易にバイパスされるため、ハードコードされたキーはソースコードが難読化されていても問題があることに注意する。<br>

アプリが双方向 TLS (サーバとクライアントの両方の証明書が検証される)を使用している場合、以下を確認する。<br>
* クライアント証明書のパスワードがローカルに保存されていない、またはデバイスの Keychain にロックされていること。
* クライアント証明書は、すべてのインストール間で共有されていないこと。

アプリが、アプリのデータ内に保存され暗号化されたコンテナに依存する場合、暗号化鍵がどのように使用されるかを確認する。キーラップ方式を使用している場合、各ユーザのマスターシークレットが初期化されていること、またはコンテナが新しいキーで再暗号化されていることを確認する。マスターシークレットや以前のパスワードを使用してコンテナを復号できる場合、パスワードの変更がどのように処理されるかを確認する。<br>

モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する必要がある。プラットフォーム固有の API の詳細については、「 [Data Storage on iOS](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md)」の章を参照する。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Symmetric Encryption with Hard-Coded Cryptographic Keys](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#symmetric-encryption-with-hard-coded-cryptographic-keys)

ルールブック
* [ソースコード内にキーやパスワードを保存しない（必須）](#ソースコード内にキーやパスワードを保存しない必須)
* [クライアント証明書のパスワードをローカルに保存しない、またはデバイスの Keychain にロックする（必須）](#クライアント証明書のパスワードをローカルに保存しないまたはデバイスの-keychain-にロックする必須)
* [クライアント証明書はすべてのインストール間で共有しない（必須）](#クライアント証明書はすべてのインストール間で共有しない必須)
* [コンテナに依存する場合、暗号化鍵がどのように使用されるかを確認する（必須）](#コンテナに依存する場合暗号化鍵がどのように使用されるかを確認する必須)
* [モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する（必須）](#モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する必須)

#### 弱いキー生成関数

暗号化アルゴリズム (対称暗号化や一部の MAC など) は、特定のサイズの秘密の入力を想定している。例えば、 AES はちょうど16バイトのキーを使用する。ネイティブな実装では、ユーザが提供したパスワードを直接入力キーとして使用することがある。ユーザが提供したパスワードを入力キーとして使用する場合、以下のような問題がある。<br>

* パスワードがキーよりも小さい場合、完全なキースペースは使用されない。残りのスペースはパディングされる(パディングのためにスペースが使われることもある)。
* ユーザ提供のパスワードは、現実的には、ほとんどが表示・発音可能な文字で構成される。したがって、 256 文字ある ASCII 文字の一部だけが使われ、エントロピーはおよそ4分の1に減少する。

パスワードが暗号化関数に直接渡されないようにする。代わりに、ユーザが提供したパスワードは、暗号化鍵を作成するために KDF に渡されるべきである。パスワード導出関数を使用する場合は、適切な反復回数を選択する。例えば、 [NIST は PBKDF2 の反復回数を少なくとも 10,000 回](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)、[ユーザが感じるパフォーマンスが重要でない重要なキーの場合は少なくとも 10,000,000 回](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) を推奨している。重要なキーについては、 [Argon2](https://github.com/p-h-c/phc-winner-argon2) のような [Password Hashing Competition (PHC)](https://www.password-hashing.net/) で認められたアルゴリズムの実装を検討することが推奨される。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Weak Key Generation Functions](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#weak-key-generation-functions)

ルールブック
* [暗号化アルゴリズム (対称暗号化や一部の MAC など) を使用する場合、想定されている特定のサイズの秘密の入力を使用する（必須）](#暗号化アルゴリズム-対称暗号化や一部の-mac-など-を使用する場合想定されている特定のサイズの秘密の入力を使用する必須)
* [ユーザが提供したパスワードは、暗号鍵を作成するために KDF に渡す（必須）](#ユーザが提供したパスワードは暗号鍵を作成するために-kdf-に渡す必須)
* [パスワード導出関数を使用する場合は、適切な反復回数を選択する（必須）](#パスワード導出関数を使用する場合は適切な反復回数を選択する必須)

#### 弱い乱数ジェネレーター

決定論的なデバイスで真の乱数を生成することは基本的に不可能である。擬似乱数ジェネレーター( RNG )は、擬似乱数のストリーム(あたかもランダムに発生したかのように見える数値のストリーム)を生成することでこれを補う。生成される数値の品質は、使用するアルゴリズムの種類によって異なる。暗号化的に安全な RNG は、統計的ランダム性テストに合格した乱数を生成し、予測攻撃に対して耐性がある。(例:次に生成される数を予測することは統計的に不可能である)<br>

Mobile SDK は、十分な人工的ランダム性を持つ数値を生成する RNG アルゴリズムの標準的な実装を提供している。利用可能な API については、 iOS 固有のセクションで紹介する。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Weak Random Number Generators](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#weak-random-number-generators)

ルールブック
* [十分な人工的ランダム性を持つ数値を生成する RNG アルゴリズムの標準的な実装を確認する（必須）](#十分な人工的ランダム性を持つ数値を生成する-rng-アルゴリズムの標準的な実装を確認する必須)

#### 暗号化のカスタム実装

独自の暗号関数を開発することは、時間がかかり、困難であり、失敗する可能性が高い。その代わりに、安全性が高いと広く認められている、よく知られたアルゴリズムを使用することができる。モバイル OS は、これらのアルゴリズムを実装した標準的な暗号 API を提供している。<br>

ソースコード内で使用されているすべての暗号化方式、特に機密データに直接適用されている暗号化方式を注意深く検査する。すべての暗号化操作では、 iOS 標準の暗号化 API を使用する必要がある(これらについては、プラットフォーム固有の章で詳しく説明する)。既知のプロバイダが提供する標準的なルーチンを呼び出さない暗号化操作は、厳密に検査する必要がある。標準的なアルゴリズムが変更されている場合は、細心の注意を払う必要がある。エンコーディングは暗号化と同じではないことに注意する。 XOR (排他的論理和) のようなビット操作の演算子を見つけたら、必ずさらに調査する。<br>

暗号化のすべての実装で、以下のことが常に行われていることを確認する必要がある。
* ワーカーキー ( AES/DES/Rijndael における中間鍵/派生鍵のようなもの)は、消費後またはエラー発生時にメモリから適切に削除される。
* 暗号の内部状態は、できるだけ早くメモリから削除する。

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Custom Implementations of Cryptography](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#custom-implementations-of-cryptography)

ルールブック
* [暗号化に関するすべての実装では適切にメモリ状態を管理する（必須）](#暗号化に関するすべての実装では適切にメモリ状態を管理する必須)
* [OS が提供する業界標準の暗号 API を使用する（必須）](#os-が提供する業界標準の暗号-api-を使用する必須)

#### 不適切な AES 構成

Advanced Encryption Standard ( AES ) は、モバイルアプリにおける対称暗号化の標準として広く受け入れられている。 AES は、一連の連鎖的な数学演算に基づく反復型ブロック暗号である。 AES は入力に対して可変回数のラウンドを実行し、各ラウンドでは入力ブロック内のバイトの置換と並べ替えが行われる。各ラウンドでは、オリジナルの AES キーから派生した 128 ビットのラウンドキーが使用される。

この記事の執筆時点では、 AES に対する効率的な暗号解読攻撃は発見されていない。しかし、実装の詳細やブロック暗号モードなどの設定可能なパラメータには、エラーの余地がある。

**弱いブロック暗号モード**

ブロックベースの暗号化は、個々の入力ブロック ( 例: AES は 128 ビットブロック ) に対して実行される。平文がブロックサイズより大きい場合、平文は内部で指定された入力サイズのブロックに分割され、各ブロックに対して暗号化が実行される。ブロック暗号操作モード ( またはブロックモード ) は、前のブロックの暗号化の結果が後続のブロックに影響を与えるかどうかを決定する。

[ECB ( Electronic Codebook )](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_%28ECB%29) は、入力を一定サイズのブロックに分割し、同じキーを用いて個別に暗号化する。分割された複数のブロックに同じ平文が含まれている場合、それらは同一の暗号文ブロックに暗号化されるため、データのパターンを容易に特定することができる。また、状況によっては、攻撃者が暗号化されたデータを再生することも可能である。

<img src="images/0x04/MSTG-CRYPTO-1/EncryptionMode.png" alt="ECBの暗号化例" width="550px" />

ECB の代わりに暗号ブロック連鎖 ( CBC ) モードが使用されていることを確認する。 CBC モードでは、平文ブロックは直前の暗号文ブロックと XOR される。これにより、ブロックに同じ情報が含まれている場合でも、暗号化された各ブロックは一意であり、ランダムであることが保証される。 CBC を HMAC と組み合わせたり、「パディングエラー」「 MAC エラー」「復号失敗」などのエラーが出ないようにすることが、パディングオラクル攻撃に対抗するために最善であることに注意してください。

暗号化されたデータを保存する場合、Galois/Counter Mode ( GCM )のような、保存データの完全性も保護するブロックモードを使用することを推奨する。後者には、このアルゴリズムが各 TLSv1.2 の実装に必須であり、したがってすべての最新のプラットフォームで利用できるという利点もある。

有効なブロックモードの詳細については、[ブロックモード選択に関する NIST のガイドライン](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development)を参照する。

**予測可能な初期化ベクトル**

CBC 、 OFB 、 CFB 、 PCBC 、 GCM モードでは、暗号への初期入力として、初期化ベクトル( IV )が必要である。 IV は秘密にする必要はないが、予測可能であってはならない。暗号化されたメッセージごとにランダムで一意であり、非再現性である必要がある。 IV は暗号的に安全な乱数ジェネレーターを用いて生成されていることを確認する。 IV の詳細については、 [Crypto Fail の初期化ベクトルに関する記事](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors)を参照する。

コードで使用されている暗号化ライブラリに注意すること:多くのオープンソースライブラリは、悪い習慣(ハードコードされた IV の使用など)に従う可能性のあるドキュメントが提供されている。よくある間違いは、 IV 値を変更せずにサンプルコードをコピーアンドペーストすることである。

**ステートフル操作モードでの初期化ベクトル**

初期化ベクトルがカウンター( CTR と nonce の組み合わせ)であることが多い CTR モードと GCM モード を使用する場合は、 IV の使用方法が異なることに注意する。したがって、ここでは、独自のステートフルモデルを持つ予測可能な IV を使用することが、まさに必要である。 CTR では、新しいブロック操作のたびに、新しい nonce とカウンターを入力として使用する。<br>
例: 5120 ビット長の平文の場合では、 20 個のブロックがあるため、 nonce とカウンターで構成される 20 個の入力ベクトルが必要である。<br>
一方 GCM では、暗号化操作ごとに IV を 1 つだけ持ち、同じキーで繰り返さないようにする。 IV の詳細と推奨事項については、 [GCM に関する NIST の資料](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)の 8 項を参照する。

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Inadequate AES Configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#inadequate-aes-configuration)
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Weak Block Cipher Mode](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#weak-block-cipher-mode)
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Predictable Initialization Vector](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#predictable-initialization-vector)
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Initialization Vectors in stateful operation modes](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#initialization-vectors-in-stateful-operation-modes)

ルールブック
* [パディングオラクル攻撃に対抗するために、CBC を HMAC と組み合わせたりパディングエラー, MAC エラー, 復号失敗などのエラーが出ないようにする（必須）](#パディングオラクル攻撃に対抗するためにcbc-を-hmac-と組み合わせたりパディングエラー-mac-エラー-復号失敗などのエラーが出ないようにする必須)
* [暗号化されたデータを保存する場合、Galois/Counter Mode ( GCM )のような、保存データの完全性も保護するブロックモードを使用する（推奨）](#暗号化されたデータを保存する場合galoiscounter-mode--gcm-のような保存データの完全性も保護するブロックモードを使用する推奨)
* [IV は暗号的に安全な乱数ジェネレーターを用いて生成する（必須）](#iv-は暗号的に安全な乱数ジェネレーターを用いて生成する必須)
* [初期化ベクトルがカウンターであることが多い CTR モードと GCM モード を使用する場合は、 IV の使用方法が異なることに注意する（必須）](#初期化ベクトルがカウンターであることが多い-ctr-モードと-gcm-モード-を使用する場合は-iv-の使用方法が異なることに注意する必須)

#### 弱いパディングまたはブロック操作の実装によるパディングオラクル攻撃

以前は、非対称暗号を行う際のパディングメカニズムとして、 [PKCS1.5](https://www.rfc-editor.org/rfc/rfc2313) パディング(コード: PKCS1Padding) が使われていた。このメカニズムは、パディングオラクル攻撃に対して脆弱である。そのため、 [PKCS#1 v2.0](https://www.rfc-editor.org/rfc/rfc2437) (コード: OAEPwithSHA-256andMGF1Padding 、 OAEPwithSHA-224andMGF1Padding 、 OAEPwithSHA-384andMGF1Padding 、 OAEPwithSHA-512andMGF1Padding ) に取り込まれた OAEP ( Optimal Asymmetric Encryption PaddingOAEPPadding ) を使用するのが最適である。なお、 OAEP を使用した場合でも、 [Kudelskisecurity のブログ](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/)で紹介されている Mangers 攻撃としてよく知られている問題に遭遇する可能性があることに注意する。<br>

注: PKCS #5 を使用する AES-CBC は、実装が「パディングエラー」、「 MAC エラー」、または「復号に失敗しました」などの警告を表示するため、パディングオラクル攻撃に対しても脆弱であることが示されている。例として、 [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack/) および [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem) を参照する。次に、平文を暗号化した後に HMAC を追加することが最善である。結局、 MAC に失敗した暗号文は復号する必要がなく、破棄することができる。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Padding Oracle Attacks due to Weaker Padding or Block Operation Implementations](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#padding-oracle-attacks-due-to-weaker-padding-or-block-operation-implementations)

ルールブック
* [非対称暗号を行う際のパディングメカニズムとして PKCS#1 v2.0 に取り込まれた OAEP を使用する（必須）](#非対称暗号を行う際のパディングメカニズムとして-pkcs1-v20-に取り込まれた-oaep-を使用する必須)

#### ストレージおよびメモリ内のキーの扱い

メモリダンプが脅威モデルの一部である場合、キーがアクティブに使用された瞬間にキーにアクセスできる。メモリダンプには、ルートアクセス(ルート化されたデバイスやジェイルブレイクされたデバイスなど)が必要であるか、 Frida でパッチされたアプリケーション( Fridump などのツールを使用できるように)が必要である。したがって、デバイスでキーがまだ必要な場合は、次のことを考慮するのが最善である。<br>

* リモートサーバのキー: Amazon KMS や Azure Key Vault などのリモート Key Vault を使用することができる。一部のユースケースでは、アプリとリモートリソースの間にオーケストレーションレイヤーを開発することが適切なオプションとなる場合がある。例えば、 Function as a Service ( FaaS ) システム ( AWS Lambda や Google Cloud Functions など ) 上で動作するサーバレス関数が、 API キーやシークレットを取得するためのリクエストを転送するような場合である。その他の選択肢として、 Amazon Cognito 、 Google Identity Platform 、 Azure Active Directory なども存在する。
* ハードウェアで保護された安全なストレージ内のキー:すべての暗号化アクションとキー自体が [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave) ( 例: Keychainを使用 ) にあることを確認する。詳細については、 [iOS Data Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md#the-keychain) の章を参照する。
* エンベロープ暗号化によって保護されたキー:キーが TEE/SE の外部に保存されている場合は、 multi-layered 暗号化の使用を検討する。エンベロープ暗号化アプローチ ([OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys)、 [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en)、 [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html) 参照)、またはデータ暗号化鍵をキー暗号化する [HPKE アプローチ](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hpke-08)を使用する。
* メモリ内のキー:キーができるだけ短時間しかメモリに残さないようにし、暗号化操作に成功した後やエラー時にキーをゼロにし、無効化することを考慮する。一般的な暗号化のガイドラインについては、[機密データのメモリの消去](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/)を参照する。より詳細な情報については、[「Testing Memory for Sensitive Data」](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) を参照する。


注: メモリダンプが容易になるため、署名の検証や暗号化に使用される公開鍵以外は、アカウントやデバイス間で同じキーを共有しない。


参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Protecting Keys in Storage and in Memory](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#protecting-keys-in-storage-and-in-memory)

ルールブック
* [メモリダンプを考慮してキーを使用する（必須）](#メモリダンプを考慮してキーを使用する必須)
* [アカウントやデバイス間で同じキーを共有しない（必須）](#アカウントやデバイス間で同じキーを共有しない必須)

#### 転送時のキーの扱い

キーをデバイス間で、またはアプリからバックエンドに転送する必要がある場合、トランスポート対称鍵や他のメカニズムによって、適切なキー保護が行われていることを確認する。多くの場合、キーは難読化された状態で共有されるため、簡単に元に戻すことができる。代わりに、非対称暗号化またはラッピングキーが使用されていることを確認する。
例えば、対称鍵は非対称鍵の公開鍵で暗号化することができる。<br>

参考資料
* [owasp-mastg Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Protecting Keys in Transport](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#protecting-keys-in-transport)

ルールブック
* [トランスポート対称鍵や他のメカニズムによって、適切なキー保護を行う（必須）](#トランスポート対称鍵や他のメカニズムによって適切なキー保護を行う必須)

### ルールブック
1. [業界標準を満たしたキーの長さを設定する（必須）](#業界標準を満たしたキーの長さを設定する必須)
1. [ソースコード内にキーやパスワードを保存しない（必須）](#ソースコード内にキーやパスワードを保存しない必須)
1. [クライアント証明書のパスワードをローカルに保存しない、またはデバイスの Keychain にロックする（必須）](#クライアント証明書のパスワードをローカルに保存しないまたはデバイスの-keychain-にロックする必須)
1. [クライアント証明書はすべてのインストール間で共有しない（必須）](#クライアント証明書はすべてのインストール間で共有しない必須)
1. [コンテナに依存する場合、暗号化鍵がどのように使用されるかを確認する（必須）](#コンテナに依存する場合暗号化鍵がどのように使用されるかを確認する必須)
1. [モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する（必須）](#モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する必須)
1. [暗号化アルゴリズム (対称暗号化や一部の MAC など) を使用する場合、想定されている特定のサイズの秘密の入力を使用する（必須）](#暗号化アルゴリズム-対称暗号化や一部の-mac-など-を使用する場合想定されている特定のサイズの秘密の入力を使用する必須)
1. [ユーザが提供したパスワードは、暗号鍵を作成するために KDF に渡す（必須）](#ユーザが提供したパスワードは暗号鍵を作成するために-kdf-に渡す必須)
1. [パスワード導出関数を使用する場合は、適切な反復回数を選択する（必須）](#パスワード導出関数を使用する場合は適切な反復回数を選択する必須)
1. [十分な人工的ランダム性を持つ数値を生成する RNG アルゴリズムの標準的な実装を確認する（必須）](#十分な人工的ランダム性を持つ数値を生成する-rng-アルゴリズムの標準的な実装を確認する必須)
1. [暗号化に関するすべての実装では適切にメモリ状態を管理する（必須）](#暗号化に関するすべての実装では適切にメモリ状態を管理する必須)
1. [OS が提供する業界標準の暗号 API を使用する（必須）](#os-が提供する業界標準の暗号-api-を使用する必須)
1. [パディングオラクル攻撃に対抗するために、CBC を HMAC と組み合わせたりパディングエラー, MAC エラー, 復号失敗などのエラーが出ないようにする（必須）](#パディングオラクル攻撃に対抗するためにcbc-を-hmac-と組み合わせたりパディングエラー-mac-エラー-復号失敗などのエラーが出ないようにする必須)
1. [暗号化されたデータを保存する場合、Galois/Counter Mode ( GCM )のような、保存データの完全性も保護するブロックモードを使用する（推奨）](#暗号化されたデータを保存する場合galoiscounter-mode--gcm-のような保存データの完全性も保護するブロックモードを使用する推奨)
1. [IV は暗号的に安全な乱数ジェネレーターを用いて生成する（必須）](#iv-は暗号的に安全な乱数ジェネレーターを用いて生成する必須)
1. [初期化ベクトルがカウンターであることが多い CTR モードと GCM モード を使用する場合は、 IV の使用方法が異なることに注意する（必須）](#初期化ベクトルがカウンターであることが多い-ctr-モードと-gcm-モード-を使用する場合は-iv-の使用方法が異なることに注意する必須)
1. [非対称暗号を行う際のパディングメカニズムとして PKCS#1 v2.0 に取り込まれた OAEP を使用する（必須）](#非対称暗号を行う際のパディングメカニズムとして-pkcs1-v20-に取り込まれた-oaep-を使用する必須)
1. [メモリダンプを考慮してキーを使用する（必須）](#メモリダンプを考慮してキーを使用する必須)
1. [アカウントやデバイス間で同じキーを共有しない（必須）](#アカウントやデバイス間で同じキーを共有しない必須)
1. [トランスポート対称鍵や他のメカニズムによって、適切なキー保護を行う（必須）](#トランスポート対称鍵や他のメカニズムによって適切なキー保護を行う必須)

#### 業界標準を満たしたキーの長さを設定する（必須）

キーの長さが[業界標準](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014)を満たしていることを確認する。なお日本国内においては[「電子政府推奨暗号リスト」掲載の暗号仕様書一覧](https://www.cryptrec.go.jp/method.html)を確認する。<br>
最も安全な暗号化アルゴリズムであっても、不十分なキーサイズを使用すると、ブルートフォースアタックに対して脆弱になる。

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* ブルートフォースアタックに対して脆弱になる。

#### ソースコード内にキーやパスワードを保存しない（必須）

難読化は動的インストルメンテーションによって容易にバイパスされるため、ハードコードされたキーはソースコードが難読化されていても問題がある。そのため、ソースコード（Objective-C/Swift コード）内にキーやパスワードを保存しない。

※非推奨なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* 難読化が動的インストルメンテーションによってバイパスされ、キーやパスワードが漏洩する。

#### クライアント証明書のパスワードをローカルに保存しない、またはデバイスの Keychain にロックする（必須）

アプリが双方向 TLS (サーバとクライアントの両方の証明書が検証される)を使用している場合、クライアント証明書のパスワードをローカルに保存しない。またはデバイスの Keychain にロックする。

サンプルコードは以下ルールブックを参照。

ルールブック
* [Keychain Services API を使用してセキュアに値を保存する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#keychain-services-api-を使用してセキュアに値を保存する必須)

これに違反する場合、以下の可能性がある。
* パスワードが他アプリに読み取られ悪用される。

#### クライアント証明書はすべてのインストール間で共有しない（必須）

アプリが双方向 TLS (サーバとクライアントの両方の証明書が検証される)を使用している場合、クライアント証明書はすべてのインストール間で共有しない。

※非推奨なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* クライアントが攻撃者によってなりすまされる。

#### コンテナに依存する場合、暗号化鍵がどのように使用されるかを確認する（必須）

アプリが、アプリのデータ内に保存された暗号化されたコンテナに依存する場合、暗号化鍵がどのように使用されるかを確認する。

**キーラップ方式を使用している場合**

以下について確認する。
* 各ユーザのマスターシークレットが初期化されていること
* コンテナが新しいキーで再暗号化されていること

**マスターシークレットや以前のパスワードを使用してコンテナを復号できる場合**

パスワードの変更がどのように処理されるかを確認する。

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* パスワードやマスターシークレットが意図した目的以外で使用される。

#### モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する（必須）

モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する必要がある。<br>
iOS プラットフォームでの秘密鍵の保存方法については、「[データ保護 API](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#データ保護-api)」を参照。

ルールブック
* [iOS Data Protection API を活用して、フラッシュメモリに保存されたユーザデータにアクセス制御を実装する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#ios-data-protection-api-を活用してフラッシュメモリに保存されたユーザデータにアクセス制御を実装する必須)

これに違反する場合、以下の可能性がある。
* 秘密鍵が他アプリや第三者に読み取られる。

#### 暗号化アルゴリズム (対称暗号化や一部の MAC など) を使用する場合、想定されている特定のサイズの秘密の入力を使用する（必須）

暗号化アルゴリズム (対称暗号化や一部の MAC など) を使用する場合、想定されている特定のサイズの秘密の入力を使用する必要がある。例えば、 AES はちょうど16バイトのキーを使用する。

ネイティブな実装では、ユーザが提供したパスワードを直接入力キーとして使用することがある。ユーザが提供したパスワードを入力キーとして使用する場合、以下のような問題がある。<br>

* パスワードがキーよりも小さい場合、完全なキースペースは使用されない。残りのスペースはパディングされる(パディングのためにスペースが使われることもある)。
* ユーザ提供のパスワードは、現実的には、ほとんどが表示・発音可能な文字で構成される。したがって、 256 文字ある ASCII 文字の一部だけが使われ、エントロピーはおよそ4分の1に減少する。

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* 脆弱なキーが生成される。

#### ユーザが提供したパスワードは、暗号鍵を作成するために KDF に渡す（必須）
暗号化関数を使用する場合、ユーザが提供したパスワードは、暗号鍵を作成するために KDF に渡されるべきである。
パスワードが暗号化関数に直接渡されないようにする。代わりに、ユーザが提供したパスワードは、暗号化鍵を作成するために KDF に渡されるべきである。パスワード導出関数を使用する場合は、適切な反復回数を選択する。

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* パスワードがキーよりも小さい場合、完全なキースペースは使用されない。残りのスペースはパディングされる。
* エントロピーがおよそ4分の1に減少する。

#### パスワード導出関数を使用する場合は、適切な反復回数を選択する（必須）

パスワード導出関数を使用する場合は、適切な反復回数を選択する必要がある。例えば、 [NIST は PBKDF2 の反復回数を少なくとも 10,000 回](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)、[ユーザが感じるパフォーマンスが重要でない重要なキーの場合は少なくとも 10,000,000 回](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) を推奨している。重要なキーについては、 [Argon2](https://github.com/p-h-c/phc-winner-argon2) のような [Password Hashing Competition (PHC)](https://www.password-hashing.net/) で認められたアルゴリズムの実装を検討することが推奨される。

※サーバ側のルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* 脆弱なキーが生成される。

#### 十分な人工的ランダム性を持つ数値を生成する RNG アルゴリズムの標準的な実装を確認する（必須）
暗号化的に安全な RNG は、統計的ランダム性テストに合格した乱数を生成し、予測攻撃に対して耐性がある。
安全な水準に満たない RNG アルゴリズムにより生成された乱数を使用すると、予測攻撃が成功する可能性が高まる。
そのため、十分な人工的ランダム性を持つ数値を生成する RNG アルゴリズムを使用する必要がある。

iOS 標準で安全性の高い乱数を生成する API については以下を参照する。

ルールブック
* [Randomization Services API を使用して安全な乱数を生成（推奨）](#randomization-services-api-を使用して安全な乱数を生成推奨)

これに違反する場合、以下の可能性がある。
* 予測攻撃が成功する可能性が高まる。

#### 暗号化に関するすべての実装では適切にメモリ状態を管理する（必須）

暗号化に関するすべての実装では、ワーカーキー ( AES/DES/Rijndael における中間鍵/派生鍵のようなもの)が消費後またはエラー発生時にメモリから適切に削除する必要がある。また暗号の内部状態も、できるだけ早くメモリから削除する必要がある。

AES実装と実行後の解放：
```swift
import Foundation
import CryptoSwift

class CryptoAES {
    var aes: AES? = nil
    
    // 暗号化処理
    func encrypt(key: String, iv:String, text:String) -> String {


        do {
            // 関数最後に実行
            defer {
                aes = nil
            }
            // AES インスタンス化
            aes = try AES(key: key, iv: iv)
            guard let encrypt = try aes?.encrypt(Array(text.utf8)) else {
                return ""
            }

            
            // Data 型変換
            let data = Data( encrypt )
            // base64 変換
            let base64Data = data.base64EncodedData()
            // UTF-8変換 nil 不可
            guard let base64String =
                String(data: base64Data as Data, encoding: String.Encoding.utf8) else {
                    return ""
                }
            // base64文字列
            return base64String

        } catch {
            return ""
        }
    }

    // 複合処理
    func decrypt(key: String, iv:String, base64:String) -> String {

        do {
            // 関数最後に実行
            defer {
                aes = nil
            }
            // AES インスタンス化
            aes = try AES(key: key, iv:iv)

            // base64 から Data型へ
            let byteData = base64.data(using: String.Encoding.utf8)! as Data
            // base64 デーコード
            guard let data = Data(base64Encoded: byteData) else {
                return ""
            }

            // UInt8 配列の作成
            let aBuffer = Array<UInt8>(data)
            // AES 複合
            guard let decrypted = try aes?.decrypt(aBuffer) else {
                return ""
            }
            // UTF-8変換
            guard let text = String(data: Data(decrypted), encoding: .utf8)else {
                return ""
            }

            return text
        } catch {

            return ""
        }
    }
}
```

CryptoSwiftのPods使用例：
```default
target 'MyApp' do
  use_frameworks!
  # CryptoSwiftライブラリを追加する
  pod 'CryptoSwift'
end
```

これに違反する場合、以下の可能性がある。
* メモリに残された暗号化情報を意図しない処理で利用される。

#### OS が提供する業界標準の暗号 API を使用する（必須）
独自の暗号関数を開発することは、時間がかかり、困難であり、失敗する可能性が高い。その代わりに、安全性が高いと広く認められている、よく知られたアルゴリズムを使用することができる。モバイル OS は、これらのアルゴリズムを実装した標準的な暗号 API を提供しているため、安全な暗号化のためにはこちらを利用する必要がある。

サンプルコードについては、以下のルールブックを参照。

ルールブック
* [iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）](#ios-暗号化アルゴリズム-apple-cryptokit-の実装推奨)

これに違反する場合、以下の可能性がある。
* 脆弱性を含む実装となる可能性がある。

#### パディングオラクル攻撃に対抗するために、CBC を HMAC と組み合わせたりパディングエラー, MAC エラー, 復号失敗などのエラーが出ないようにする（必須）

CBC モードでは、平文ブロックは直前の暗号文ブロックと XOR される。これにより、ブロックに同じ情報が含まれている場合でも、暗号化された各ブロックは一意であり、ランダムであることが保証される。 

CBCモード実装の例：
```swift
import Foundation
import CryptoSwift

class CryptoCBC {
    // 暗号化する平文の例
    let cleartext = "Hello CryptoSwift"
    
    // 暗号化処理
    func encrypt( text:String) -> (String, String) {
        // 適当な256ビット長の鍵（文字列）
        let key = "BDC171111B7285F67F035497EE9A081D"
        
        // エンコード
        let byteText = text.data(using: .utf8)!.bytes
        let byteKey = key.data(using: .utf8)!.bytes

        // IV（初期化ベクトル）、ivの型は[UInt8]
        let iv = AES.randomIV(AES.blockSize)
        do {
            // AES-256-CBCインスタンスの生成
            let aes = try AES(key: byteKey, blockMode: CBC(iv: iv))
            
            // 平文を暗号化
            // デフォルトのパディングがPKC7
            let encrypted = try aes.encrypt(byteText)

            // IV、encryptedを出力 Base64文字列にエンコード
            let strIV = NSData(bytes: iv, length: iv.count).base64EncodedString(options: .lineLength64Characters)
            print("IV: " + strIV)  // 出力 -> IV: lBMiK2GWEwrPgNdGfrJEig==
            let strEnc = NSData(bytes: encrypted, length: encrypted.count).base64EncodedString(options: .lineLength64Characters)
            print("Encrypted: " + strEnc)  // 出力 -> Encrypted: MHf5ZeUL/gjviiZitpZKJFuqppdTgEe+IklDgg3N1fQ=
            return (strIV, strEnc)
        } catch {
          print("Error")
        }
        return ("", "")
    }
}
```

これに違反する場合、以下の可能性がある。
* パディングオラクル攻撃に対して脆弱になる。

#### 暗号化されたデータを保存する場合、Galois/Counter Mode ( GCM )のような、保存データの完全性も保護するブロックモードを使用する（推奨）

暗号化されたデータを保存する場合、Galois/Counter Mode ( GCM )のような、保存データの完全性も保護するブロックモードを使用することを推奨する。後者には、このアルゴリズムが各 TLSv1.2 の実装に必須であり、したがってすべての最新のプラットフォームで利用できるという利点もある。

GCMモード実装の例：
```swift
import Foundation
import CryptoKit

class CryptoGCM {
    
    // 鍵の生成
    let symmetricKey: SymmetricKey = SymmetricKey(size: .bits256)
    /// 暗号化
    /// - Parameter data: 暗号化するデータ
    func encrypt(data: Data) -> Data? {
        do {
            // GCM encrypt
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            guard let data = sealedBox.combined else {
                return nil
            }
            return data
        } catch _ {
            return nil
        }
    }
    
    /// 復号
    /// - Parameter data: 復号するデータ
    private func decrypt(data: Data) -> Data? {
        do {
            // GCM decrypt
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch _ {
            return nil
        }
    }
}
```

これに違反する場合、以下の可能性がある。
* データのパターンを容易に特定される。

#### IV は暗号的に安全な乱数ジェネレーターを用いて生成する（必須）

CBC 、 OFB 、 CFB 、 PCBC 、 GCM モードでは、暗号への初期入力として、初期化ベクトル( IV )が必要である。 IV は秘密にする必要はないが、予測可能であってはならない。暗号化されたメッセージごとにランダムで一意であり、非再現性である必要がある。そのため、 IV は暗号的に安全な乱数ジェネレーターを用いて生成する必要がある。 IV の詳細については、 [Crypto Fail の初期化ベクトルに関する記事](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors)を参照する。

サンプルコードは以下ルールブックを参照。

ルールブック
* [Randomization Services API を使用して安全な乱数を生成（推奨）](#randomization-services-api-を使用して安全な乱数を生成推奨)

これに違反する場合、以下の可能性がある。
* 予測可能な初期化ベクトルが生成される。

#### 初期化ベクトルがカウンターであることが多い CTR モードと GCM モード を使用する場合は、 IV の使用方法が異なることに注意する（必須）

初期化ベクトルがカウンター( CTR と nonce の組み合わせ)であることが多い CTR モードと GCM モード を使用する場合は、 IV の使用方法が異なることに注意する。そのため、独自のステートフルモデルを持つ予測可能な IV を使用することが必要である。<br>
CTR では、新しいブロック操作のたびに、新しい nonce とカウンターを入力として使用する。<br>
例: 5120 ビット長の平文の場合では、 20 個のブロックがあるため、 nonce とカウンターで構成される 20 個の入力ベクトルが必要である。<br>
一方 GCM では、暗号化操作ごとに IV を 1 つだけ持ち、同じキーで繰り返さないようにする。 IV の詳細と推奨事項については、 [GCM に関する NIST の資料](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)の 8 項を参照する。

※概念的なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* 各モードで必要とされる初期化ベクトルの要件を満たせない。

#### 非対称暗号を行う際のパディングメカニズムとして PKCS#1 v2.0 に取り込まれた OAEP を使用する（必須）

以前は、非対称暗号を行う際のパディングメカニズムとして、 [PKCS1.5](https://www.rfc-editor.org/rfc/rfc2313) パディング(コード: PKCS1Padding) が使われていた。このメカニズムは、パディングオラクル攻撃に対して脆弱である。そのため、 [PKCS#1 v2.0](https://www.rfc-editor.org/rfc/rfc2437) (コード: OAEPwithSHA-256andMGF1Padding 、 OAEPwithSHA-224andMGF1Padding 、 OAEPwithSHA-384andMGF1Padding 、 OAEPwithSHA-512andMGF1Padding ) に取り込まれた OAEP ( Optimal Asymmetric Encryption PaddingOAEPPadding ) を使用するのが最適である。なお、 OAEP を使用した場合でも、 [Kudelskisecurity のブログ](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/)で紹介されている Mangers 攻撃としてよく知られている問題に遭遇する可能性があることに注意する。

以下のサンプルコードは、 OAEP の使用方法である。
```swift
let plainData = "TEST TEXT".data(using: .utf8)!

// main digest SHA256, MGF1 digest SHA1 で RsaOAEPPadding クラスを生成
let padding = RsaOAEPPadding(mainDigest: OAEPDigest.SHA256, mgf1Digest: OAEPDigest.SHA1)

// OAEP Padding を計算 (RSA鍵長は 2048bit = 256byte前提)
let padded = try! padding.pad(plain: plainData, blockSize: 256);

// raw で暗号化
guard let cipherData = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.rsaEncryptionRaw, padded as CFData, &error) else {
    // Error処理
}
```

これに違反する場合、以下の可能性がある。
* パディングオラクル攻撃に対して脆弱になる。

#### メモリダンプを考慮してキーを使用する（必須）

メモリダンプが脅威モデルの一部である場合、キーがアクティブに使用された瞬間にキーにアクセスできる。メモリダンプには、ルートアクセス(ルート化されたデバイスやジェイルブレイクされたデバイスなど)が必要であるか、 Frida でパッチされたアプリケーション( Fridump などのツールを使用できるように)が必要である。したがって、デバイスでキーがまだ必要な場合は、次のことを考慮するのが最善である。

* リモートサーバのキー: Amazon KMS や Azure Key Vault などのリモート Key Vault を使用することができる。一部のユースケースでは、アプリとリモートリソースの間にオーケストレーションレイヤーを開発することが適切なオプションとなる場合がある。例えば、 Function as a Service ( FaaS ) システム ( AWS Lambda や Google Cloud Functions など ) 上で動作するサーバレス関数が、 API キーやシークレットを取得するためのリクエストを転送するような場合である。その他の選択肢として、 Amazon Cognito 、 Google Identity Platform 、 Azure Active Directory なども存在する。
* ハードウェアで保護された安全なストレージ内のキー:すべての暗号化アクションとキー自体が [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave) ( 例: Keychainを使用 ) にあることを確認する。詳細については、 [iOS Data Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md#the-keychain) の章を参照する。
* エンベロープ暗号化によって保護されたキー:キーが TEE/SE の外部に保存されている場合は、 multi-layered 暗号化の使用を検討する。エンベロープ暗号化アプローチ ([OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys)、 [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en)、 [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html) 参照)、またはデータ暗号化鍵をキー暗号化する [HPKE アプローチ](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hpke-08)を使用する。
* メモリ内のキー:キーができるだけ短時間しかメモリに残さないようにし、暗号化操作に成功した後やエラー時にキーをゼロにし、無効化することを考慮する。一般的な暗号化のガイドラインについては、[機密データのメモリの消去](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/)を参照する。より詳細な情報については、[「Testing Memory for Sensitive Data」](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) を参照する。

以下サンプルコードは、アプリでのメモリ内のキーの漏洩防止用の処理。
```swift
data.resetBytes(in: NSRange(location:0, length:data.length))
```

また、キーを全く保存しないことで、キーマテリアルがダンプされないことが保証される。これは、 PKBDF-2 などのパスワードキー導出機能を使用することで実現できる。以下の例を参照する。

 ```swift
func pbkdf2SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA256(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    let passwordData = password.data(using: String.Encoding.utf8)!
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedKeyDataLength = derivedKeyData.count
    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        salt.withUnsafeBytes { saltBytes in

            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes, salt.count,
                hash,
                UInt32(rounds),
                derivedKeyBytes, derivedKeyDataLength
            )
        }
    }
    if derivationStatus != 0 {
        // Error
        return nil
    }

    return derivedKeyData
}

func testKeyDerivation() {
    let password = "password"
    let salt = Data([0x73, 0x61, 0x6C, 0x74, 0x44, 0x61, 0x74, 0x61])
    let keyByteCount = 16
    let rounds = 100_000

    let derivedKey = pbkdf2SHA1(password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}
```

* 出典： [https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios)（Arcaneライブラリのテストスイートでテスト済み）

これに違反する場合、以下の可能性がある。
* メモリダンプが脅威モデルの一部である場合、キーがアクティブに使用された瞬間にキーにアクセスできる。

#### アカウントやデバイス間で同じキーを共有しない（必須）

メモリダンプが容易になるため、署名の検証や暗号化に使用される公開鍵以外は、アカウントやデバイス間で同じキーを共有しない。

※非推奨なルールのため、サンプルコードはなし。

これに違反する場合、以下の可能性がある。
* キーのメモリダンプが容易になる。

#### トランスポート対称鍵や他のメカニズムによって、適切なキー保護を行う（必須）

キーをデバイス間で、またはアプリからバックエンドに転送する必要がある場合、トランスポート対称鍵や他のメカニズムによって、適切なキー保護が行われていることを確認する。多くの場合、キーは難読化された状態で共有されるため、簡単に元に戻すことができる。代わりに、非対称暗号化またはラッピングキーが使用されていることを確認する。 例えば、対称鍵は非対称鍵の公開鍵で暗号化することができる。

キーを適切に保護するには Keychain を使用する。 Keychain によるキーの保管方法は以下ルールブックを参照。

ルールブック
* [Keychain Services API を使用してセキュアに値を保存する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#keychain-services-api-を使用してセキュアに値を保存する必須)

これに違反する場合、以下の可能性がある。
* キーを元に戻され読み取られる。

## MSTG-CRYPTO-2
アプリは実績のある暗号化プリミティブの実装を使用している。

### 問題のある暗号化構成
※問題のある暗号化構成については、<a href="#mstg-crypto-1-overview">「MSTG-CRYPTO-1 3.1.1. 問題のある暗号化構成」</a>の内容を確認すること。<br>

<a id="mstg-crypto-2-overview"></a>
### 暗号化標準アルゴリズムの構成

Apple は、最も一般的な暗号化アルゴリズムの実装を含むライブラリを提供している。 [Apple の Cryptographic Services Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html) が参考になる。これには、標準ライブラリを使用して暗号化プリミティブを初期化および使用する方法の一般化されたドキュメント、ソースコード分析に役立つ情報が含まれている。

参照資料
* [owasp-mastg Verifying the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#overview)

#### CryptoKit
Apple CryptoKit は iOS 13 でリリースされ、[FIPS 140-2 検証済み](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856)の Apple のネイティブ暗号化ライブラリ corecrypto をベースに構築されている。 Swift フレームワークは、厳密に型指定された API インターフェースを提供し、効果的なメモリ管理を行い、equatable に準拠し、ジェネリックをサポートする。 CryptoKit には、ハッシュ、対称鍵暗号化、および公開鍵暗号化のための安全なアルゴリズムが含まれている。フレームワークは、 Secure Enclave のハードウェアベースのキーマネージャーも利用できる。

Apple CryptoKit には、以下のアルゴリズムが含まれている。

**ハッシュ：**
* MD5 (Insecure Module)
* SHA1 (Insecure Module)
* SHA-2 256-bit digest
* SHA-2 384-bit digest
* SHA-2 512-bit digest

**対称鍵：**
* メッセージ認証コード（ HMAC ） 
* 認証付き暗号化
  * AES-GCM
  * ChaCha20-Poly1305

**公開鍵：**
* キー共有
  * Curve25519
  * NIST P-256
  * NIST P-384
  * NIST P-512

使用例：

対称鍵の生成と公開：
```default
let encryptionKey = SymmetricKey(size: .bits256)
```

SHA-2 512-bit digest の計算：
```default
let rawString = "OWASP MTSG"
let rawData = Data(rawString.utf8)
let hash = SHA512.hash(data: rawData) // Compute the digest
let textHash = String(describing: hash)
print(textHash) // Print hash text
```

Apple CryptoKit の詳細については、以下のリソースを参照。
* [Apple CryptoKit | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit)
* [Performing Common Cryptographic Operations | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations)
* [WWDC 2019 session 709 | Cryptography and Your Apps](https://developer.apple.com/videos/play/wwdc2019/709)
* [How to calculate the SHA hash of a String or Data instance | Hacking with Swift](https://www.hackingwithswift.com/example-code/cryptokit/how-to-calculate-the-sha-hash-of-a-string-or-data-instance)

参考資料
* [owasp-mastg Verifying the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3) CryptoKit](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#cryptokit)

ルールブック
* [iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）](#ios-暗号化アルゴリズム-apple-cryptokit-の実装推奨)

#### CommonCrypto、SecKey、Wrapper の各ライブラリ
暗号化操作に最も一般的に使用されるクラスは、iOS runtime にパッケージされている CommonCrypto である。 CommonCrypto オブジェクトによって提供される機能は、[ヘッダーファイルのソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html)を見ることで最もよく分析できる。

* Commoncryptor.h ：対称暗号操作のパラメータを提供する。
* CommonDigest.h ：ハッシュアルゴリズムのパラメータを提供する。
* CommonHMAC.h ：サポートされている HMAC 操作のパラメータを提供する。
* CommonKeyDerivation.h ：サポートされている KDF 関数のパラメータを提供する。
* CommonSymmetricKeywrap.h ：対称鍵をキー暗号化鍵でラップするために使用される関数を提供する。

残念ながら、CommonCryptor の public API には、次のようないくつかのタイプの操作が存在しない。 GCM モードは、private API でのみ使用できる。[ソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h)を参照。このためには、追加のバインディングヘッダーが必要である。または、他の wrapper  ライブラリを使用することもできる。

次に、非対称な操作のために、 Apple は [SecKey](https://developer.apple.com/documentation/security/seckey) を提供している。 Apple は [Developer Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption) の中で、この使い方を丁寧に説明している。

前に述べたように、利便性を提供するために、いくつかの wrapper ライブラリが両方に存在する。使用される典型的なライブラリは、以下のようなものである。
* [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto)
* [Heimdall](https://github.com/henrinormak/Heimdall)
* [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA)
* [RNCryptor](https://github.com/RNCryptor/RNCryptor)
* [Arcane](https://github.com/onmyway133/Arcane)

参考資料
* [owasp-mastg Verifying the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3) CommonCrypto, SecKey and Wrapper libraries](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#commoncrypto-seckey-and-wrapper-libraries)

ルールブック
* [iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）](#ios-暗号化アルゴリズム-apple-cryptokit-の実装推奨)

#### サードパーティライブラリ

次のようなさまざまなサードパーティライブラリが利用できる。

* CJOSE ： JWE の台頭と、AES GCM の公的サポートの不足により、 [CJOSE](https://github.com/cisco/cjose) などの他のライブラリが登場した。 CJOSE は C/C++ 実装のみを提供するため、より高いレベルの wrapping が必要である。
* CryptoSwift ： [GitHub](https://github.com/krzyzanowskim/CryptoSwift) 公開されている Swift のライブラリである。このライブラリは、さまざまなハッシュ関数、 MAC 関数、 CRC 関数、対称暗号、およびパスワードベースのキー導出関数をサポートしている。これは wrapper ではなく、各暗号を完全に自己実装したものである。関数の効果的な実装を検証することが重要である。
* OpenSSL ： [OpenSSL](https://www.openssl.org/) は、C で記述された TLS に使用されるツールキットライブラリである。その暗号化関数のほとんどは、（ H ）MAC 、署名、対称および非対称暗号、ハッシュなどの作成など、必要なさまざまな暗号化アクションを実行するために使用できる。 [OpenSSL](https://github.com/ZewoGraveyard/OpenSSL) や [MIHCrypto](https://github.com/hohl/MIHCrypto) など、さまざまな wrapper がある。
* LibSodium ： Sodium は、暗号化、復号、署名、パスワードハッシュなどのための最新の使いやすいソフトウェアライブラリである。これは、移植可能で、クロスコンパイル可能で、インストール可能で、パッケージ化可能な NaCl の fork であり、互換性のある API と使いやすさをさらに向上させる拡張 API を備えている。詳細については、 [LibSodiums のドキュメント](https://doc.libsodium.org/installation)を参照。 [Swift-sodiu](https://github.com/jedisct1/swift-sodium), [NAChloride](https://github.com/gabriel/NAChloride), [libsodium-ios](https://github.com/mochtu/libsodium-ios) などの wrapper ライブラリがいくつかある。
* Tink ： Google による新しい暗号化ライブラリである。 Google は、[セキュリティブログ](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html)でライブラリの背後にある理由を説明している。ソースは [Tinks GitHub](https://github.com/google/tink) リポジトリにある。
* Themis ： Swift, Obj-C, Android/Java, С++, JS, Python, Ruby, PHP, Go のストレージとメッセージング用の暗号化ライブラリである。 [Themis](https://github.com/cossacklabs/themis) は依存関係として LibreSSL/OpenSSL エンジン libcrypto を使用する。キー生成、安全なメッセージング（ペイロードの暗号化と署名など）、安全なストレージ、および安全なセッションの設定のために、 Objective-C と Swift をサポートする。詳細については、[関係者の wiki](https://github.com/cossacklabs/themis/wiki/) を参照。
* Others ： [CocoaSecurity](https://github.com/kelp404/CocoaSecurity), [Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA), [aerogear-ios-crypto](https://github.com/aerogear-attic/aerogear-ios-crypto) など、他にも多くのライブラリがある。これらの一部はもはやメンテナンスされておらず、セキュリティレビューが行われていない可能性がある。いつものように、サポートおよび保守されているライブラリを探すことが必要。
* DIY ： 暗号や暗号関数の実装を独自に作成する開発者が増えている。このような行為は非常に推奨されておらず、使用する場合は暗号化の専門家に十分に吟味してもらう必要がある。

参考資料
* [owasp-mastg Verifying the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Third party libraries](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#third-party-libraries)

#### 静的解析
非推奨のアルゴリズムと暗号化構成については、 "Cryptography for Mobile Apps" セクションで多くのことが述べられている。当然ながらこれらは、この章で言及されているライブラリごとに検証する必要がある。キーを保持するデータ構造と平文のデータ構造の削除方法がどのように定義されているかに注意すること。 キーワード "let" を使用すると、メモリから消去するのがより困難な不変の構造が作成される。メモリから簡単に削除できる親構造体の一部であることを確認すること（例：一時的に存在する構造体）。

**CommonCryptor**<br>
アプリが Apple が提供する標準の暗号化実装を使用している場合、関連するアルゴリズムのステータスを判断する最も簡単な方法は、 CCCrypt や CCCryptorCreate などの CommonCryptor からの関数への呼び出しを確認することである。[ソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h)には、CommonCryptor.h のすべての関数の署名が含まれている。例えば、 CCCryptorCreate には次の署名がある。

```c
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef);  /* RETURNED */
```

次に、すべての列挙型を比較して、どのアルゴリズム、パディング、およびキーマテリアルが 使用されているかを判断できる。キーマテリアル に注意すること。キーは、キー導出関数または乱数生成関数を使用して安全に生成する必要がある。「Cryptography for Mobile Apps」の章で非推奨として記載されている関数は、プログラムで引き続きサポートされていることに注意すること。これらの関数は使用しない。

**サードパーティライブラリ**<br>
すべてのサードパーティライブラリが継続的に進化していることを考えると、静的解析の観点から各ライブラリを評価する場所であってはならない。それでも注意点がいくつかある：

* 使用されているライブラリを見つけること。これは、次の方法を使用して実行できる。
  * Carthage が使用されている場合は、 [cartfile](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile) を確認する。
  * Cocoapods が使用されている場合は、 [podfile](https://guides.cocoapods.org/syntax/podfile.html) を確認する。
  * リンクされたライブラリを確認する： xcodeproj ファイルを開き、プロジェクトのプロパティを確認する。 [Build Phases] タブに移動し、 [Link Binary With Libraries] のエントリでライブラリのいずれかを確認する。 [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) を使用して同様の情報を取得する方法については、前のセクションを参照。
  * コピー＆ペーストされたソースの場合：ヘッダーファイル（ Objective-C を使用している場合）を検索し、それ以外の場合は Swift ファイルで既知のライブラリの既知のメソッド名を検索する。
* 使用されているバージョンを特定する：使用しているライブラリのバージョンを常に確認し、潜在的な脆弱性や欠点にパッチが適用された新しいバージョンが利用可能かどうかを確認する。ライブラリの新しいバージョンがなくても、暗号化機能がまだレビューされていない場合がある。したがって、検証済みのライブラリを使用するか、自分で検証を行う能力、知識、および経験があることを確認することを推奨する。
* 手動：独自の暗号を展開したり、既知の暗号機能を自分で実装したりしないことを推奨する。

参考資料
* [owasp-mastg Verifying the Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#static-analysis)

### ルールブック
1. [iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）](#ios-暗号化アルゴリズム-apple-cryptokit-の実装推奨)

#### iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）

Apple CryptoKit を使用して、以下の一般的な暗号化操作を実行する。
* 暗号的に安全なダイジェストを計算して比較する。
* 公開鍵暗号を使用して、デジタル署名を作成および評価し、鍵交換を実行する。メモリに保存されたキーを操作するだけでなく、 Secure Enclave に保存され管理されている秘密鍵を使用することも可能。
* 対称鍵を生成し、メッセージ認証や暗号化などの操作で使用する。

低レベルのインターフェースよりも CryptoKit の使用を推奨する。 CryptoKit は、生ポインターの管理からアプリを解放し、メモリの割り当て解除中に機密データを上書きするなど、アプリをより安全にするタスクを自動的に処理している。

**CryptoKitを使ったハッシュ値生成**

CryptoKit を使用すると、以下のハッシュを生成できる。

暗号的に安全なハッシュ
* struct SHA512
  * 512 ビット ダイジェストによる Secure Hashing Algorithm 2 (SHA-2) ハッシュの実装。
* struct SHA384
  *  384 ビット ダイジェストによる Secure Hashing Algorithm 2 (SHA-2) ハッシュの実装。
* struct SHA256
  * 256 ビット ダイジェストによる Secure Hashing Algorithm 2 (SHA-2) ハッシュの実装。

暗号的に安全でないハッシュ
* Insecure. struct MD5
  * MD5 ハッシュの実装。
* Insecure. struct SHA1
  * SHA1 ハッシュの実装。

```swift
import CryptoKit
import UIKit

func sha256Hash(str: String) -> String? {
    let data = Data(str.utf8)
    let hashed = SHA256.hash(data: data)

    return hashed.compactMap { String(format: "%02x", $0) }.joined()
}

func md5Hash(str: String) -> String? {
    
    let data = Data(str.utf8)
    // Insecure 古い、暗号的に安全でないアルゴリズムのコンテナ
    let hashed = Insecure.MD5.hash(data: data)

    return hashed.compactMap { String(format: "%02x", $0) }.joined()
}

func createSha256Hashing() {
    //  sha256 strings generated
    let hash = sha256Hash(str: "test") // 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
}

func createMd5hash() {
    // md5 strings generated
    let hash = md5Hash(str: "test") //098f6bcd4621d373cade4e832627b4f6

}
```

**CryptoKitを使った デジタル署名 ( Cryptographic Signature )**

CryptoKit を使用すると、以下の公開鍵暗号で署名と検証が可能

公開鍵暗号
* enum Curve25519
  * X25519 鍵合意と ed25519 署名を可能にする楕円曲線。
* enum P521
  * NIST P-521 署名と鍵合意を可能にする楕円曲線。
* enum P384
  * NIST P-384 署名と鍵合意を可能にする楕円曲線。
* enum P256
  * NIST P-256 署名と鍵合意を可能にする楕円曲線。


```swift
import UIKit
import CryptoKit

// CryptoSigningProtocol
struct CryptoSignature {
    var signature: Data
    var signedData: Data
}


struct CryptoSigning {

    var rawPrivateKey: Data = Data(base64Encoded: "EDpGUyQuE0Xtjt3/j8KmxtBdaKQNP+7uTU3nJg7pzsg=") ?? Data()

    func createKey() -> Data? {
        guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey) else { return nil }
        return privateKey.publicKey.rawRepresentation
    }

    func sign(str: String) -> CryptoSignature? {
        guard let data = str.data(using: .utf8),
        let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey),
        let signature = try? privateKey.signature(for: data) else { return nil }

        return CryptoSignature(signature: signature, signedData: data)
    }

    func isValid(rawPublicKey: Data, signature: CryptoSignature) -> Bool {
        guard let signingPublicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey) else { return false }

        return signingPublicKey.isValidSignature(signature.signature, for: signature.signedData)
    }
}

class CryptoSigningSample {

    func testSuccessCaseForCryptoSigning() {

        let cryptoSigning = CryptoSigning()
        let rawPublicKey = cryptoSigning.createKey()!
        let signedSignature = cryptoSigning.sign(str: "ABC")!


        if cryptoSigning.isValid(rawPublicKey: rawPublicKey, signature: signedSignature) {
            // 検証OK
        }
    }
}
```

**CryptoKitを使った 対象鍵暗号 （ Symmetric Encryption ）**

CryptoKit を使用すると、以下の対称鍵暗号化方式で操作ができる。

暗号
* enum AES
  * Advanced Encryption Standard (AES) 暗号のコンテナ。
  * GCMモードを使用するには AESコンテナにあるGCMを使用する。
* enum ChaChaPoly
  * ChaCha20-Poly1305 暗号の実装。

```swift
import UIKit
import CryptoKit

struct ChaChaPolyEncryption {

    var cryptoKey: SymmetricKey = SymmetricKey(size: .bits256)

    func encrypt(str: String) -> Data? {
        let data = Data(str.utf8)
        guard let sealedBox = try? ChaChaPoly.seal(data, using: cryptoKey) else { return nil }

        return sealedBox.combined
    }

    func decrypt(data: Data) -> String? {
        guard let sealedBox = try? ChaChaPoly.SealedBox(combined: data) else { return nil }
        guard let decryptedData = try? ChaChaPoly.open(sealedBox, using: cryptoKey) else { return nil }

        return String(data: decryptedData, encoding: .utf8)
    }
}

class ChaChaPolyEncryptionSample {

    func execChaChaPolyEncryption() {

        let encryption = ChaChaPolyEncryption()

        // 暗号化
        guard let signature = encryption.encrypt(str: "ABC") else {
            return
        }

        // 復元
        guard let decryptText =  encryption.decrypt(data: signature)  else {
            return
        }

    }
}
```

**CommonCrypto と SecKey による暗号化の実装**

CryptoKit が誕生する以前は CommonCrypto や SecKey が利用されていた。
現在 Apple は CryptoKit 利用を推奨しているが、OS バージョンなどの理由から利用できない場合は、OS 標準の API としてこちらを利用することができる。

以下のサンプルコードへ CommonCrypto の利用方法を示す。
```objectivec
#ifndef SwiftAES_Bridging_Header_h
#define SwiftAES_Bridging_Header_h


#endif /* SwiftAES_Bridging_Header_h */

#import <CommonCrypto/CommonCrypto.h>
```

```swift
import UIKit
import CryptoKit
import CommonCrypto

public class Chiper {

    enum AESError : Error {
        case encryptFailed(String, Any)
        case decryptFailed(String, Any)
        case otherFailed(String, Any)
    }

    /// バイナリDataを16進数文字列に変換する
     ///
     /// - Parameter binaryData: バイナリの入ったData
     /// - Returns: 16進数文字列
     public static func convetHexString(frombinary data: Data) -> String {

         return data.reduce("") { (a : String, v : UInt8) -> String in
             return a + String(format: "%02x", v)
         }

     }

    public class AES {
        /// 暗号
        public static func encrypt(plainString: String, sharedKey: String, iv: String) throws -> Data {
            guard let initialzeVector = (iv.data(using: .utf8)) else {
                throw Chiper.AESError.otherFailed("Encrypt iv failed", iv)
            }
            guard let keyData = sharedKey.data(using: .utf8) else {
                throw Chiper.AESError.otherFailed("Encrypt sharedkey failed", sharedKey)
            }
            guard let data = plainString.data(using: .utf8) else {
                throw Chiper.AESError.otherFailed("Encrypt plainString failed", plainString)
            }

            // 暗号化後のデータのサイズを計算
            let cryptLength = size_t(Int(ceil(Double(data.count / kCCBlockSizeAES128)) + 1.0) * kCCBlockSizeAES128)

            var cryptData = Data(count:cryptLength)
            var numBytesEncrypted: size_t = 0

            // 暗号化
            let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
                initialzeVector.withUnsafeBytes {ivBytes in
                    data.withUnsafeBytes {dataBytes in
                        keyData.withUnsafeBytes {keyBytes in
                            CCCrypt(CCOperation(kCCEncrypt),
                                    CCAlgorithm(kCCAlgorithmAES),
                                    CCOptions(kCCOptionPKCS7Padding),
                                    keyBytes, keyData.count,
                                    ivBytes,
                                    dataBytes, data.count,
                                    cryptBytes, cryptLength,
                                    &numBytesEncrypted)
                        }
                    }
                }
            }

            if UInt32(cryptStatus) != UInt32(kCCSuccess) {
                throw Chiper.AESError.encryptFailed("Encrypt Failed", kCCSuccess)
            }
            return cryptData
        }

        /// 復号
        public static func decrypt(encryptedData: Data, sharedKey: String, iv: String) throws -> String {
            guard let initialzeVector = (iv.data(using: .utf8)) else {
                throw Chiper.AESError.otherFailed("Encrypt iv failed", iv)
            }
            guard let keyData = sharedKey.data(using: .utf8) else {
                throw Chiper.AESError.otherFailed("Encrypt sharedKey failed", sharedKey)
            }

            let clearLength = size_t(encryptedData.count + kCCBlockSizeAES128)
            var clearData   = Data(count:clearLength)

            var numBytesEncrypted :size_t = 0

            // 復号
            let cryptStatus = clearData.withUnsafeMutableBytes {clearBytes in
                initialzeVector.withUnsafeBytes {ivBytes in
                    encryptedData.withUnsafeBytes {dataBytes in
                        keyData.withUnsafeBytes {keyBytes in
                            CCCrypt(CCOperation(kCCDecrypt),
                                    CCAlgorithm(kCCAlgorithmAES),
                                    CCOptions(kCCOptionPKCS7Padding),
                                    keyBytes, keyData.count,
                                    ivBytes,
                                    dataBytes, encryptedData.count,
                                    clearBytes, clearLength,
                                    &numBytesEncrypted)
                        }
                    }
                }
            }

            if UInt32(cryptStatus) != UInt32(kCCSuccess) {
                throw Chiper.AESError.decryptFailed("Decrypt Failed", kCCSuccess)
            }

            // パディングされていた文字数分のデータを捨てて文字列変換を行う
            guard let decryptedStr = String(data: clearData.prefix(numBytesEncrypted), encoding: .utf8) else {
                throw Chiper.AESError.decryptFailed("PKSC Unpad Failed", clearData)
            }
            return decryptedStr
        }

        /// ランダムIV生成
        public static func generateRandamIV() throws -> String {
            // CSPRNGから乱数取得
            var randData = Data(count: 8)
            let result = randData.withUnsafeMutableBytes {mutableBytes in
                SecRandomCopyBytes(kSecRandomDefault, 16, mutableBytes)
            }
            if result != errSecSuccess {
                // SecRandomCopyBytesに失敗(本来はあり得ない)
                throw Chiper.AESError.otherFailed("SecRandomCopyBytes Failed GenerateRandam IV", result)
            }
            // 16進数文字列化
            let ivStr = Chiper.convetHexString(frombinary: randData)
            return ivStr
        }
    }
}
```

以下のサンプルコードへ SecKey の利用方法を示す。
```swift
import Foundation

public class SecKeyHelper {

   /// base64pem形式の鍵文字列をiOSで利用するSecKey形式に変換する
    ///
    /// - Parameters:
    ///   - argBase64Key: base64pem形式の公開鍵 あるいは秘密鍵
    ///   - keyType: kSecAttrKeyClassPublic|kSecAttrKeyClassPrivate
    /// - Returns: SecKey形式の鍵データ
    /// - Throws: RSAError
    static func convertSecKeyFromBase64Key(_ argBase64Key: String, _ keyType: CFString) throws -> SecKey {

        var keyData = Data(base64Encoded: argBase64Key, options: [.ignoreUnknownCharacters])!
        let keyClass = keyType

        let sizeInBits = keyData.count * 8
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
            kSecReturnPersistentRef: true
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
            throw RSAError.keyCreateFailed(status: 0)
        }
        return key

    }

    /// 公開鍵で暗号化を行う
    ///
    /// - Parameters:
    ///   - argBody: 対象文字列
    ///   - argBase64PublicKey: 公開鍵文字列(base64)
    /// - Returns: 暗号データ
    static func encrypt(_ argBody: String, _ argBase64PublicKey: String) -> Data {

        do {
            let pubKey = try self.convertSecKeyFromBase64Key(argBase64PublicKey, kSecAttrKeyClassPublic)
            let plainBuffer = [UInt8](argBody.utf8)
            var cipherBufferSize = Int(SecKeyGetBlockSize(pubKey))
            var cipherBuffer = [UInt8](repeating:0, count:Int(cipherBufferSize))
            // Encrypto  should less than key length
            let status = SecKeyEncrypt(pubKey, SecPadding.PKCS1, plainBuffer, plainBuffer.count, &cipherBuffer, &cipherBufferSize)
            if (status != errSecSuccess) {
                print("Failed Encryption")
            }
            return Data(bytes: cipherBuffer)
        }
        catch {
            // エラー処理
        }

        return Data()

    }
}
```

これに注意しない場合、以下の可能性がある。
* 脆弱な暗号化実装となる可能性がある。

## MSTG-CRYPTO-3

アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。

### 問題のある暗号化構成
※問題のある暗号化構成については、<a href="#mstg-crypto-1-overview">「MSTG-CRYPTO-1 3.1.1. 問題のある暗号化構成」</a>の内容を確認すること。<br>

### 暗号化標準アルゴリズムの構成
※暗号化標準アルゴリズムの構成については、<a href="#mstg-crypto-2-overview">「MSTG-CRYPTO-2 3.2.2. 暗号化標準アルゴリズムの構成」</a>の内容を確認すること。<br>

## MSTG-CRYPTO-4
アプリはセキュリティ上の目的で広く非推奨と考えられる暗号プロトコルやアルゴリズムを使用していない。

### セキュアでない、または非推奨な暗号化アルゴリズム

モバイルアプリを評価する際には、重大な既知の弱点を持つ暗号アルゴリズムやプロトコルを使用していないこと、あるいは最新のセキュリティ要件に対して不十分な点がないことを確認する必要がある。過去に安全とされていたアルゴリズムも、時間の経過とともに安全でなくなる可能性がある。したがって、現在のベストプラクティスを定期的にチェックし、それに応じて設定を調整することが重要である。<br>

暗号化アルゴリズムが最新のものであり、業界標準に準拠していることを確認する。脆弱なアルゴリズムには、旧式のブロック暗号 ( DES 、 3DES など ) 、ストリーム暗号 ( RC4 など ) 、ハッシュ関数 ( MD5 、 SHA1 など ) 、壊れた乱数ジェネレーター ( Dual_EC_DRBG 、 SHA1PRNG など ) が含まれる。認証されているアルゴリズム ( NIST など ) でも、時間の経過とともに安全でなくなる可能性があることに注意する。認証は、アルゴリズムの健全性を定期的に検証することに取って代わるものではない。既知の弱点を持つアルゴリズムは、より安全な代替手段に置き換える必要がある。さらに、暗号化に使用されるアルゴリズムは標準化され、検証可能である必要がある。未知のアルゴリズムや独自のアルゴリズムを使ってデータを暗号化すると、アプリケーションがさまざまな暗号攻撃にさらされ、平文が復元される可能性がある。<br>

アプリのソースコードを調査し、以下のような脆弱性が知られている暗号化アルゴリズムのインスタンスを特定する。<br>

* [DES,3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014)
* RC2
* RC4
* [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014)
* MD4
* MD5
* SHA1

暗号化 API の名前は、特定のモバイルプラットフォームによって異なる。<br>

次のことを確認する。<br>

* 暗号化アルゴリズムは最新で、業界標準に準拠している。これには、時代遅れのブロック暗号( DES など)ストリーム暗号( RC4 など)、ハッシュ関数(MD5など)、 Dual_EC_DRBG などの破損した乱数ジェネレーター ( NIST 認定であっても ) が含まれますが、これらに限定されない。これらはすべて安全でないものとしてマークし、使用せず、アプリケーションとサーバから削除する必要がある。<br>
* キーの長さは業界標準に準拠しており、十分な時間の保護を提供する。ムーアの法則を考慮したさまざまなキーの長さとその保護性能の比較は、[オンライン](https://www.keylength.com/)で確認可能である。
* 暗号化手段は互いに混合されていない:例えば、公開鍵で署名したり、署名に使用した対称鍵を暗号化に再利用しない。
* 暗号化パラメータが合理的な範囲で適切に定義されている。これには、ハッシュ関数出力と少なくとも同じ長さである必要がある暗号ソルト、パスワード導出関数と反復回数の適切な選択(例: PBKDF2 、 scrypt 、 bcrypt ) 、 IV はランダムでユニークであること、目的に合ったブロック暗号化モード(例: ECB は特定の場合を除き使用しない)、キー管理が適切に行われているか(例: 3DES は 3 つの独立したキーを持つべきである)などが含まれるが、これらに限定されない。

参考資料
* [owasp-mastg Identifying Insecure and/or Deprecated Cryptographic Algorithms (MSTG-CRYPTO-4)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms-mstg-crypto-4)

ルールブック
* [セキュアでない、または非推奨な暗号化アルゴリズムは使用しない（必須）](#セキュアでないまたは非推奨な暗号化アルゴリズムは使用しない必須)

### ルールブック
1. [セキュアでない、または非推奨な暗号化アルゴリズムは使用しない（必須）](#セキュアでないまたは非推奨な暗号化アルゴリズムは使用しない必須)

#### セキュアでない、または非推奨な暗号化アルゴリズムは使用しない（必須）

業界標準に準拠した最新の暗号化アルゴリズムで実装すること。

具体的な観点としては以下内容に準拠して実装する。
* 暗号化アルゴリズムは最新で、業界標準に準拠している。業界標準については「[業界標準を満たしたキーの長さを設定する（必須）](#業界標準を満たしたキーの長さを設定する必須)」を参照。
* キーの長さは業界標準に準拠し、十分な時間の保護を提供する。ムーアの法則を考慮したさまざまなキーの長さとその保護性能の比較は、[オンライン](https://www.keylength.com/)で確認可能である。
* 暗号化手段を互いに混合しない:例えば、公開鍵で署名したり、署名に使用した対称鍵を暗号化に再利用しない。
* 暗号化パラメータを合理的な範囲で適切に定義する。これには、ハッシュ関数出力と少なくとも同じ長さである必要がある暗号ソルト、パスワード導出関数と反復回数の適切な選択(例: PBKDF2 、 scrypt 、 bcrypt ) 、 IV はランダムでユニークであること、目的に合ったブロック暗号化モード(例: ECB は特定の場合を除き使用しない)、キー管理が適切に行われているか(例: 3DES は 3 つの独立したキーを持つべきである)などが含まれるが、これらに限定されない。

サンプルコードは、以下ルールブックを参照。

ルールブック
* [iOS 暗号化アルゴリズム Apple CryptoKit の実装（推奨）](#ios-暗号化アルゴリズム-apple-cryptokit-の実装推奨)

これに違反する場合、以下の可能性がある。
* 脆弱な暗号化処理となる可能性がある。

## MSTG-CRYPTO-5
アプリは複数の目的のために同じ暗号化鍵を再利用していない。

参考資料
* [owasp-mastg Testing Key Management (MSTG-CRYPTO-1 and MSTG-CRYPTO-5)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#testing-key-management-mstg-crypto-1-and-mstg-crypto-5)


### キー管理の検証
端末にキーを保存する方法は様々である。キーを全く保存しないことで、キーマテリアルがダンプされないことが保証される。これは、 PKBDF-2 などのパスワードキー導出機能を使用することで実現できる。以下の例を参照する。

 ```swift
func pbkdf2SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA256(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    let passwordData = password.data(using: String.Encoding.utf8)!
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedKeyDataLength = derivedKeyData.count
    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        salt.withUnsafeBytes { saltBytes in

            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes, salt.count,
                hash,
                UInt32(rounds),
                derivedKeyBytes, derivedKeyDataLength
            )
        }
    }
    if derivationStatus != 0 {
        // Error
        return nil
    }

    return derivedKeyData
}

func testKeyDerivation() {
    let password = "password"
    let salt = Data([0x73, 0x61, 0x6C, 0x74, 0x44, 0x61, 0x74, 0x61])
    let keyByteCount = 16
    let rounds = 100_000

    let derivedKey = pbkdf2SHA1(password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}
```

* 出典： [https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios)（Arcaneライブラリのテストスイートでテスト済み）

キーを保存する必要がある場合、選択した保護クラスが kSecAttrAccessibleAlways でない限り、 Keychain を使用することが推奨される。 NSUserDefaults 、プロパティリストファイル、または Core Data や Realm からの他のシンクによって、他の場所にキーを保管することは、通常 Keychain を使用するよりも安全ではない。 Core Data や Realm の同期が NSFileProtectionComplete データ保護クラスで保護されている場合でも、 Keychain を使用することを推奨する。詳しくは「 [iOS Data Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06d-Testing-Data-Storage.md) 」を参照する。

 Keychain は 2 種類の保存メカニズムをサポートしている。キーはセキュアエンクレーブに保存された暗号キーによって保護されるか、キー自体がセキュアエンクレーブ内にあるかのどちらかである。後者は、 ECDH 署名キーを使用する場合のみ有効である。その実装の詳細については、 [Apple Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave) を参照する。

 最後の 3 つのオプションは、ソースコードにハードコードされた暗号キーを使用する、安定した属性に基づいて予測可能なキー生成関数を持つ、生成されたキーを他のアプリケーションと共有する場所に保存することから構成される。ハードコードされた暗号化鍵を使用することは、アプリケーションのすべてのインスタンスが同じ暗号化鍵を使用することを意味するため、明らかに推奨される方法ではない。攻撃者は、ソースコード（ネイティブに保存されているか、 Objective-C/Swift で保存されているかに関わらず）からキーを抽出するために、一度だけ作業を行う必要がある。その結果、攻撃者は、アプリケーションによって暗号化された他のすべてのデータを解読することができる。次に、他のアプリケーションからアクセス可能な識別子に基づく予測可能なキー導出関数がある場合、攻撃者はキーを見つけるために、 KDF を見つけてデバイスに適用するだけでよい。最後に、対称暗号化キーの公開保存は強く推奨されない。

 暗号に関して忘れるべきでないもう2つの概念がある。

* 常に公開鍵で暗号化・検証し、秘密鍵で復号・署名すること。
* 別の目的で対称鍵を再利用しないこと。これにより、キーに関する情報が漏洩する可能性がある。署名用の対称鍵と暗号化用の対称鍵を別々に用意すること。

ルールブック
* [メモリダンプを考慮してキーを使用する（必須）](#メモリダンプを考慮してキーを使用する必須)
* [ソースコード内にキーやパスワードを保存しない（必須）](#ソースコード内にキーやパスワードを保存しない必須)
* [暗号に関して忘れるべきでない概念の遵守（必須）](#暗号に関して忘れるべきでない概念の遵守必須)

データストレージとプライバシー要件ルールブック
* [Keychain Services API を使用してセキュアに値を保存する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#keychain-services-api-を使用してセキュアに値を保存する必須)

#### 静的解析
探すキーワードは様々である。「問題のある暗号化構成」の概要と静的解析で紹介したライブラリで、キーの保存方法についてどのキーワードを確認するのがベストなのか、確認する。

確認事項
* 高リスクのデータを保護するために使用する場合、キーはデバイス間で同期させないこと。
* キーは追加保護なしで保存されないこと。
* キーがハードコードされていないこと。
* キーは、デバイスの安定した機能から派生したものではないこと。
* キーが低水準言語（ C/C++ など ）の使用により隠されていないこと。
* キーが安全でない場所からインポートされないこと。

静的解析に関する推奨事項のほとんどは、「Testing Data Storage for iOS」の章にすでに記載されている。次に、以下のページで読み解くことができる。

* [Apple Developer Documentation: Certificates and keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys)
* [Apple Developer Documentation: Generating new keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys)
* [Apple Developer Documentation: Key generation attributes](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes)

ルールブック
* [ソースコード内にキーやパスワードを保存しない（必須）](#ソースコード内にキーやパスワードを保存しない必須)
* [クライアント証明書のパスワードをローカルに保存しない、またはデバイスの Keychain にロックする（必須）](#クライアント証明書のパスワードをローカルに保存しないまたはデバイスの-keychain-にロックする必須)
* [クライアント証明書はすべてのインストール間で共有しない（必須）](#クライアント証明書はすべてのインストール間で共有しない必須)
* [モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する（必須）](#モバイルアプリで対称暗号化が使用される場合は常に秘密鍵を安全なデバイスストレージに保存する必須)

データストレージとプライバシー要件ルールブック
* [Keychain Services API を使用してセキュアに値を保存する（必須）](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md#keychain-services-api-を使用してセキュアに値を保存する必須)

#### 動的解析
暗号化方式をフックし、使用されているキーを分析する。暗号化処理中のファイルシステムのアクセスを監視し、キーの書き込み、読み出しを評価する。

### ルールブック
1. [暗号に関して忘れるべきでない概念の遵守（必須）](#暗号に関して忘れるべきでない概念の遵守必須)

#### 暗号に関して忘れるべきでない概念の遵守（必須）
暗号に関して忘れるべきでないもう2つの概念がある。以下の概念を遵守する必要がある。
* 常に公開鍵で暗号化・検証し、秘密鍵で復号・署名すること。
* 別の目的で対称鍵を再利用しないこと。これにより、キーに関する情報が漏洩する可能性がある。署名用の対称鍵と暗号化用の対称鍵を別々に用意すること。

これに違反する場合、以下の可能性がある。
* キーに関する情報が漏洩する可能性がある。

## MSTG-CRYPTO-6
すべての乱数値は十分にセキュアな乱数ジェネレーターを用いて生成されている。

参考資料
* [owasp-mastg Testing Random Number Generation (MSTG-CRYPTO-6)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x06e-Testing-Cryptography.md#testing-random-number-generation-mstg-crypto-6)

### 乱数ジェネレーターの選択
 Apple は、暗号的に安全な乱数を生成する [Randomization Services API](https://developer.apple.com/documentation/security/randomization_services) を提供している。

 Randomization Services API は、 SecRandomCopyBytes関数を使用して数値を生成する。これは、 /dev/random デバイスファイルの wrapper 関数であり、 0 から 255 までの暗号的に安全な疑似乱数値を提供する。すべての乱数がこの API で生成されていることを確認する。開発者が別のものを使う理由はない。

#### 静的解析

  [SecRandomCopyBytes API](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes) は次のように定義されている。

 Swift：

 ```default
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Object-C version](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc)：

 ```objectivec
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

APIの使用例を以下に示す。

 ```objectivec
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

注意：もし他のメカニズムが乱数のために使われているならば、それらが上記のAPIの wrapper であるか、安全な乱数であるかどうかを検証する。多くの場合、これは難しすぎるため、上記の実装に固執するのが最善である。

ルールブック
* [Randomization Services API を使用して安全な乱数を生成（推奨）](#randomization-services-api-を使用して安全な乱数を生成推奨)

#### 動的解析
ランダム性をテストしたい場合は、大きな数値をキャプチャしてみて、 [Burp Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer) のプラグインでランダム性の品質を確認できる。

### ルールブック
1. [Randomization Services API を使用して安全な乱数を生成（推奨）](#randomization-services-api-を使用して安全な乱数を生成推奨)

#### Randomization Services API を使用して安全な乱数を生成（推奨）

鍵の生成やパスワード文字列を生成などの強度は、文字列の文字が完全にランダムである (そして隠されている) 場合、攻撃者はブルート フォース攻撃で考えられるすべての組み合わせを 1 つずつ試すしかなくなる。十分に長い文字列の場合、解析は実行不可能なことになる。

ただし、ランダム化の品質に依存する。明確に定義されたルールに従って境界セットからのソフトウェア命令が実行されるような決定論的システムでは、真のランダム化は不可能である。
十分にランダム化するサービスとして Apple では Randomization Services API を使用して、暗号的に安全な乱数を生成することができる。


 ```swift
import UIKit

class GenerateBitSample {
    func generate10bitRandom() -> [Int8?] {

        var bytes = [Int8](repeating: 0, count: 10)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        if status == errSecSuccess { // Always test the status.
            return bytes
        }

        return []
    }
}
```

これに注意しない場合、以下の可能性がある。
* 安全性の低い乱数が生成される。
