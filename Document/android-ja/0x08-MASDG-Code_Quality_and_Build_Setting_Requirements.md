# コード品質とビルド設定要件

## MSTG-CODE-1
アプリは有効な証明書で署名およびプロビジョニングされている。その秘密鍵は適切に保護されている。

### アプリ署名時に考慮すべき要素

#### 利用する証明書の有効期限

Android では、すべての APK をインストールまたは実行する前に、証明書によるデジタル署名を行うことが義務付けられている。デジタル署名は、アプリケーションの更新時に所有者の身元を確認するために使用される。このプロセスにより、アプリが改ざんされたり、悪意のあるコードが含まれるように変更されたりすることを防ぐことができる。<br>

APK が署名されると、公開鍵証明書が添付される。この証明書は、 APK と開発者、および開発者の秘密鍵を一意に関連付ける。アプリをデバッグモードでビルドする場合、 Android SDK は、デバッグ専用に作成されたデバッグキーでアプリに署名する。デバッグキーで署名されたアプリは、配布されることを意図しておらず、 Google Play ストアを含むほとんどのアプリストアで受け入れられない。<br>

アプリの[最終的なリリースビルド](https://developer.android.com/studio/publish/app-signing.html)は、有効なリリースキーで署名する必要がある。 Android Studio では、アプリは手動で署名するか、リリースビルドタイプに割り当てられた署名設定を作成することで署名できる。<br>

Android 9 (API level 28) 以前の Android では、すべてのアプリのアップデートは同じ証明書で署名する必要があるため、 [25 年以上の有効期間を持つ証明書を推奨](https://developer.android.com/studio/publish/app-signing#considerations)している。 Google Play で公開されるアプリは、 2033 年 10 月 22 日以降に終了する有効期限を持つキーで署名する必要がある。<br>

参考資料
* [owasp-mastg Making Sure That the App is Properly Signed (MSTG-CODE-1) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview)

ルールブック
* [アプリの最終的なリリースビルドでは、有効なリリースキーで署名する（必須）](#アプリの最終的なリリースビルドでは有効なリリースキーで署名する必須)
* [証明書の有効期限（推奨）](#証明書の有効期限推奨)


#### アプリの署名スキーム

4 つの APK 署名スキームが利用可能である。<br>
* JAR 署名 (v1 スキーム)
* APK Signature Scheme v2 (v2 スキーム)
* APK Signature Scheme v3 (v3 スキーム)
* APK Signature Scheme v4 (v4 スキーム)

Android 7.0 (API level 24) 以降でサポートされる v2 スキームは、v1 スキームと比較してセキュリティとパフォーマンスが向上している。 V3 スキームは、 Android 9 (API level 28) 以降でサポートされており、 APK アップデートの一部として署名キーを変更する機能をアプリに提供する。この機能は、新旧両方のキーを使用できるようにすることで、互換性とアプリの継続的な可用性を保証する。 V4 スキームは、 Android 11 (API level 30) 以降でサポートされている。なお、現時点では、 apksigner を介してのみ利用可能である。<br>

各署名方式において、リリースビルドは常に以前のすべての方式でも署名されている必要がある。<br>

参考資料
* [owasp-mastg Making Sure That the App is Properly Signed (MSTG-CODE-1) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview)

ルールブック
* [アプリの署名スキームによるセキュリティの向上（推奨）](#アプリの署名スキームによるセキュリティの向上推奨)

### 静的解析

Android 7.0 (API level 24) 以上では v1 と v2 の両方の方式で、 Android 9 (API level 28) 以上では 3 つの方式すべてでリリースビルド時に署名されており、 APK 内のコード署名証明書が開発者のものであることを確認する。<br>

APK 署名は、 apksigner ツールで検証することができる。 [SDK-Path]/build-tools/[version] に配置されている。<br>
```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

署名証明書の内容は、 jarsigner で確認することができる。なお、デバッグ証明書では Common Name (CN) 属性が "Android Debug" に設定されている。<br>

デバッグ証明書で署名した APK の出力は以下の通りである。<br>
```bash
$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)

```

"CertPath not validated" エラーは無視する。このエラーは、 Java SDK 7 以上で発生する。 jarsigner の代わりに、 apksigner により証明書チェーンを検証することができる。<br>

署名の設定は、 Android Studio または build.gradle の signingConfig ブロックで管理することができる。 v1 および v2 の両方の方式を有効にするには、以下の値を設定する必要がある。
```default
v1SigningEnabled true
v2SigningEnabled true
```

[アプリをリリースするための設定](https://developer.android.com/tools/publishing/preparing.html#publishing-configure)に関するいくつかのベストプラクティスは、公式の Android 開発者向けドキュメントに記載されている。<br>

最後に、アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする。<br>

参考資料
* [owasp-mastg Making Sure That the App is Properly Signed (MSTG-CODE-1) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis)

ルールブック
* [ターゲットとする OS バージョンにマッチした署名を行う（必須）](#ターゲットとする-os-バージョンにマッチした署名を行う必須)
* [アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする（必須）](#アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする必須)

### 動的解析

APL 署名を検証するには、静的解析を使用する必要がある。<br>

参考資料
* [owasp-mastg Making Sure That the App is Properly Signed (MSTG-CODE-1) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis)


### ルールブック
1. [アプリの最終的なリリースビルドでは、有効なリリースキーで署名する（必須）](#アプリの最終的なリリースビルドでは有効なリリースキーで署名する必須)
1. [証明書の有効期限（推奨）](#証明書の有効期限推奨)
1. [アプリの署名スキームによるセキュリティの向上（推奨）](#アプリの署名スキームによるセキュリティの向上推奨)
1. [ターゲットとする OS バージョンにマッチした署名を行う（必須）](#ターゲットとする-os-バージョンにマッチした署名を行う必須)
1. [アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする（必須）](#アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする必須)

#### アプリの最終的なリリースビルドでは、有効なリリースキーで署名する（必須）
アプリの[最終的なリリースビルド](https://developer.android.com/studio/publish/app-signing.html)は、有効なリリースキーで署名する必要がある。 Android Studio では、アプリは手動で署名するか、リリースビルドタイプに割り当てられた署名設定を作成することで署名できる。

<img src="images/0x08/MSTG-CODE-1/keystore-wizard_2x.png" width="50%" />

参考資料
* [アプリに署名して Google Play でリリースする](https://developer.android.com/studio/publish/app-signing?hl=ja#sign-apk)

これに違反する場合、以下の可能性がある。
* Google Play でのアプリの公開ができない。

#### 証明書の有効期限（推奨）

Android 9 (API level 28) 以前の Android では、すべてのアプリのアップデートは同じ証明書で署名する必要があるため、 [25 年以上の有効期間を持つ証明書を推奨](https://developer.android.com/studio/publish/app-signing#considerations)している。 Google Play で公開されるアプリは、 2033 年 10 月 22 日以降に終了する有効期限を持つキーで署名する必要がある。<br>

これに注意しない場合、以下の可能性がある。
* キーの有効期限が切れると、ユーザはアプリの新しいバージョンにシームレスにアップグレードできなくなる。


#### アプリの署名スキームによるセキュリティの向上（推奨）

Android アプリでは以下の 4 つの APK 署名スキームが利用可能である。
* JAR 署名 (v1 スキーム)
* APK Signature Scheme v2 (v2 スキーム)
* APK Signature Scheme v3 (v3 スキーム)
* APK Signature Scheme v4 (v4 スキーム)

Android 7.0 (API level 24) 以降でサポートされる v2 スキームは、v1 スキームと比較してセキュリティとパフォーマンスが向上している。 V3 スキームは、 Android 9 (API level 28) 以降でサポートされており、 APK アップデートの一部として署名キーを変更する機能をアプリに提供する。この機能は、新旧両方のキーを使用できるようにすることで、互換性とアプリの継続的な可用性を保証する。 V4 スキームは、 Android 11 (API level 30) 以降でサポートされている。なお、現時点では、 apksigner を介してのみ利用可能である。

各署名方式において、リリースビルドは常にその前のすべての方式でも署名されている必要がある。等

以下は apksigner による署名方法である。
```shell
apksigner sign --ks keystore.jks |
  --key key.pk8 --cert cert.x509.pem
  [signer_options] app-name.apk


--v1-signing-enabled <true | false>
指定された APK パッケージに apksigner が署名する際に、従来の JAR ベースの署名スキームを使用するかどうかを指定します。デフォルトでは、このツールは --min-sdk-version と --max-sdk-version の値を使用して、この署名スキームをいつ適用するかを決定します。
--v2-signing-enabled <true | false>
指定された APK パッケージに apksigner が署名する際に、APK 署名スキーム v2 を使用するかどうかを指定します。デフォルトでは、このツールは --min-sdk-version と --max-sdk-version の値を使用して、この署名スキームをいつ適用するかを決定します。
--v3-signing-enabled <true | false>
指定された APK パッケージに apksigner が署名する際に、APK 署名スキーム v3 を使用するかどうかを指定します。デフォルトでは、このツールは --min-sdk-version と --max-sdk-version の値を使用して、この署名スキームをいつ適用するかを決定します。
```

参考資料
* [JAR 署名 (v1 スキーム)](https://source.android.com/docs/security/features/apksigning#v1)
* [APK Signature Scheme v2 (v2 スキーム)](https://source.android.google.cn/docs/security/features/apksigning/v2?hl=ja)
* [APK Signature Scheme v3 (v3 スキーム)](https://source.android.google.cn/docs/security/features/apksigning/v3?hl=ja)
* [APK Signature Scheme v4 (v4 スキーム)](https://source.android.google.cn/docs/security/features/apksigning/v4?hl=ja)

これに注意しない場合、以下の可能性がある。
* セキュリティとパフォーマンスが低下する可能性がある。

#### ターゲットとする OS バージョンにマッチした署名を行う（必須）

Android 7.0 (API level 24) 以上では v1 と v2 の両方の方式で、 Android 9 (API level 28) 以上では 3 つの方式 (v1, v2, v3) すべてでリリースビルド時に署名する。 Android 11 (API level 30) 以上では v4 署名と、これを補完するために v2 または v3 署名が必要である。旧バージョンの Android を実行するデバイスをサポートするには、APK 署名スキーム v2 以降を使用した署名に加えて、引き続き APK 署名スキーム v1 を使用して APK に署名する必要がある。

以下は、 apksigner コマンドによる APK への署名方法。
```shell
apksigner sign --ks [キーストアファイル] -v --ks-key-alias [キーエイリアス] --ks-pass pass:[キーストアパスワード] [未署名のAPKファイル]
```

これに違反する場合、以下の可能性がある。
* セキュリティとパフォーマンスが低下する可能性がある。

#### アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする（必須）

アプリケーションは決して内部のテスト用証明書とともにデプロイされないようにする必要がある。

これに違反する場合、以下の可能性がある。
* ログやデバッグが有効の状態でデプロイされてしまう可能性がある。
* アプリストアで受け入れられない可能性がある。

## MSTG-CODE-2
アプリはリリースモードでビルドされている。リリースビルドに適した設定である（デバッグ不可など）。

### アプリのデバッグ有効/無効の切替

Android manifest で定義される [Application 要素](https://developer.android.com/guide/topics/manifest/application-element.html)の android:debuggable 属性は、アプリがデバッグ可能かどうかを決定する。<br>

参考資料
* [owasp-mastg Testing Whether the App is Debuggable (MSTG-CODE-2) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-1)

### 静的解析

AndroidManifest.xml を確認し、 android:debuggable 属性が設定されているかどうか、またその属性値を確認する。<br>
```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

Android SDK に含まれる apt ツールを以下のコマンドラインで使用すると、 android:debuggable="true" ディレクティブが存在するかどうかを迅速に確認することができる。<br>
```bash
# If the command print 1 then the directive is present
# The regex search for this line: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
$ aapt d xmltree sieve.apk AndroidManifest.xml | grep -Ec "android:debuggable\(0x[0-9a-f]+\)=\(type\s0x[0-9a-f]+\)0xffffffff"
1
```

リリースビルドの場合、この属性は常に "false" (デフォルト値) に設定されるべきである。<br>

参考資料
* [owasp-mastg Testing Whether the App is Debuggable (MSTG-CODE-2) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-1)

ルールブック
* [リリース時は android:debuggable 属性を false にすべきである（推奨）](#リリース時は-androiddebuggable-属性を-false-にすべきである推奨)

### 動的解析

adb は、アプリケーションがデバッグ可能かどうかを判断するために使用することができる。<br>

次のコマンドを使用する。<br>
```bash
# If the command print a number superior to zero then the application have the debug flag
# The regex search for these lines:
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
# pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
$ adb shell dumpsys package com.mwr.example.sieve | grep -c "DEBUGGABLE"
2
$ adb shell dumpsys package com.nondebuggableapp | grep -c "DEBUGGABLE"
0
```

デバッグ可能なアプリケーションであれば、アプリケーションコマンドの実行は簡単である。 adb shell で、バイナリ名にパッケージ名とアプリケーションコマンドを付加して run-as を実行する。<br>
```bash
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html) は、アプリケーションのデバッグや、アプリのデバッグ有効化の確認にも利用できる。<br>

アプリケーションがデバッグ可能かどうかを判断する別の方法として、実行中のプロセスに jdb をアタッチする方法がある。これが成功すると、デバッグが有効になる。<br>

以下の手順で、 jdb を用いたデバッグセッションを開始することができる。<br>

1. adb と jdwp を使用して、デバッグしたいアクティブなアプリケーションの PID を特定する。<br>
    ```bash
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```
2. 特定のローカルポートを使って、アプリケーションプロセス (PID を使用) とホストコンピュータの間に adb による通信チャネルを作成する。<br>
    ```bash
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```
3. jdb を使用して、ローカル通信チャネルポートにデバッガをアタッチし、デバッグセッションを開始する。<br>
    ```bash
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

デバッグに関するいくつかの注意点は以下の通りである。<br>
* [JADX](https://github.com/skylot/jadx) は、ブレークポイント挿入のための興味深い場所を特定するために使用することができる。
* jdb の基本的なコマンドの使い方は、 [Tutorialspoint](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm) に掲載されている。
* jdb がローカル通信チャネルポートにバインドされているときに、「デバッガへの接続が閉じられました」というエラーが発生した場合、すべての adb セッションを終了して、新しいセッションを 1 つだけ開始する。

参考資料
* [owasp-mastg Testing Whether the App is Debuggable (MSTG-CODE-2) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-1)

### ルールブック
1. [リリース時は android:debuggable 属性を false にすべきである（推奨）](#リリース時は-androiddebuggable-属性を-false-にすべきである推奨)

#### リリース時は android:debuggable 属性を false にすべきである（推奨）

リリース時は android:debuggable 属性を false にすべてきである。

これに違反する場合、以下の可能性がある。
* 悪意のあるユーザに悪用されてしまう可能性がある。

## MSTG-CODE-3
デバッグシンボルはネイティブバイナリから削除されている。

### デバッグシンボルの有無

一般に、コンパイルされたコードには、できるだけ説明を省く必要がある。デバッグ情報、行番号、説明的な関数名やメソッド名などの一部のメタデータは、リバースエンジニアがバイナリやバイトコードを理解しやすくするが、これらはリリースビルドでは必要ないため、アプリの機能に影響を与えることなく安全に省略することが可能である。<br>

ネイティブバイナリを検査するには、nm や objdump などの標準的なツールを使用して、シンボルテーブルを調べる。一般に、リリースビルドにはデバッグ用シンボルを含めるべきではない。ライブラリの難読化が目的であれば、不要なダイナミックシンボルを削除することも推奨される。<br>

参考資料
* [owasp-mastg Testing for Debugging Symbols (MSTG-CODE-3) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-2)

ルールブック
* [リリースビルドではコード情報を出力しないようにする（必須）](#リリースビルドではコード情報を出力しないようにする必須)

### 静的解析

シンボルは通常ビルドプロセスで取り除かれるので、不要なメタデータが破棄されたことを確認するために、コンパイルされたバイトコードとライブラリが必要である。<br>

まず、 Android NDK で nm バイナリを見つけ、それをエクスポートする (またはエイリアスを作成する) 。<br>
```bash
export NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

デバッグシンボルを表示する場合は以下の通りである。<br>
```bash
$NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

ダイナミックシンボルを表示する場合は以下の通りである。<br>
```bash
$NM -D libfoo.so
```

または、お気に入りのディスアセンブラでファイルを開き、シンボルテーブルを手動でチェックする。<br>

動的シンボルは、 visibility コンパイラーフラグによって除去することができる。このフラグを追加すると、 gcc は JNIEXPORT として宣言された関数の名前を保持したまま、関数名を破棄するようになる。<br>

build.gradle に以下が追加されていることを確認する。<br>
```default
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

参考資料
* [owasp-mastg Testing for Debugging Symbols (MSTG-CODE-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-2)

### 動的解析

デバッグ用シンボルの検証には、静的解析を使用する必要がある。

参考資料
* [owasp-mastg Testing for Debugging Symbols (MSTG-CODE-3) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-2)

### ルールブック
1. [リリースビルドではコード情報を出力しないようにする（必須）](#リリースビルドではコード情報を出力しないようにする必須)

#### リリースビルドではコード情報を出力しないようにする（必須）
コンパイルされたコードには、できるだけ説明を省く必要がある。デバッグ情報、行番号、説明的な関数名やメソッド名などの一部のメタデータは、リバースエンジニアがバイナリやバイトコードを理解しやすくするが、これらはリリースビルドでは必要ないため、アプリの機能に影響を与えることなく安全に削除する必要がある。

また、リリースビルドにはデバッグ用シンボルを含めるべきではなく、ライブラリの難読化が目的であれば、不要なダイナミックシンボルを削除することも推奨される。

ダイナミックシンボルは、 visibility コンパイラーフラグによって除去することができる。このフラグを追加すると、 gcc は JNIEXPORT として宣言された関数の名前を保持したまま、関数名を破棄するようになる。

build.gradle に以下が追加されていることを確認する。
```default
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

これに違反する場合、以下の可能性がある。
* コード内のデバッグ情報、行番号、説明的な関数名やメソッド名などの一部のメタデータを漏洩する可能性がある。

## MSTG-CODE-4
デバッグコードおよび開発者支援コード (テストコード、バックドア、隠し設定など) は削除されている。アプリは詳細なエラーやデバッグメッセージをログ出力していない。

### StrictMode の利用

StrictMode は、アプリケーションのメインスレッドでの偶発的なディスクやネットワークアクセスなどの違反を検出するための開発者用ツールである。また、パフォーマンスの高いコードの実装など、良いコーディングの実践を確認するためにも使用できる。<br>

以下は、メインスレッドへのディスクアクセスやネットワークアクセスに対するポリシーが有効な [StrictMode の例](https://developer.android.com/reference/android/os/StrictMode.html)である。<br>
```java
public void onCreate() {
     if (DEVELOPER_MODE) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }
```

DEVELOPER_MODE 条件で if 文の中にポリシーを挿入することを推奨する。 StrictMode を無効にするには、リリースビルドで DEVELOPER_MODE を無効にする必要がある。<br>

参考資料
* [owasp-mastg Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-3)

ルールブック
* [デバッグ時のみ StrictMode を使用する（推奨）](#デバッグ時のみ-strictmode-を使用する推奨)

### 静的解析

StrictMode が有効かどうかを判断するには、 StrictMode.setThreadPolicy または StrictMode.setVmPolicy メソッドを探せばよい。ほとんどの場合、これらは onCreate メソッドにある。<br>

[スレッドポリシーの検出方法](https://javabeat.net/strictmode-android-1/)は以下の通りである。<br>
```java
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

[スレッドポリシー違反の罰則](https://javabeat.net/strictmode-android-1/)は以下の通りである。<br>
```java
penaltyLog() // Logs a message to LogCat
penaltyDeath() // Crashes application, runs at the end of all enabled penalties
penaltyDialog() // Shows a dialog
```

StrictMode を使用するための[ベストプラクティス](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581)を確認する。<br>

参考資料
* [owasp-mastg Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-3)

### 動的解析

StrictMode を検出する方法はいくつかある。最適な方法は、ポリシーの役割がどのように実装されているかによる。以下のようなものが存在する。<br>
* Logcat
* 警告ダイアログ
* アプリケーションのクラッシュ

参考資料
* [owasp-mastg Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-3)

### ルールブック
1. [デバッグ時のみ StrictMode を使用する（推奨）](#デバッグ時のみ-strictmode-を使用する推奨)

#### デバッグ時のみ StrictMode を使用する（推奨）
StrictMode はアプリのメインスレッドでの偶発的なディスクやネットワークアクセスなどの違反を検出するための開発者用ツールである。
StrictMode 利用する場合は、スレッドポリシーと VM ポリシーを設定する必要がある。
そのため、開発時に組み込まれた StrictMode の設定処理がリリース版アプリに組み込まれないために、ポリシーの設定処理の前に分岐を設けるなど、対応する必要がある。

以下に開発用に StrictMode のポリシー設定を組み込んだサンプルコードを示す。
```java
public void onCreate() {
     if (DEVELOPER_MODE) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }
```

この場合、以下の可能性がある。
* ディスクアクセス等の情報が漏洩する可能性がある。

## MSTG-CODE-5
モバイルアプリで使用されるライブラリ、フレームワークなどのすべてのサードパーティコンポーネントを把握し、既知の脆弱性を確認している。

### サードパーティライブラリ使用時の注意点

Android アプリは、サードパーティーライブラリを利用することが多い。これらのサードパーティライブラリを利用することで、開発者は問題を解決するために書くコードが少なくなり、開発が加速される。ライブラリには2つのカテゴリがある。<br>
* テストに使われる Mockito や、特定のライブラリをコンパイルするために使われる JavaAssist のようなライブラリのように、実際のプロダクション・アプリケーションに組み込まれない (あるいは組み込まれるべきではない) ライブラリである。
* Okhttp3 のような、実際のプロダクション・アプリケーション内にパックされているライブラリ。

これらのライブラリは、望ましくない副作用をもたらす可能性がある。<br>
* ライブラリは脆弱性を含んでいる可能性があり、それがアプリケーションを脆弱にする。良い例として、 OKHTTP の 2.7.5 より前のバージョンでは、 TLS チェーン汚染により SSL ピンニングをバイパスすることが可能であった。
* ライブラリがメンテナンスされなくなったり、ほとんど使われなくなったりして、脆弱性の報告や修正がされなくなる。そのため、脆弱性の報告や修正が行われず、ライブラリを通してアプリケーションに不正なコードや脆弱性のあるコードが含まれる可能性がある。
* 「ライブラリは LGPL2.1 などのライセンスを使用できる。この場合、アプリケーションの作成者は、アプリケーションを使用してそのソースの洞察を要求するユーザに、ソース コードへのアクセスを提供する必要がある。実際、アプリケーションは、ソースコードを変更して再配布できるようにする必要がある。これにより、アプリケーションの知的財産 (IP) が危険にさらされる可能性がある。

この問題は、複数のレベルで発生する可能性があることに注意する。 webview で JavaScript を使用する場合、 JavaScript のライブラリにもこのような問題がある可能性がある。 Cordova 、 React-native 、 Xamarin アプリのプラグイン/ライブラリも同様である。<br>

参考資料
* [owasp-mastg Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-4)

ルールブック
* [サードパーティライブラリの使用には注意する（推奨）](#サードパーティライブラリの使用には注意する推奨)

### 静的解析

#### 使用するライブラリの脆弱性

サードパーティの依存関係における脆弱性の検出は、 OWASP Dependency checker によって行うことができる。これは、 [dependency-check-gradle](https://github.com/jeremylong/dependency-check-gradle) のような gradle プラグインを使用することで最もよく行われる。このプラグインを使用するためには、以下の手順を適用する必要がある。以下のスクリプトを build.gradle に追加し、 Maven セントラルリポジトリからプラグインをインストールする。<br>
```default
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.2.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
```

gradle がプラグインを呼び出したら、実行することでレポートを作成することができる。<br>
```bash
gradle assemble
gradle dependencyCheckAnalyze --info
```

レポートは、特に設定されない限り、build/reports に置かれる。発見された脆弱性を分析するために、レポートを使用する。ライブラリで見つかった脆弱性から何をすべきかについては、改善策を参照する。<br>

プラグインは、脆弱性フィードをダウンロードする必要があることに注意する。プラグインで問題が発生した場合は、ドキュメントを参照する。<br>

また、 [Sonatype Nexus IQ](https://www.sonatype.com/nexus/iqserver) 、 [Sourceclear](https://www.sourceclear.com/) 、 [Snyk](https://snyk.io/) 、 [Blackduck](https://www.blackducksoftware.com/) など、使用するライブラリの依存関係をよりよくカバーする商用ツールもある。 OWASP Dependency Checker または他のツールを使用した場合の実際の結果は、 (NDK 関連または SDK 関連) ライブラリの種類によって異なる。<br>

最後に、ハイブリッドアプリケーションの場合、 RetireJS で JavaScript の依存性をチェックする必要があることに注意する。同様に、 Xamarin の場合は、 C# の依存性をチェックする必要がある。<br>

ライブラリが脆弱性を含んでいることが判明した場合、以下の推論が適用される。
* そのライブラリは、アプリケーションと一緒にパッケージされているか。次に、そのライブラリに脆弱性のパッチが適用されたバージョンがあるかどうかをチェックする。もしそうでなければ、その脆弱性が実際にアプリケーションに影響を与えるかどうかをチェックする。もしそうであれば、または将来そうなる可能性があるのであれば、同様の機能を提供し、かつ脆弱性のない代替品を探す。
* そのライブラリは、アプリケーションと一緒にパッケージされていないか。脆弱性が修正されたパッチが適用されたバージョンがあるかどうか確認する。そうでない場合、その脆弱性がビルドプロセスに影響を与えるかどうか確認する。その脆弱性がビルドの妨げになったり、ビルドパイプラインのセキュリティを弱めたりする可能性はないか。そして、その脆弱性が修正されている代替案を探す。

ソースが入手できない場合、アプリを逆コンパイルして、 JAR ファイルを確認することができる。 Dexguard や [ProGuard](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#proguard) が適切に適用されている場合、ライブラリに関するバージョン情報は消えていることがよくある。そうでない場合は、与えられたライブラリの Java ファイルのコメントで、非常に多くの情報を見つけることができる。 MobSF のようなツールは、アプリケーションに含まれる可能性のあるライブラリの分析に役立つ。もし、コメントや特定のバージョンで使用される特定のメソッドによってライブラリのバージョンを取得できるなら、手動で CVE を調べることができる。<br>


もし、そのアプリケーションが高リスクのアプリケーションであれば、結局は手作業でライブラリを吟味することになる。その場合、ネイティブコードに特有の要件があり、それは「[コード品質のテスト](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md)」の章に記載されている。その次に、ソフトウェアエンジニアリングのベストプラクティスがすべて適用されているかどうかを吟味するのがよい。<br>

参考資料
* [owasp-mastg Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5) Detecting vulnerabilities of third party libraries](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#detecting-vulnerabilities-of-third-party-libraries)

ルールブック
* [ライブラリのアプリの依存関係の解析方法（必須）](#ライブラリのアプリの依存関係の解析方法必須)

#### 使用するライブラリのライセンス

著作権法に抵触していないことを確認するためには、 License Gradle Plugin のようなライブラリの依存関係を繰り返し確認することができるプラグインを使用するのが一番良い方法である。このプラグインは、次の手順で使用できる。<br>

build.gradle ファイルに以下を追加する。<br>
```default
plugins {
    id "com.github.hierynomus.license-report" version"{license_plugin_version}"
}
```

プラグインがピックアップされたら、次のコマンドを使う。<br>
```bash
gradle assemble
gradle downloadLicenses
```

これで、ライセンスレポートが生成され、サードパーティライブラリで使用されているライセンスを参照するために使用することができる。アプリに著作権表示を含める必要があるかどうか、また、ライセンスの種類によってアプリのコードをオープンソースにする必要があるかどうかを確認するために、ライセンス契約を確認する。<br>

依存関係のチェックと同様に、 [Sonatype Nexus IQ](https://www.sonatype.com/nexus/iqserver) 、 [Sourceclear](https://www.sourceclear.com/) 、 [Snyk](https://snyk.io/) 、 [Blackduck](https://www.blackducksoftware.com/) など、ライセンスをチェックできる商用ツールもある。<br>

注意 : サードパーティのライブラリで使用されているライセンスモデルの意味について疑問がある場合は、法律の専門家に相談する。<br>

ライブラリにアプリケーション知的財産 (IP) をオープンソース化する必要があるライセンスが含まれている場合、同様の機能を提供するために使用できるライブラリの代替品があるかどうかを確認する。<br>

注 ： ハイブリッドアプリの場合、使用されているビルドツールを確認する ： それらのほとんどは、使用されているライセンスを見つけるためのライセンス列挙プラグインを持っている。<br>

ソースが入手できない場合、アプリを逆コンパイルして JAR ファイルを確認することができる。 Dexguard や [ProGuard](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#proguard) が適切に適用されている場合、ライブラリに関するバージョン情報が消えていることがよくある。そうでない場合は、与えられたライブラリの Java ファイルのコメントで、まだ非常に頻繁に見つけることができる。 MobSF のようなツールは、アプリケーションに同梱されている可能性のあるライブラリの分析に役立つ。もし、コメントや特定のバージョンで使用されている特定のメソッドによって、ライブラリのバージョンを取得することができれば、手動で使用されているライセンスを調べることができる。<br>

参考資料
* [owasp-mastg Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5) Detecting the Licenses Used by the Libraries of the Application](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#detecting-the-licenses-used-by-the-libraries-of-the-application)

### 動的解析

このセクションの動的解析は、ライセンスの著作権が順守されているかどうかを検証する。これは、アプリケーションに、サードパーティライブラリのライセンスが要求する著作権に関する記述がある、 about または EULA セクションが必要であることを意味することが多い。

参考資料
* [owasp-mastg Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-4)

ルールブック
* [ライセンスの著作権が順守されているかどうかの検証（必須）](#ライセンスの著作権が順守されているかどうかの検証必須)


### ルールブック
1. [サードパーティライブラリの使用には注意する（推奨）](#サードパーティライブラリの使用には注意する推奨)
1. [ライブラリのアプリの依存関係の解析方法（必須）](#ライブラリのアプリの依存関係の解析方法必須)
1. [ライセンスの著作権が順守されているかどうかの検証（必須）](#ライセンスの著作権が順守されているかどうかの検証必須)

#### サードパーティライブラリの使用には注意する（推奨）
サードパーティライブラリには以下の欠点があるため、使用する場合は吟味する必要がある。

* ライブラリに含まれる脆弱性。脆弱性が含まれるライブラリを使用すると、ライブラリを通してアプリケーションに不正なコードや脆弱性のあるコードが含まれる可能性があるため注意する。また現時点では脆弱性が発見されていない場合でも今後発見される可能性も存在する。その場合は、脆弱性に対応したバージョンに更新するか、更新バージョンがない場合は使用を控える。
* ライブラリに含まれるライセンス。ライブラリの中には、そのライブラリを使用した場合、使用したアプリのソースコードの展開を求めるライセンスが存在するため注意する。

この問題は、複数のレベルで発生する可能性があることに注意する。 webview で JavaScript を使用する場合、 JavaScript のライブラリにもこのような問題がある可能性がある。 Cordova 、 React-native 、 Xamarin アプリのプラグイン/ライブラリも同様である。<br>

※サードパーティライブラリの使用注意に関するルールのため、サンプルコードなし。

これに注意しない場合、以下の可能性がある。
* アプリケーションに不正なコードや脆弱性のあるコードが含まれており、悪用される可能性がある。
* サードパーティライブラリに含まれるライセンスにより、アプリのソースコードの展開を求められる可能性がある。

#### ライブラリのアプリの依存関係の解析方法（必須）
サードパーティの依存関係における脆弱性の検出は、 OWASP Dependency checker によって行うことができる。これは、 [dependency-check-gradle](https://github.com/jeremylong/dependency-check-gradle) のような gradle プラグインを使用することで最もよく行われる。このプラグインを使用するためには、以下の手順を適用する必要がある。以下のスクリプトを build.gradle に追加し、 Maven セントラルリポジトリからプラグインをインストールする。<br>
```default
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.2.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
```

gradle がプラグインを呼び出したら、実行することでレポートを作成することができる。<br>
```bash
gradle assemble
gradle dependencyCheckAnalyze --info
```

レポートは、特に設定されない限り、build/reports に置かれる。発見された脆弱性を分析するために、レポートを使用する。ライブラリで見つかった脆弱性から何をすべきかについては、脆弱性の理由を確認する。<br>

プラグインは、脆弱性フィードをダウンロードする必要があることに注意する。プラグインで問題が発生した場合は、ドキュメントを参照する。<br>

また、 [Sonatype Nexus IQ](https://www.sonatype.com/nexus/iqserver) 、 [Sourceclear](https://www.sourceclear.com/) 、 [Snyk](https://snyk.io/) 、 [Blackduck](https://www.blackducksoftware.com/) など、使用するライブラリの依存関係をよりよくカバーする商用ツールもある。 OWASP Dependency Checker または他のツールを使用した場合の実際の結果は、 (NDK 関連または SDK 関連) ライブラリの種類によって異なる。<br>

最後に、ハイブリッドアプリケーションの場合、 RetireJS で JavaScript の依存性をチェックする必要があることに注意する。同様に、 Xamarin の場合は、 C# の依存性をチェックする必要がある。<br>

ライブラリが脆弱性を含んでいることが判明した場合、以下の理由が適用される。
* そのライブラリは、アプリケーションと一緒にパッケージされているか。次に、そのライブラリに脆弱性のパッチが適用されたバージョンがあるかどうかをチェックする。もしそうでなければ、その脆弱性が実際にアプリケーションに影響を与えるかどうかをチェックする。もしそうであれば、または将来そうなる可能性があるのであれば、同様の機能を提供し、かつ脆弱性のない代替品を探す。
* そのライブラリは、アプリケーションと一緒にパッケージされていないか。脆弱性が修正されたパッチが適用されたバージョンがあるかどうか確認する。そうでない場合、その脆弱性がビルドプロセスに影響を与えるかどうか確認する。その脆弱性がビルドの妨げになったり、ビルドパイプラインのセキュリティを弱めたりする可能性はないか。そして、その脆弱性が修正されている代替案を探す。

ソースが入手できない場合、アプリを逆コンパイルして、 JAR ファイルを確認することができる。 Dexguard や [ProGuard](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#proguard) が適切に適用されている場合、ライブラリに関するバージョン情報は消えていることがよくある。そうでない場合は、与えられたライブラリの Java ファイルのコメントで、非常に多くの情報を見つけることができる。 MobSF のようなツールは、アプリケーションに含まれる可能性のあるライブラリの分析に役立つ。もし、コメントや特定のバージョンで使用される特定のメソッドによってライブラリのバージョンを取得できるなら、手動で CVE を調べることができる。<br>

もし、そのアプリケーションが高リスクのアプリケーションであれば、結局は手作業でライブラリを吟味することになる。その場合、ネイティブコードに特有の要件があり、それは「[コード品質のテスト](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md)」の章に記載されている。その次に、ソフトウェアエンジニアリングのベストプラクティスがすべて適用されているかどうかを吟味するのがよい。<br>

これに違反する場合、以下の可能性がある。
* ライブラリに脆弱性のあるコードが含まれており、悪用される可能性がある。


#### ライセンスの著作権が順守されているかどうかの検証（必須）
主要なライセンスに共通する特徴として、派生ソフトウェアを頒布する際は、利用元 OSS の「著作権」「ライセンス文」「免責事項」などを表示しなければならない点が挙げられる。
具体的に「何を」「どこに」「どのように」表示するかは**各ライセンスによって異なる可能性がある**ため、詳細は個別のライセンスを丁寧に確認する必要がある。

例えば MIT License では下記の記述によって「著作権表示」および「ライセンス文」を、「ソフトウェアのすべての複製または重要な部分に記載する」よう定められている。

```default
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
```

これに違反する場合、以下の可能性がある。
* アプリの IP をオープンソースにする必要があるライセンスがライブラリに含まれている可能性がある。


## MSTG-CODE-6
アプリは可能性のある例外を catch し処理している。

### 例外処理の注意点

例外は、アプリケーションが異常な状態やエラー状態に陥ったときに発生する。 Java と C++ の両方が例外を発生する可能性がある。例外処理のテストは、アプリケーションが例外を処理し、 UI やアプリケーションのロギングメカニズムを通じて機密情報を公開することなく安全な状態に移行することを確認することである。<br>

参考資料
* [owasp-mastg Testing Exception Handling (MSTG-CODE-6 and MSTG-CODE-7) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-5)

### 静的解析

アプリケーションを理解するためにソースコードを見直し、異なるタイプのエラー (IPC 通信、リモートサービスの呼び出しなど) をどのように処理しているかを確認する。この段階でチェックすべき事項の例をいくつか挙げる。<br>
* アプリケーションは、[例外を処理](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88487665)するためによく設計され、統一されたスキームを使用することを確認する。
* NullPointerException 、 IndexOutOfBoundsException 、 ActivityNotFoundException 、 CancellationException 、 SQLException などの標準的な RuntimeException を想定し、 Null チェックやバウンドチェックなど適切な処理を行う。 [RuntimeException の利用可能なサブクラスの概要](https://developer.android.com/reference/java/lang/RuntimeException.html)については、 Android 開発者向けドキュメントに記載されている。 RuntimeException の子クラスは意図的にthrow されるべきであり、その意図は呼び出し側のメソッドによって処理されるべきである。
* すべての　non-runtime Throwable に対して、適切な catch ハンドラが存在することを確認し、実際の例外を適切に処理するようにする。
* 例外が発生した場合、アプリケーションは同様の動作をする例外のハンドラを一元的に持つようにする。これは静的なクラスでもかまわない。メソッドに固有の例外については、固有の catch blocks を用意する。
* アプリケーションが例外処理中に機密情報を UI やログステートメントで公開しないようにする。ユーザに問題を説明するために、例外はまだ十分に冗長であることを確認する。
* 高リスクのアプリケーションが扱うすべての機密情報が、 finally blocks　の実行中に常にワイプされることを確認する。

```java
byte[] secret;
try{
    //use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2 e) {
    // handle any issues
} finally {
    //clean the secret.
}
```

catch　できない例外のために一般的な例外ハンドラを追加することは、クラッシュが差し迫っているときにアプリケーションの状態をリセットするためのベストプラクティスである。<br>
```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {

    private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
    private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

    //initialize the handler and set it as the default exception handler
    public static void init() {
        S_INSTANCE.mHandlers.add(Thread.getDefaultUncaughtExceptionHandler());
        Thread.setDefaultUncaughtExceptionHandler(S_INSTANCE);
    }

     //make sure that you can still add exception handlers on top of it (required for ACRA for instance)
    public void subscribeCrashHandler(Thread.UncaughtExceptionHandler handler) {
        mHandlers.add(handler);
    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {

            //handle the cleanup here
            //....
            //and then show a message to the user if possible given the context

        for (Thread.UncaughtExceptionHandler handler : mHandlers) {
            handler.uncaughtException(thread, ex);
        }
    }
}
```

ここで、ハンドラのイニシャライザは、カスタムアプリケーションクラス (例えば、 Application を継承したクラス) で呼び出す必要がある。<br>
```java
@Override
protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    MemoryCleanerOnCrash.init();
}
```

参考資料
* [owasp-mastg Testing Exception Handling (MSTG-CODE-6 and MSTG-CODE-7) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-5)

ルールブック
* [例外/エラー処理の適切な実装と確認事項（必須）](#例外エラー処理の適切な実装と確認事項必須)
* [catch できない例外の場合のベストプラクティス（推奨）](#catch-できない例外の場合のベストプラクティス推奨)


### 動的解析

動的解析にはいくつかの方法がある。<br>
* Xposed を使ってメソッドにフックし、予期しない値で呼び出すか、既存の変数を予期しない値 (例えば NULL 値) で上書きする。
* Android アプリケーションの UI フィールドに予期しない値を入力する。
* アプリケーションの intents 、public providers 、および予期しない値を使用して、アプリケーションと対話する。
* ネットワーク通信やアプリケーションに保存されているファイルを改ざんする。

アプリケーションは決してクラッシュしてはならない。<br>
* エラーから回復するか、継続不可能であることをユーザに知らせることができる状態に移行する。
* 必要であれば、ユーザに適切な行動をとるように指示する (メッセージは機密情報を漏らしてはならない) 。
* アプリケーションで使用されるロギングメカニズムにおいて、いかなる情報も提供しないこと。

参考資料
* [owasp-mastg Testing Exception Handling (MSTG-CODE-6 and MSTG-CODE-7) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-5)

### ルールブック
1. [例外/エラー処理の適切な実装と確認事項（必須）](#例外エラー処理の適切な実装と確認事項必須)
1. [catch できない例外の場合のベストプラクティス（推奨）](#catch-できない例外の場合のベストプラクティス推奨)


#### 例外/エラー処理の適切な実装と確認事項（必須）

Android で例外/エラー処理を実装する場合は、以下内容を確認する必要がある。<br>
* アプリケーションは、[例外を処理](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88487665)するためによく設計され、統一されたスキームを使用することを確認する。
* NullPointerException 、 IndexOutOfBoundsException 、 ActivityNotFoundException 、 CancellationException 、 SQLException などの標準的な RuntimeException を想定し、 Null チェックやバウンドチェックなど適切な処理を行う。 [RuntimeException の利用可能なサブクラスの概要](https://developer.android.com/reference/java/lang/RuntimeException.html)については、 Android 開発者向けドキュメントに記載されている。 RuntimeException の子クラスは意図的にthrow されるべきであり、その意図は呼び出し側のメソッドによって処理されるべきである。
* すべての　non-runtime Throwable に対して、適切な catch ハンドラが存在することを確認し、実際の例外を適切に処理するようにする。
* 例外が発生した場合、アプリケーションは同様の動作をする例外のハンドラを一元的に持つようにする。これは静的なクラスでもかまわない。メソッドに固有の例外については、固有の catch blocks を用意する。
* アプリケーションが例外処理中に機密情報を UI やログステートメントで公開しないようにする。ユーザに問題を説明するために、例外はまだ十分に冗長であることを確認する。
* 高リスクのアプリケーションが扱うすべての機密情報が、 finally blocks　の実行中に常にワイプされることを確認する。


これに違反する場合、以下の可能性がある。
* アプリケーションのクラッシュが発生する。
* 機密情報が漏洩する。

#### catch できない例外の場合のベストプラクティス（推奨）


catch　できない例外のために一般的な例外ハンドラを追加することは、クラッシュが差し迫っているときにアプリケーションの状態をリセットするためのベストプラクティスである。<br>
```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {

    private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
    private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

    //initialize the handler and set it as the default exception handler
    public static void init() {
        S_INSTANCE.mHandlers.add(Thread.getDefaultUncaughtExceptionHandler());
        Thread.setDefaultUncaughtExceptionHandler(S_INSTANCE);
    }

     //make sure that you can still add exception handlers on top of it (required for ACRA for instance)
    public void subscribeCrashHandler(Thread.UncaughtExceptionHandler handler) {
        mHandlers.add(handler);
    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {

            //handle the cleanup here
            //....
            //and then show a message to the user if possible given the context

        for (Thread.UncaughtExceptionHandler handler : mHandlers) {
            handler.uncaughtException(thread, ex);
        }
    }
}
```

ここで、ハンドラのイニシャライザは、カスタムアプリケーションクラス (例えば、 Application を継承したクラス) で呼び出す必要がある。<br>
```java
@Override
protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    MemoryCleanerOnCrash.init();
}
```

これに注意しない場合、以下の可能性がある。
* アプリケーションのクラッシュが発生する。
* 機密情報が漏洩する。

## MSTG-CODE-7
セキュリティコントロールのエラー処理ロジックはデフォルトでアクセスを拒否している。

<span style="color: red; ">※例外処理に関する記載は「7.6.1. 例外処理の注意点」へ纏めて記載するため、本章での記載を省略</span>

## MSTG-CODE-8
アンマネージドコードでは、メモリはセキュアに割り当て、解放、使用されている。

### ネイティブコードでのメモリ破損バグ

メモリ破損バグは、ハッカーに人気のある主要なものである。この種のバグは、プログラムが意図しないメモリ位置にアクセスするようなプログラミングエラーに起因する。適切な条件下で、攻撃者はこの挙動を利用して、脆弱なプログラムの実行フローを乗っ取り、任意のコードを実行することができる。この種の脆弱性は、様々な方法で発生する。<br>

メモリ破損を悪用する主な目的は、通常、攻撃者がシェルコードと呼ばれる組み立てられたマシン命令を配置した場所にプログラムフローをリダイレクトすることである。この機能を回避するために、攻撃者は ROP (return-oriented programming) を利用する。このプロセスでは、テキストセグメント内の小さな既存のコードチャンク (ガジェット) を連結し、これらのガジェットが攻撃者にとって有用な機能を実行したり、 mprotect を呼び出して攻撃者がシェルコードを格納した場所のメモリ保護設定を変更したりする。<br>

Android アプリは、ほとんどの場合、 Java で実装されており、設計上、メモリ破損の問題から本質的に安全である。しかし、 JNI ライブラリを利用したネイティブアプリは、この種のバグの影響を受けやすくなっている。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### バッファオーバーフロー

特定の操作に対して、割り当てられたメモリの範囲を超えて書き込みを行うプログラミングエラーを指す。攻撃者は、この欠陥を利用して、関数ポインタなど、隣接するメモリにある重要な制御データを上書きすることができる。バッファオーバーフローは、以前はメモリ破壊の最も一般的なタイプの欠陥でしたが、さまざまな要因により、ここ数年はあまり見かけなくなった。特に、安全でない C ライブラリ関数を使用することのリスクについて開発者の間で認識されるようになり、さらに、バッファオーバーフローのバグを捕まえることが比較的簡単になったことが、一般的なベストプラクティスとなっている。しかし、このような不具合がないかどうかをテストする価値はまだある。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### Out-of-bounds-access

ポインタの演算にバグがあると、ポインタやインデックスが、意図したメモリ構造 (バッファやリストなど) の境界を超えた位置を参照することがある。アプリが境界外のアドレスに書き込もうとすると、クラッシュや意図しない動作が発生する。攻撃者が対象のオフセットを制御し、書き込まれた内容をある程度操作できれば、[コード実行の悪用が可能である可能性が高い](https://www.zerodayinitiative.com/advisories/ZDI-17-110/)。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### ダングリングポインタ

これは、あるメモリ位置への参照を持つオブジェクトが削除または解放されたにもかかわらず、オブジェクトポインタがリセットされない場合に発生する。プログラムが後でダングリングポインタを使用して、既に割り当て解除されたオブジェクトの仮想関数を呼び出すと、元の vtable ポインタを上書きして実行を乗っ取ることが可能である。また、ダングリングポインタから参照されるオブジェクト変数や他のメモリ構造の読み書きが可能である。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### Use-after-free

これは、解放された (割り当て解除された) メモリを参照するダングリングポインタの特殊なケースを指す。メモリアドレスがクリアされると、その場所を参照していたポインタはすべて無効となり、メモリマネージャはそのアドレスを使用可能なメモリのプールに戻すことになる。このメモリアドレスが再割り当てされると、元のポインタにアクセスすると、新しく割り当てられたメモリに含まれるデータが読み取られたり書き込まれたりする。これは通常、データの破損や未定義の動作につながるが、巧妙な攻撃者は、命令ポインタの制御を活用するために適切なメモリ位置を設定することができる。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### 整数オーバーフロー

演算結果がプログラマが定義した整数型の最大値を超える場合、整数型の最大値に値が「回り込む」ことになり、必然的に小さな値が格納されることになる。逆に、演算結果が整数型の最小値より小さい場合、結果が予想より大きくなる整数型アンダーフローが発生する。特定の整数オーバーフロー/アンダーフローのバグが悪用可能かどうかは、整数の使われ方によって異なる。例えば、整数型がバッファの長さを表す場合、バッファオーバーフローの脆弱性が発生する可能性がある。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

#### フォーマット文字列の脆弱性

C 言語の printf 関数の format string パラメータに未チェックのユーザ入力が渡されると、攻撃者は '%c' や '%n' などのフォーマットトークンを注入してメモリにアクセスする可能性がある。フォーマット文字列のバグは、その柔軟性から悪用するのに便利である。文字列の書式設定結果を出力してしまうと、ASLRなどの保護機能を回避して、任意のタイミングでメモリの読み書きができるようになる。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs-mstg-code-8)

### バッファと整数のオーバーフロー

以下のコードは、バッファオーバーフローの脆弱性が発生する条件の簡単な例を示す。<br>
```c
 void copyData(char *userId) {  
    char  smallBuffer[10]; // size of 10  
    strcpy(smallBuffer, userId);
 } 
```

バッファオーバーフローの可能性を特定するには、安全でない文字列関数 (strcpy 、 strcat 、その他「 str 」接頭辞で始まる関数など) の使用や、ユーザ入力を限られたサイズのバッファにコピーするなどの潜在的に脆弱なプログラミング構造を確認する。安全でない文字列関数のレッドフラグと考えられるのは、以下のようなものである。<br>
* strcat
* strcpy
* strncat
* strlcat
* strncpy
* strlcpy
* sprintf
* snprintf
* gets

また、「 for 」または「 while 」ループとして実装されたコピー操作のインスタンスを探し、長さチェックが正しく実行されていることを確認する。<br>

以下のベストプラクティスが守られていることを確認する。<br>
* 配列のインデックス付けやバッファ長の計算など、セキュリティ上重要な操作に整数変数を使用する場合は、符号なし整数型が使用されていることを確認し、整数の折り返しの可能性を防ぐために前提条件テストを実行する。
* アプリは、 strcpy 、その他「 str 」という接頭辞で始まるほとんどの関数、 sprint 、 vsprintf 、 gets などの安全でない文字列関数を使用していないこと。
* アプリに C++ コードが含まれる場合、 ANSI C++ 文字列クラスを使用する。
* memcpy の場合、ターゲットバッファが少なくともソースと同じサイズであること、両バッファが重複していないことを確認すること。
* 信頼できないデータがフォーマット文字列に連結されることはない。

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8) Buffer and Integer Overflows](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#buffer-and-integer-overflows)

ルールブック
* [バッファオーバーフローを引き起こす安全でない文字列関数を使用しない（必須）](#バッファオーバーフローを引き起こす安全でない文字列関数を使用しない必須)
* [バッファオーバーフローのベストプラクティス（必須）](#バッファオーバーフローのベストプラクティス必須)

#### 静的解析

低レベルコードの静的コード解析は、それだけで1冊の本が完成するほど複雑なトピックである。 [RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads) のような自動化されたツールと、限られた手動での検査作業を組み合わせれば、通常、低い位置にある果実を特定するのに十分である。しかし、メモリ破損は複雑な原因によって引き起こされることがよくある。例えば、 use-after-free バグは、すぐには明らかにならない複雑で直感に反するレースコンディションの結果である可能性がある。一般に、見落とされているコードの欠陥の深い部分に起因するバグは、動的解析またはプログラムを深く理解するために時間を投資するテスターによって発見される。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#static-analysis-1)

#### 動的解析

メモリ破壊のバグは、入力ファジングによって発見するのが最適である。自動化されたブラックボックスソフトウェアテストの手法で、不正なデータをアプリケーションに継続的に送信し、脆弱性の可能性がないか調査する。このプロセスでは、アプリケーションの誤動作やクラッシュがないかどうかが監視される。クラッシュが発生した場合、 (少なくともセキュリティテスト実施者にとっては) クラッシュを発生させた条件から、攻略可能なセキュリティ上の不具合が明らかになることが期待される。<br>

ファズテストの技術やスクリプト (しばしば「ファザー」と呼ばれる) は、通常、半正確な方法で、構造化された入力の複数のインスタンスを生成する。基本的に、生成された値や引数は、少なくとも部分的にはターゲットアプリケーションに受け入れられるが、無効な要素も含まれており、潜在的に入力処理の欠陥や予期しないプログラムの動作を誘発する可能性がある。優れたファザーは、可能性のあるプログラム実行パスの相当量を公開する (すなわち、高いカバレッジの出力) 。入力は、ゼロから生成する方法 (生成ベース) と、既知の有効な入力データを変異させて生成する方法 (変異ベース) の 2 種類がある。<br>

ファジングの詳細については、 [OWASP Fuzzing Guide](https://owasp.org/www-community/Fuzzing) を参照する。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#dynamic-analysis-1)

### Java/Kotlin コードでのメモリ破損バグ

Android アプリケーションは、多くの場合、メモリ破損の問題のほとんどが取り除かれた VM 上で実行される。しかし、メモリ破損のバグが存在しないわけではない。例えば、 [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522) は、 Parcels を使用したシリアライゼーションの問題に関連している。次に、ネイティブコードでは、一般的なメモリ破壊のセクションで説明したような問題がまだ見られる。最後に、 [BlackHat](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf) で示された Stagefright 攻撃のように、サポートするサービスにおけるメモリバグが見られる。<br>

メモリリークもしばしば問題になる。例えば、 Context オブジェクトへの参照を Activity 以外のクラスに回した場合や、 Activity クラスへの参照をヘルパークラスに回した場合などに起こる。<br>

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#memory-corruption-bugs-mstg-code-8)

#### 静的解析

探すべき項目はいろいろある。<br>
* ネイティブコード部分があるか。もしあるなら、一般的なメモリ破壊のセクションで指定された問題をチェックする。ネイティブコードは、 JNI ラッパー、 .CPP / .H / .C ファイル、 NDK または他のネイティブフレームワークを使用すると簡単に見つけることができる。
* Java コードや Kotlin コードはあるか。 [A brief history of Android deserialization vulnerabilities](https://securitylab.github.com/research/android-deserialization-vulnerabilities) で説明されているような、シリアライズ/デシリアライズの問題を探す。

Java / Kotlin のコードにもメモリリークがある可能性があることに注意する。次のような様々な項目がないか探す。 
BroadcastReceiver の未登録、 Activity や View クラスの静的参照、 Context への参照を持つ Singleton クラス、 Inner クラスの参照、匿名クラスの参照、 AsyncTask の参照、 Handler の参照、 Threading の誤り、 TimerTask の参照などである。
詳しくは、以下を確認する。<br>

* [Android でメモリリークを回避する 9 つの方法](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e)
* [Android のメモリリークパターン](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570)

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-6)

ルールブック
* [シリアライズ/デシリアライズの問題（推奨）](#シリアライズデシリアライズの問題推奨)
* [メモリリークがある可能性がある項目を探す（推奨）](#メモリリークがある可能性がある項目を探す推奨)

#### 動的解析

実行する様々な手順がある。<br>
* ネイティブコードの場合 ： Valgrind または Mempatrol を使用して、コードによるメモリ使用量とメモリ呼び出しを分析する。
* Java / Kotlin コードの場合 ： アプリを再コンパイルし、 [Squares leak canary](https://github.com/square/leakcanary) で使用する。
* [Android Studio の Memory Profiler](https://developer.android.com/studio/profile/memory-profiler) でリークを確認する。
* シリアライズの脆弱性がないか、 [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda) で確認する。

参考資料
* [owasp-mastg Memory Corruption Bugs (MSTG-CODE-8) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#dynamic-analysis-6)

### ルールブック
1. [バッファオーバーフローを引き起こす安全でない文字列関数を使用しない（必須）](#バッファオーバーフローを引き起こす安全でない文字列関数を使用しない必須)
1. [バッファオーバーフローのベストプラクティス（必須）](#バッファオーバーフローのベストプラクティス必須)
1. [シリアライズ/デシリアライズの問題（推奨）](#シリアライズデシリアライズの問題推奨)
1. [メモリリークがある可能性がある項目を探す（推奨）](#メモリリークがある可能性がある項目を探す推奨)

#### バッファオーバーフローを引き起こす安全でない文字列関数を使用しない（必須）
バッファオーバーフローを引き起こす安全でない文字列関数として以下の関数が存在し、これらの未然に使用を控える必要がある。

* strcat
* strcpy
* strncat
* strlcat
* strncpy
* strlcpy
* sprintf
* snprintf
* gets

※非推奨なルールのため、サンプルコードなし。

これに違反する場合、以下の可能性がある。
* バッファオーバーフローを引き起こす可能性がある。

#### バッファオーバーフローのベストプラクティス（必須）

バッファオーバーフローを引き起こさなために以下のことを確認する。

* 配列のインデックス付けやバッファ長の計算など、セキュリティ上重要な操作に整数変数を使用する場合は、符号なし整数型が使用されていることを確認し、整数の折り返しの可能性を防ぐために前提条件テストを実行する。
* アプリは、 strcpy 、その他「 str 」という接頭辞で始まるほとんどの関数、 sprint 、 vsprintf 、 gets などの安全でない文字列関数を使用していないこと。
* アプリに C++ コードが含まれる場合、 ANSI C++ 文字列クラスを使用する。
* memcpy の場合、ターゲットバッファが少なくともソースと同じサイズであること、両バッファが重複していないことを確認すること。
* 信頼できないデータがフォーマット文字列に連結されることはない。

これに違反する場合、以下の可能性がある。
* バッファオーバーフローを引き起こす可能性がある。

#### シリアライズ/デシリアライズの問題（推奨）
[A brief history of Android deserialization vulnerabilities](https://securitylab.github.com/research/android-deserialization-vulnerabilities) で説明されているような。問題がある。
Android のデシリアライゼーションに関する多数の脆弱性を確認し、Android の IPC メカニズムの欠陥がどのようにして 4 つの異なる悪用可能な脆弱性につながるかを示した。

* CVE-2014-7911: Privilege Escalation using ObjectInputStream
* Finding C++ proxy classes with CodeQL
* CVE-2015-3825: One class to rule them all
* CVE-2017-411 and CVE-2017-412: Ashmem race conditions in MemoryIntArray

これに注意しない場合、以下の可能性がある。
* デシリアライズの脆弱性による攻撃。

#### メモリリークがある可能性がある項目を探す（推奨）

* BroadcastReceiver の未登録
* Activity や View クラスの静的参照
* Context への参照を持つ Singleton クラス
* Inner クラスの参照
* 匿名クラスの参照
* AsyncTask の参照
* Handler の参照
* Threading の誤り
* TimerTask の参照

詳しくは、以下を確認する。<br>

* [Android でメモリリークを回避する 9 つの方法](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e)
* [Android のメモリリークパターン](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570)

これに注意しない場合、以下の可能性がある。
* メモリーリークを引き起こす可能性がある。

## MSTG-CODE-9
バイトコードの軽量化、スタック保護、PIEサポート、自動参照カウントなどツールチェーンにより提供されるフリーのセキュリティ機能が有効化されている。

### バイナリ保護機能の利用

[バイナリ保護機能](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#binary-protection-mechanisms)の存在を検出するために使用されるテストは、アプリケーションの開発に使用される言語に大きく依存する。<br>

一般に、すべてのバイナリをテストする必要があり、これには、メインのアプリ実行ファイルとすべてのライブラリ/依存ファイルが含まれる。しかし、 Android では、次に述べるようにメインの実行ファイルは安全であると考えられているため、ネイティブライブラリに焦点を当てる。<br>

Android は、アプリの DEX ファイル (classes.dex など) から Dalvik バイトコードを最適化し、ネイティブ コードを含む新しいファイルを生成する (通常、拡張子は .odex または .oat) 。この [Android コンパイル済みバイナリ](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#compiled-app-binary)は、 Linux と Android がアセンブリコードのパッケージに使用する [ELF 形式](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)を使用してラップされる。<br>

アプリの [NDK ネイティブライブラリ](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#native-libraries)も [ELF 形式を使用している](https://developer.android.com/ndk/guides/abis)。<br>
* [PIE ( Position Independent Executable )](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#position-independent-code)
  * Android 7.0 (API level 24) 以降、メインの実行ファイルに対して PIC コンパイルが[デフォルトで有効](https://source.android.com/devices/tech/dalvik/configure)になっている。
  * Android 5.0 (API level 21) で、 PIE を有効にしないネイティブライブラリのサポートが[停止され](https://source.android.com/security/enhancements/enhancements50)、それ以降は[リンカーによって](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430) PIE が強制的に実行される。
* [メモリ管理](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#memory-management)
  * ガベージコレクションはメインバイナリに対して実行されるだけで、バイナリ自体には何もチェックすることはない。
  * ガベージコレクションは Android のネイティブライブラリには適用されない。開発者は、適切な[手動メモリ管理](#mstg-code-9-manual-memory-management)を行う責任がある。「[ネイティブコードでのメモリ破損バグ](#ネイティブコードでのメモリ破損バグ)」を参照する。
* [スタックスマッシングプロテクション](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#stack-smashing-protection)
  * Android アプリは、メモリ安全とされる Dalvik バイトコードにコンパイルされる (少なくともバッファオーバーフローを軽減するために) 。 Flutter などの他のフレームワークは、その言語 (この場合は Dart) がバッファオーバーフローを軽減する方法のため、スタックカナリアを使用してコンパイルされない。
  * Android ネイティブライブラリでは有効になっているはずであるが、完全に判断するのは難しい。
    * NDK ライブラリは、コンパイラがデフォルトでそれを行うので、有効になっているはずである。
    * その他のカスタム C/C++ ライブラリでは有効になっていないかもしれない。

より詳細に知る :
* [Android executable formats](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
* [Android runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works)
* [Android NDK](https://developer.android.com/ndk/guides)
* [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)

参考資料
* [owasp-mastg Make Sure That Free Security Features Are Activated (MSTG-CODE-9) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#overview-6)

#### PIC (Position Independent Code)

[PIC (Position Independent Code)](https://en.wikipedia.org/wiki/Position-independent_code) とは、主記憶装置のどこかに配置されると、その絶対アドレスに関係なく正しく実行されるコードのことである。 PIC は共有ライブラリによく使われ、同じライブラリコードを各プログラムのアドレス空間の中で、他の使用中のメモリ (例えば他の共有ライブラリ) と重ならない位置にロードできるようにする。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Position Independent Code](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#position-independent-code)

#### PIE (Position Independent Executable)

PIE (Position Independent Executable) は、すべてPICで作られた実行バイナリである。 PIE バイナリは、実行ファイルのベースやスタック、ヒープ、ライブラリの位置など、プロセスの重要なデータ領域のアドレス空間の位置をランダムに配置する [ASLR (アドレス空間レイアウトランダム化)](https://en.wikipedia.org/wiki/Address_space_layout_randomization) を有効にするために使用される。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Position Independent Code](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#position-independent-code)

#### メモリ管理

**自動参照カウント**

[ARC (Automatic Reference Counting)](https://en.wikipedia.org/wiki/Automatic_Reference_Counting) は、 [Objective-C](https://developer.apple.com/library/content/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html) と [Swift](https://docs.swift.org/swift-book/LanguageGuide/AutomaticReferenceCounting.html) 専用の Clang コンパイラのメモリ管理機能である。 ARC は、クラスのインスタンスが不要になったときに、そのインスタンスが使用しているメモリを自動的に解放する。 ARC は、実行時に非同期にオブジェクトを解放するバックグラウンドプロセスがない点で、トレースガベージコレクションとは異なる。<br>

トレースガベージコレクションとは異なり、 ARC は参照サイクルを自動的に処理しない。つまり、あるオブジェクトへの「強い」参照がある限り、そのオブジェクトは解放されないということである。強い相互参照は、それに応じてデッドロックやメモリリークを発生させる可能性がある。弱い参照を使ってサイクルを断ち切るかどうかは、開発者次第である。ガベージコレクションとの違いについては、[こちら](https://fragmentedpodcast.com/episodes/064/)で詳しく解説している。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Automatic Reference Counting](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#automatic-reference-counting)

**ガベージコレクション**

[ガベージコレクション (GC)](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)) は、 Java/Kotlin/Dart など一部の言語が持つ自動的なメモリ管理機能である。ガベージコレクタは、プログラムによって割り当てられたが、もはや参照されていないメモリ (ガベージとも呼ばれる) を回収しようとする。 Android ランタイム (ART) は、 [GC の改良版](https://source.android.com/devices/tech/dalvik#Improved_GC)を使用している。 ARC との違いについては、[こちら](https://fragmentedpodcast.com/episodes/064/)で詳しく説明している。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Garbage Collection](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#garbage-collection)

<a id="mstg-code-9-manual-memory-management"></a>
**手動メモリ管理**

ARC や GC が適用されない C/C++ で書かれたネイティブライブラリでは、通常、[手動でのメモリ管理](https://en.wikipedia.org/wiki/Manual_memory_management)が必要である。開発者は、適切なメモリ管理を行う責任がある。手動メモリ管理は、不適切に使用された場合、プログラムにいくつかの主要なクラスのバグ、特に[メモリ安全性の侵害](https://en.wikipedia.org/wiki/Memory_safety)や[メモリリーク](https://en.wikipedia.org/wiki/Memory_leak)を引き起こすことが知られている。

より詳細な情報は、「[ネイティブコードでのメモリ破損バグ](#ネイティブコードでのメモリ破損バグ)」に記載されている。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Manual Memory Management](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#manual-memory-management)

#### スタック破壊保護

[スタックカナリア](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)は、リターンポインタの直前のスタックに隠された整数値を保存することで、スタックバッファオーバーフロー攻撃を防ぐのに役立つ。この値は、関数の return 文が実行される前に検証される。バッファオーバーフロー攻撃は、しばしばリターンポインタを上書きし、プログラムフローを乗っ取るために、メモリ領域を上書きする。スタックカナリアが有効な場合、それらも上書きされ、 CPU はメモリが改ざんされたことを知ることになる。<br>

スタックバッファオーバーフローは、[バッファオーバーフロー](https://en.wikipedia.org/wiki/Buffer_overflow) (またはバッファオーバーラン) と呼ばれる、より一般的なプログラミングの脆弱性の一種である。スタックには、すべてのアクティブな関数呼び出しの戻りアドレスが含まれているため、スタック上のバッファのオーバーフローは、ヒープ上のバッファのオーバーフローよりも、プログラムの実行を狂わせる可能性が高くなる。<br>

参考資料
* [owasp-mastg Binary Protection Mechanisms Stack Smashing Protection](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#stack-smashing-protection)

### 静的解析

アプリのネイティブライブラリをテストして、 PIE とスタックスマッシングの保護が有効になっているかどうかを判断する。<br>

[radare2 の rabin2](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#radare2) を使ってバイナリ情報を取得することができる。例として、[UnCrackable App for Android Level 4 v1.0 APK](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08b-Reference-Apps.md#uncrackable-app-for-android-level-4) を使用する。<br>

すべてのネイティブライブラリは、 canary と pic の両方が true に設定されている必要がある。<br>

libnative-lib.so の場合が以下である。<br>
```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   true
pic      true
```

しかし、 libtool-checker.so についてはそうではない。<br>
```sh
rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"
canary   false
pic      true
```

この例では、 libtool-checker.so をスタックスマッシングプロテクション付きで再コンパイルする必要がある。<br>

参考資料
* [owasp-mastg Make Sure That Free Security Features Are Activated (MSTG-CODE-9) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#static-analysis-7)

ルールブック
* [PIE とスタックスマッシングの保護が有効になっている（必須）](#pie-とスタックスマッシングの保護が有効になっている必須)

### ルールブック
1. [PIE とスタックスマッシングの保護が有効になっている（必須）](#pie-とスタックスマッシングの保護が有効になっている必須)

#### PIE とスタックスマッシングの保護が有効になっている（必須）


アプリのネイティブライブラリをテストして、 PIE とスタックスマッシングの保護が有効になっているかどうかを判断する。<br>

[radare2 の rabin2](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#radare2) を使ってバイナリ情報を取得することができる。例として、[UnCrackable App for Android Level 4 v1.0 APK](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08b-Reference-Apps.md#uncrackable-app-for-android-level-4) を使用する。<br>

すべてのネイティブライブラリは、 canary と pic の両方が true に設定されている必要がある。<br>

libnative-lib.so の場合が以下である。<br>
```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   true
pic      true
```

しかし、 libtool-checker.so についてはそうではない。<br>
```sh
rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"
canary   false
pic      true
```

この例では、 libtool-checker.so をスタックスマッシングプロテクション付きで再コンパイルする必要がある。

これに違反する場合、以下の可能性がある。
* スタックバッファオーバーフローを引き起こす可能性がある。
