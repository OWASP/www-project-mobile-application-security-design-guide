# Network Communication Requirements

## MSTG-NETWORK-1
Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.

### Secure Network Requests

#### Recommended Network APIs

First, you should identify all network requests in the source code and ensure that no plain HTTP URLs are used. Make sure that sensitive information is sent over secure channels by using [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html) or [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html) (for socket-level communication using TLS).

Next, even when using a low-level API which is supposed to make secure connections (such as SSLSocket), be aware that it has to be securely implemented. For instance, SSLSocket doesn't verify the hostname. Use getDefaultHostnameVerifier to verify the hostname. The Android developer documentation includes a [code example](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket).

Reference
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing Network Requests over Secure Protocols](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-network-requests-over-secure-protocols)
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing Network API Usage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-network-api-usage)

Rulebook
* [Ensure that plain-text HTTP URLs are not used (Required)](#ensure-that-plain-text-http-urls-are-not-used-required)
* [Ensure that sensitive information is transmitted over a secure channel (Required)](#ensure-that-sensitive-information-is-transmitted-over-a-secure-channel-required)
* [Secure implementation using low-level API (Required)](#secure-implementation-using-low-level-api-required)

#### Configure plain-text HTTP Traffic

Next, you should ensure that the app is not allowing cleartext HTTP traffic. Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the [default Network Security Configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations)) but there are multiple ways in which an application can still send it:

* Setting the [android:usesCleartextTraffic](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) attribute of the \<application\> tag in the AndroidManifest.xml file. Note that this flag is ignored in case the Network Security Configuration is configured.
* Configuring the Network Security Configuration to enable cleartext traffic by setting the cleartextTrafficPermitted attribute to true on \<domain-config\> elements.
* Using low-level APIs (e.g. [Socket](https://developer.android.com/reference/java/net/Socket)) to set up a custom HTTP connection.
* Using a cross-platform framework (e.g. Flutter, Xamarin, ...), as these typically have their own implementations for HTTP libraries.

All of the above cases must be carefully analyzed as a whole. For example, even if the app does not permit cleartext traffic in its Android Manifest or Network Security Configuration, it might actually still be sending HTTP traffic. That could be the case if it's using a low-level API (for which Network Security Configuration is ignored) or a badly configured cross-platform framework.

For more information refer to the article ["Security with HTTPS and SSL"](https://developer.android.com/training/articles/security-ssl.html).

Reference
* [owasp-mastg Testing Data Encryption on the Network (MSTG-NETWORK-1) Testing for Cleartext Traffic](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#testing-for-cleartext-traffic)

Rulebook
* [Ensure that the app does not allow plain-text HTTP traffic (Required)](#ensure-that-the-app-does-not-allow-plain-text-http-traffic-required)


### Rulebook
1. [Ensure that plain-text HTTP URLs are not used (Required)](#ensure-that-plain-text-http-urls-are-not-used-required)
1. [Ensure that sensitive information is transmitted over a secure channel (Required)](#ensure-that-sensitive-information-is-transmitted-over-a-secure-channel-required)
1. [Secure implementation using low-level API (Required)](#secure-implementation-using-low-level-api-required)
1. [Ensure that the app does not allow plain-text HTTP traffic (Required)](#ensure-that-the-app-does-not-allow-plain-text-http-traffic-required)

#### Ensure that plain-text HTTP URLs are not used (Required)

It is necessary to identify all network requests in the source code and ensure that no plain-text HTTP URLs are used.

If this is violated, the following may occur.
* Leakage of plain-text information to third parties.

#### Ensure that sensitive information is transmitted over a secure channel (Required)
If confidential information is sent through a dangerous channel (HTTP), it may be leaked to a third party because it is sent in plain text. Therefore, when sending confidential information, it must be sent over a secure channel (HTTPS, SSL, etc.).

The following is a sample code for transmission over a secure channel.

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

If this is violated, the following may occur.
* Confidential information is leaked to a third party.

#### Secure implementation using low-level API (Required)

Even when using low-level APIs, secure implementations are required.
SSLSocket does not validate hostnames. To verify the host name, use getDefaultHostnameVerifier.

The following is an example of sample code for host name verification when using SSLSocket.
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

If this is violated, the following may occur.
* The host to which you are communicating may not be trusted or guaranteed.

#### Ensure that the app does not allow plain-text HTTP traffic (Required)

Ensure that the app does not allow plaintext HTTP traffic.
Since Android 9 ( API level 28 ), plain-text HTTP traffic is blocked by default, but there are multiple ways for apps to send plain text.

The following is an example of how an app can send plain text.
* In the AndroidManifest.xml file, the \<application\> tag Set the [android:usesCleartextTraffic](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) attribute in the AndroidManifest.xml file. Note that this flag is ignored if Network Security Configuration is set.
   ```xml
   <application
               android:usesCleartextTraffic="true">
   </application>
   ```

* Set Network Security Configuration to enable CleartextTraffic by setting the cleartextTrafficPermitted attribute to true in the \<domain-config> element.
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <network-security-config>
       <base-config cleartextTrafficPermitted="false" />
       <domain-config cleartextTrafficPermitted="true">
           <domain includeSubdomains="true">secure.example.com</domain>
       </domain-config>
   </network-security-config>
   ```

* Set up a custom HTTP connection using a low-level API (e.g., [Socket](https://developer.android.com/reference/java/net/Socket)).
   ```kotlin
   val address = InetSocketAddress(ip, port)
   val socket = Socket()
   try {
       socket.connect(address)
   } catch (e: Exception) {
   }
   ```

* Use a cross-platform framework (Flutter, Xamarin, etc.). These usually have their own implementations of HTTP libraries.

If this is violated, the following may occur.
* Send plaintext over HTTP traffic.

## MSTG-NETWORK-2
The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards.

### Recommended TLS Settings

Ensuring proper TLS configuration on the server side is also important. The SSL protocol is deprecated and should no longer be used. Also TLS v1.0 and TLS v1.1 have [known vulnerabilities](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols) and their usage is deprecated in all major browsers by 2020. TLS v1.2 and TLS v1.3 are considered best practice for secure transmission of data. Starting with Android 10 (API level 29) TLS v1.3 will be enabled by default for faster and secure communication. The [major change with TLS v1.3](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3) is that customizing cipher suites is no longer possible and that all of them are enabled when TLS v1.3 is enabled, whereas Zero Round Trip (0-RTT) mode isn't supported.

When both the client and server are controlled by the same organization and used only for communicating with one another, you can increase security by [hardening the configuration](https://dev.ssllabs.com/projects/best-practices/).

If a mobile application connects to a specific server, its networking stack can be tuned to ensure the highest possible security level for the server's configuration. Lack of support in the underlying operating system may force the mobile application to use a weaker configuration.

Reference
* [owasp-mastg Verifying the TLS Settings (MSTG-NETWORK-2) Recommended TLS Settings](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04f-Testing-Network-Communication.md#recommended-tls-settings)

Rulebook
* [Secure communication protocol (Required)](#secure-communication-protocol-required)

### Recommended Cipher Suites

Cipher suites have the following structure:
```txt
Protocol_KeyExchangeAlgorithm_WITH_BlockCipher_IntegrityCheckAlgorithm
```

This structure includes:
* A Protocol used by the cipher
* A Key Exchange Algorithm used by the server and the client to authenticate during the TLS handshake
* A Block Cipher used to encrypt the message stream
* A Integrity Check Algorithm used to authenticate messages

Example: TLS_RSA_WITH_3DES_EDE_CBC_SHA

In the example above the cipher suites uses:
* TLS as protocol
* RSA Asymmetric encryption for Authentication
* 3DES for Symmetric encryption with EDE_CBC mode
* SHA Hash algorithm for integrity

Note that in TLSv1.3 the Key Exchange Algorithm is not part of the cipher suite, instead it is determined during the TLS handshake.

In the following listing, we’ll present the different algorithms of each part of the cipher suite.

Protocols:
* SSLv1
* SSLv2 - [RFC 6176](https://www.rfc-editor.org/rfc/rfc6176)
* SSLv3 - [RFC 6101](https://www.rfc-editor.org/rfc/rfc6101)
* TLSv1.0 - [RFC 2246](https://www.ietf.org/rfc/rfc2246)
* TLSv1.1 - [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346)
* TLSv1.2 - [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)
* TLSv1.3 - [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)

Key Exchange Algorithms:
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

Block Ciphers:
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

Integrity Check Algorithms:
* MD5 - [RFC 6151](https://www.rfc-editor.org/rfc/rfc6151)
* SHA - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)
* SHA256 - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)
* SHA384 - [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)

Note that the efficiency of a cipher suite depends on the efficiency of its algorithms.

The following resources contain the latest recommended cipher suites to use with TLS:
* IANA recommended cipher suites can be found in [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4).
* OWASP recommended cipher suites can be found in the [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md).

Some Android versions do not support some of the recommended cipher suites, so for compatibility purposes you can check the supported cipher suites for [Android](https://developer.android.com/reference/javax/net/ssl/SSLSocket#cipher-suites) versions and choose the top supported cipher suites.

If you want to verify whether your server supports the right cipher suites, there are various tools you can use:
* [testssl.sh](https://github.com/drwetter/testssl.sh) which "is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws".

Finally, verify that the server or termination proxy at which the HTTPS connection terminates is configured according to best practices. See also the [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md) and the [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/).

Reference
* [owasp-mastg Verifying the TLS Settings (MSTG-NETWORK-2) Cipher Suites Terminology](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04f-Testing-Network-Communication.md#cipher-suites-terminology)

Rulebook
* [Recommended cipher suites for TLS (Recommended)](#recommended-cipher-suites-for-tls-recommended)

### Rulebook
1. [Secure communication protocol (Required)](#secure-communication-protocol-required)
1. [Recommended cipher suites for TLS (Recommended)](#recommended-cipher-suites-for-tls-recommended)

#### Secure communication protocol (Required)
Ensuring proper TLS configuration on the server side is also important. The SSL protocol is deprecated and should no longer be used.

Deprecated Protocols
* SSL
* TLS v1.0
* TLS v1.1

TLS v1.0 and TLS v1.1 have been deprecated in all major browsers by 2020.

Recommended Protocols
* TLS v1.2
* TLS v1.3

Starting with Android 10 (API level 29), TLS v1.3 is enabled by default for faster and more secure communication.
While enabling TLS v1.3 enables all cipher suites, 0-RTT (Zero Round Trip) mode is not supported.

If this is violated, the following may occur.
* Vulnerable to security exploits.

#### Recommended cipher suites for TLS (Recommended)

The following is an example of a recommended cipher suite. (Cipher suites recommended by [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) that are not deprecated by [Android](https://developer.android.com/reference/javax/net/ssl/SSLEngine) that are not deprecated).
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

If this is not noted, the following may occur.
* Potential use of weak cipher suites.


## MSTG-NETWORK-3
The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted.

### Configuring Trusted Certificates

#### Default settings per target SDK version

Applications targeting Android 7.0 (API level 24) or higher will use a default Network Security Configuration that doesn't trust any user supplied CAs, reducing the possibility of MITM attacks by luring users to install malicious CAs.

[Decode the app using apktool](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#exploring-the-app-package) and verify that the targetSdkVersion in apktool.yml is equal to or higher than 24.
```txt
grep targetSdkVersion UnCrackable-Level3/apktool.yml
  targetSdkVersion: '28'
```

However, even if targetSdkVersion >=24, the developer can disable default protections by using a custom Network Security Configuration defining a custom trust anchor forcing the app to trust user supplied CAs. See ["Analyzing Custom Trust Anchors"](#analyzing-custom-trust-anchors).

Reference
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Verifying the Target SDK Version](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#verifying-the-target-sdk-version)

Rulebook
* [MITM attack potential depending on target SDK version (Required)](#mitm-attack-potential-depending-on-target-sdk-version-required)
* [Custom trust anchor analysis (Required)](#custom-trust-anchor-analysis-required)

#### Analyzing Custom Trust Anchors

Search for the [Network Security Configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#android-network-security-configuration) file and inspect any custom \<trust-anchors\> defining \<certificates src="user"\> (which should be avoided).

You should carefully analyze the [precedence of entries](https://developer.android.com/training/articles/security-config#ConfigInheritance):
* If a value is not set in a \<domain-config\> entry or in a parent \<domain-config\>, the configurations in place will be based on the \<base-config\>
* If not defined in this entry, the [default configurations](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations) will be used.

Take a look at this example of a Network Security Configuration for an app targeting Android 9 (API level 28):
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

Some observations:
* There's no \<base-config\>, meaning that the [default configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations) for Android 9 (API level 28) or higher will be used for all other connections (only system CA will be trusted in principle).
* However, the \<domain-config\> overrides the default configuration allowing the app to trust both system and user CAs for the indicated \<domain\> (owasp.org).
* This doesn't affect subdomains because of includeSubdomains="false".

Putting all together we can translate the above Network Security Configuration to: "the app trusts system and user CAs for the owasp.org domain, excluding its subdomains. For any other domains the app will trust the system CAs only".

Reference
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Analyzing Custom Trust Anchors](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#analyzing-custom-trust-anchors)

Rulebook
* [Custom trust anchor analysis (Required)](#custom-trust-anchor-analysis-required)

### Server Certificate Verification

#### Verification with TrustManager

TrustManager is a means of verifying conditions necessary for establishing a trusted connection in Android. The following conditions should be checked at this point:
* Has the certificate been signed by a trusted CA?
* Has the certificate expired?
* Is the certificate self-signed?

The following code snippet is sometimes used during development and will accept any certificate, overwriting the functions checkClientTrusted, checkServerTrusted, and getAcceptedIssuers. Such implementations should be avoided, and, if they are necessary, they should be clearly separated from production builds to avoid built-in security flaws.
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

Reference
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Verifying the Server Certificate](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate)

Rulebook
* [Verification by TrustManager (Required)](#verification-by-trustmanager-required)

#### WebView Server Certificate Verification

Sometimes applications use a WebView to render the website associated with the application. This is true of HTML/JavaScript-based frameworks such as Apache Cordova, which uses an internal WebView for application interaction. When a WebView is used, the mobile browser performs the server certificate validation. Ignoring any TLS error that occurs when the WebView tries to connect to the remote website is a bad practice.

The following code will ignore TLS issues, exactly like the WebViewClient custom implementation provided to the WebView:
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

Implementation of the Apache Cordova framework's internal WebView usage will ignore [TLS errors](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java) in the method onReceivedSslError if the flag android:debuggable is enabled in the application manifest. Therefore, make sure that the app is not debuggable. See the test case "Testing If the App is Debuggable".

Reference
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis WebView Server Certificate Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification)
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Apache Cordova Certificate Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#apache-cordova-certificate-verification)

Rulebook
* [Bad Practices for Validating Server Certificates in WebView (Required)](#bad-practices-for-validating-server-certificates-in-webview-required)

### Hostname Verification

Another security flaw in client-side TLS implementations is the lack of hostname verification. Development environments usually use internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code disables hostname verification:
```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

With a built-in HostnameVerifier, accepting any hostname is possible:
```java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Make sure that your application verifies a hostname before setting a trusted connection.

Reference
* [owasp-mastg Testing Endpoint Identify Verification (MSTG-NETWORK-3) Static Analysis Hostname Verification](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#hostname-verification)

Rulebook
* [Hostname verification (Required)](#hostname-verification-required)

### Rulebook
1. [MITM attack potential depending on target SDK version (Required)](#mitm-attack-potential-depending-on-target-sdk-version-required)
1. [Custom trust anchor analysis (Required)](#custom-trust-anchor-analysis-required)
1. [Verification by TrustManager (Required)](#verification-by-trustmanager-required)
1. [Bad Practices for Validating Server Certificates in WebView (Required)](#bad-practices-for-validating-server-certificates-in-webview-required)
1. [Hostname verification (Required)](#hostname-verification-required)

#### MITM attack potential depending on target SDK version (Required)

Applications targeting Android 7.0 (API level 24) or higher will use a default Network Security Configuration that doesn't trust any user supplied CAs, reducing the possibility of MITM attacks by luring users to install malicious CAs.

[Decode the app using apktool](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05b-Basic-Security_Testing.md#exploring-the-app-package) and verify that the targetSdkVersion in apktool.yml is equal to or higher than 24.

If this is violated, the following may occur.
* Increased likelihood of MITM attack to install malicious CA.

#### Custom trust anchor analysis (Required)

Even with targetSdkVersion >=24, developers can use a custom network security configuration to disable the default protection and define a custom trust anchor to force the app to trust the CA provided by the user.

The android:networkSecurityConfig setting in AndroidManifest.xml should be checked.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>
```

The Network Security Configuration file set in android:networkSecurityConfig should be checked to verify the status of the following tags.
* \<base-config\>
* \<trust-anchors\>
* \<certificates\>

\* \<certificates src="user"\> setting should be avoided.

Tags not set with a unique configuration inherit the setting at \<base-config\>, and if \<base-config\> is not set, the platform default is set.

You should carefully analyze the [precedence of entries](https://developer.android.com/training/articles/security-config#ConfigInheritance):
* If a value is not set in a \<domain-config\> entry or in a parent \<domain-config\>, the configurations in place will be based on the \<base-config\>
* If not defined in this entry, the [default configurations](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations) will be used.

Take a look at this example of a Network Security Configuration for an app targeting Android 9 (API level 28):
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

Some observations:
* There's no \<base-config\>, meaning that the [default configuration](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md#default-configurations) for Android 9 (API level 28) or higher will be used for all other connections (only system CA will be trusted in principle).
* However, the \<domain-config\> overrides the default configuration allowing the app to trust both system and user CAs for the indicated \<domain\> (owasp.org).
* This doesn't affect subdomains because of includeSubdomains="false".

Putting all together we can translate the above Network Security Configuration to: "the app trusts system and user CAs for the owasp.org domain, excluding its subdomains. For any other domains the app will trust the system CAs only".

If this is violated, the following may occur.
* Increased likelihood of MITM attacks that force the installation of malicious CAs.

#### Verification by TrustManager (Required)

When the functions checkClientTrusted, checkServerTrusted, and getAcceptedIssuers are overridden using TrustManager, If all certificates are accepted without verifying client certificates, as in the sample code below, secure communication cannot be guaranteed. In the case of development, the following sample code is convenient for checking the operation with a self-certified certificate, but the process should be separated to prevent accidental incorporation into the production version.

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

The sample code below is the process of initializing TrustManager and setting HttpsURLConnection in order to trust a set of specific CAs.
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

Reference
* [Security with network protocols Unknown certificate authority](https://developer.android.com/training/articles/security-ssl?hl=en#UnknownCa)

If this is violated, the following may occur.
* If verification with a self-certificate is included, it is not possible to determine if the certificate is trustworthy.

#### Bad Practices for Validating Server Certificates in WebView (Required)

Sometimes applications use a WebView to render the website associated with the application. This is true of HTML/JavaScript-based frameworks such as Apache Cordova, which uses an internal WebView for application interaction. When a WebView is used, the mobile browser performs the server certificate validation. Ignoring any TLS error that occurs when the WebView tries to connect to the remote website is a bad practice.

The sample code below is an example of how to ignore TLS errors and load a website into WebViewClient.
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

Implementation of the Apache Cordova framework's internal WebView usage will ignore [TLS errors](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java) in the method onReceivedSslError if the flag android:debuggable is enabled in the application manifest. Therefore, make sure that the app is not debuggable.

If this is violated, the following may occur.
* Vulnerable to man-in-the-middle attacks.

#### Hostname verification (Required)

During the development phase, the developer may have disabled hostname validation (or allowed arbitrary hostnames in the application).
In some cases, the validation is disabled without making any changes when the production environment goes live.

The following is a case where this is disabled.

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

The following is a list of arbitrary host names that are accepted.

```java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Host name verification should be performed when connecting to the production environment.

If this is violated, the following may occur.
* It is possible to communicate with a host that is not a trusted destination host.