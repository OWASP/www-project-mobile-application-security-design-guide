# Data Storage and Privacy Requirements

## MSTG-STORAGE-1
System credential storage facilities need to be used to store sensitive data, such as PII, user credentials or cryptographic keys.

### Hardware-backed Android KeyStore

As mentioned before, hardware-backed Android KeyStore gives another layer to defense-in-depth security concept for Android. Keymaster Hardware Abstraction Layer (HAL) was introduced with Android 6 (API level 23). Applications can verify if the key is stored inside the security hardware (by checking if KeyInfo.isinsideSecureHardware returns true). Devices running Android 9 (API level 28) and higher can have a StrongBox Keymaster module, an implementation of the Keymaster HAL that resides in a hardware security module which has its own CPU, Secure storage, a true random number generator and a mechanism to resist package tampering. To use this feature, true must be passed to the setIsStrongBoxBacked method in either the KeyGenParameterSpec.Builder class or the KeyProtection.Builder class when generating or importing keys using AndroidKeystore. To make sure that StrongBox is used during runtime, check that isInsideSecureHardware returns true and that the system does not throw StrongBoxUnavailableException which gets thrown if the StrongBox Keymaster isn't available for the given algorithm and key size associated with a key. Description of features on hardware-based keystore can be found on [AOSP pages](https://source.android.com/security/keystore).

Keymaster HAL is an interface to hardware-backed components - Trusted Execution Environment (TEE) or a Secure Element (SE), which is used by Android Keystore. An example of such a hardware-backed component is [Titan M](https://android-developers.googleblog.com/2018/10/building-titan-better-security-through.html).<br>

Reference
* [owasp-mastg Data Storage Methods Overview Hardware-backed Android KeyStore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#hardware-backed-android-keystore)

Rulebook
* [Verify that keys are stored inside security hardware (Recommended)](#verify-that-keys-are-stored-inside-security-hardware-recommended)
* [How to use StrongBox (Recommended)](#how-to-use-strongbox-recommended)

### Key Attestation

For the applications which heavily rely on Android Keystore for business-critical operations such as multi-factor authentication through cryptographic primitives, secure storage of sensitive data at the client-side, etc. Android provides the feature of [Key Attestation](https://developer.android.com/training/articles/security-key-attestation) which helps to analyze the security of cryptographic material managed through Android Keystore. From Android 8.0 (API level 26), the key attestation was made mandatory for all new (Android 7.0 or higher) devices that need to have device certification for Google apps. Such devices use attestation keys signed by the [Google hardware attestation root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate) and the same can be verified through the key attestation process.<br>

During key attestation, we can specify the alias of a key pair and in return, get a certificate chain, which we can use to verify the properties of that key pair. If the root certificate of the chain is the [Google Hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate) and the checks related to key pair storage in hardware are made it gives an assurance that the device supports hardware-level key attestation and the key is in the hardware-backed keystore that Google believes to be secure. Alternatively, if the attestation chain has any other root certificate, then Google does not make any claims about the security of the hardware.<br>

Although the key attestation process can be implemented within the application directly but it is recommended that it should be implemented at the server-side for security reasons. The following are the high-level guidelines for the secure implementation of Key Attestation:<br>
* The server should initiate the key attestation process by creating a random number securely using CSPRNG(Cryptographically Secure Random Number Generator) and the same should be sent to the user as a challenge.
* The client should call the setAttestationChallenge API with the challenge received from the server and should then retrieve the attestation certificate chain using the KeyStore.getCertificateChain method.
* The attestation response should be sent to the server for the verification and following checks should be performed for the verification of the key attestation response:
  * Verify the certificate chain, up to the root and perform certificate sanity checks such as validity, integrity and trustworthiness. Check the [Certificate Revocation Status List](https://developer.android.com/training/articles/security-key-attestation#root_certificat) maintained by Google, if none of the certificates in the chain was revoked.
  * Check if the root certificate is signed with the Google attestation root key which makes the attestation process trustworthy.
  * Extract the attestation [certificate extension data](https://developer.android.com/training/articles/security-key-attestation#certificate_schema), which appears within the first element of the certificate chain and perform the following checks:
    * Verify that the attestation challenge is having the same value which was generated at the server while initiating the attestation process.
    * Verify the signature in the key attestation response.
    * Verify the security level of the Keymaster to determine if the device has secure key storage mechanism. Keymaster is a piece of software that runs in the security context and provides all the secure keystore operations. The security level will be one of Software, TrustedEnvironment or StrongBox. The client supports hardware-level key attestation if security level is TrustedEnvironment or StrongBox and attestation certificate chain contains a root certificate signed with Google attestation root key.
    * Verify client's status to ensure full chain of trust - verified boot key, locked bootloader and verified boot state.
    * Additionally, you can verify the key pair's attributes such as purpose, access time, authentication requirement, etc.

Note, if for any reason that process fails, it means that the key is not in security hardware. That does not mean that the key is compromised.<br>

The typical example of Android Keystore attestation response looks like this:
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
In the above JSON snippet, the keys have the following meaning:
* fmt: Attestation statement format identifier
* authData: It denotes the authenticator data for the attestation
* alg: The algorithm that is used for the Signature
* sig: Signature
* x5c: Attestation certificate chain

Note: The sig is generated by concatenating authData and clientDataHash (challenge sent by the server) and signing through the credential private key using the alg signing algorithm and the same is verified at the server-side by using the public key in the first certificate.<br>

For more understanding on the implementation guidelines, [Google Sample Code](https://github.com/googlesamples/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java) can be referred.<br>

For the security analysis perspective the analysts may perform the following checks for the secure implementation of Key Attestation:<br>

* Check if the key attestation is totally implemented at the client-side. In such scenario, the same can be easily bypassed by tampering the application, method hooking, etc.
* Check if the server uses random challenge while initiating the key attestation. As failing to do that would lead to insecure implementation thus making it vulnerable to replay attacks. Also, checks pertaining to the randomness of the challenge should be performed.
* Check if the server verifies the integrity of key attestation response.
* Check if the server performs basic checks such as integrity verification, trust verification, validity, etc. on the certificates in the chain.

Reference
* [owasp-mastg Data Storage Methods Overview Key Attestation](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#key-attestation)

Rulebook
* [For secure key authentication, provide a certificate in the device by means of a challenge received from the server (Recommended)](#for-secure-key-authentication-provide-a-certificate-in-the-device-by-means-of-a-challenge-received-from-the-server-recommended)
* [Check for secure implementation of key authentication in terms of security analysis (Required)](#check-for-secure-implementation-of-key-authentication-in-terms-of-security-analysis-required)

### Secure Key Import into Keystore

Android 9 (API level 28) adds the ability to import keys securely into the AndroidKeystore. First AndroidKeystore generates a key pair using PURPOSE_WRAP_KEY which should also be protected with an attestation certificate, this pair aims to protect the Keys being imported to AndroidKeystore. The encrypted keys are generated as ASN.1-encoded message in the SecureKeyWrapper format which also contains a description of the ways the imported key is allowed to be used. The keys are then decrypted inside the AndroidKeystore hardware belonging to the specific device that generated the wrapping key so they never appear as plaintext in the device's host memory.<br>

<img src="images/0x03/MSTG-STORAGE-1/Android9_secure_key_import_to_keystore.jpg" width="500px" />

Example in Java:
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

The code above present the different parameters to be set when generating the encrypted keys in the SecureKeyWrapper format. Check the Android documentation on [WrappedKeyEntry](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry) for more details.<br>

When defining the KeyDescription AuthorizationList, the following parameters will affect the encrypted keys security:<br>

* The algorithm parameter Specifies the cryptographic algorithm with which the key is used
* The keySize parameter Specifies the size, in bits, of the key, measuring in the normal way for the key's algorithm
* The digest parameter Specifies the digest algorithms that may be used with the key to perform signing and verification operations

Reference
* [owasp-mastg Data Storage Methods Overview Secure Key Import into Keystore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#secure-key-import-into-keystore)


### Older KeyStore Implementations

Older Android versions don't include KeyStore, but they do include the KeyStore interface from JCA (Java Cryptography Architecture). You can use KeyStores that implement this interface to ensure the secrecy and integrity of keys stored with KeyStore; BouncyCastle KeyStore (BKS) is recommended. All implementations are based on the fact that files are stored on the filesystem; all files are password-protected. To create one, you can use the KeyStore.getInstance("BKS", "BC") method, where "BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" is the provider (BouncyCastle). You can also use SpongyCastle as a wrapper and initialize the KeyStore as follows: KeyStore.getInstance("BKS", "SC").<br>

Be aware that not all KeyStores properly protect the keys stored in the KeyStore files.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Older KeyStore Implementations](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#older-keystore-implementations)

Rulebook
* [On older Android OS, store keys by BouncyCastle KeyStore (Recommended)](#on-older-android-os-store-keys-by-bouncycastle-keystore-recommended)

### Key Chain

The [KeyChain class](https://developer.android.com/reference/android/security/KeyChain.html) is used to store and retrieve system-wide private keys and their corresponding certificates (chain). The user will be prompted to set a lock screen pin or password to protect the credential storage if something is being imported into the KeyChain for the first time. Note that the KeyChain is system-wide, every application can access the materials stored in the KeyChain.<br>

Inspect the source code to determine whether native Android mechanisms identify sensitive information. Sensitive information should be encrypted, not stored in clear text. For sensitive information that must be stored on the device, several API calls are available to protect the data via the KeyChain class. Complete the following steps:<br>

* Make sure that the app is using the Android KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the patterns AndroidKeystore, import java.security.KeyStore, import javax.crypto.Cipher, import java.security.SecureRandom, and corresponding usages.
* Use the store(OutputStream stream, char[] password) function to store the KeyStore to disk with a password. Make sure that the password is provided by the user, not hard-coded.

Reference
* [owasp-mastg Data Storage Methods Overview Keychain](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#keychain)

Rulebook
* [Prompt users to set a lock screen pin or password to protect certificate storage when importing into Keychain for the first time (Required)](#prompt-users-to-set-a-lock-screen-pin-or-password-to-protect-certificate-storage-when-importing-into-keychain-for-the-first-time-required)
* [Determine if native Android mechanisms identify sensitive information (Required)](#determine-if-native-android-mechanisms-identify-sensitive-information-required)

### Storing a Cryptographic Key: Techniques

To mitigate unauthorized use of keys on the Android device, Android KeyStore lets apps specify authorized uses of their keys when generating or importing the keys. Once made, authorizations cannot be changed.<br>

Storing a Key - from most secure to least secure:<br>

* the key is stored in hardware-backed Android KeyStore
* all keys are stored on server and are available after strong authentication
* master key is stored on server and use to encrypt other keys, which are stored in Android SharedPreferences
* the key is derived each time from a strong user provided passphrase with sufficient length and salt
* the key is stored in software implementation of Android KeyStore
* master key is stored in software implementation of Android Keystore and used to encrypt other keys, which are stored in SharedPreferences
* [not recommended] all keys are stored in SharedPreferences
* [not recommended] hardcoded encryption keys in the source code
* [not recommended] predictable obfuscation function or key derivation function based on stable attributes
* [not recommended] stored generated keys in public places (like /sdcard/)

Reference
* [owasp-mastg Data Storage Methods Overview Storing a Cryptographic Key: Techniques](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-a-cryptographic-key-techniques)

Rulebook
* [Encryption key storage method (Required)](#encryption-key-storage-method-required)


#### Storing Keys Using Hardware-backed Android KeyStore

You can use the [hardware-backed Android KeyStore](https://github.com/OWASP/owasp-mastg/blob/1.5.0/Document/0x05d-Testing-Data-Storage.md#hardware-backed-android-keystore) if the device is running Android 7.0 (API level 24) and above with available hardware component (Trusted Execution Environment (TEE) or a Secure Element (SE)). You can even verify that the keys are hardware-backed by using the guidelines provided for [the secure implementation of Key Attestation](https://github.com/OWASP/owasp-mastg/blob/1.5.0/Document/0x05d-Testing-Data-Storage.md#key-attestation). If a hardware component is not available and/or support for Android 6.0 (API level 23) and below is required, then you might want to store your keys on a remote server and make them available after authentication.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Storing Keys Using Hardware-backed Android KeyStore](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-using-hardware-backed-android-keystore)

#### Storing Keys on the Server

It is possible to securely store keys on a key management server, however the app needs to be online to decrypt the data. This might be a limitation for certain mobile app use cases and should be carefully thought through as this becomes part of the architecture of the app and might highly impact usability.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Storing Keys on the Server](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-on-the-server)

#### Deriving Keys from User Input

Deriving a key from a user provided passphrase is a common solution (depending on which Android API level you use), but it also impacts usability, might affect the attack surface and could introduce additional weaknesses.<br>

Each time the application needs to perform a cryptographic operation, the user's passphrase is needed. Either the user is prompted for it every time, which isn't an ideal user experience, or the passphrase is kept in memory as long as the user is authenticated. Keeping the passphrase in memory is not a best-practice as any cryptographic material must only be kept in memory while it is being used. Zeroing out a key is often a very challenging task as explained in ["Cleaning out Key Material"](#cleaning-out-key-material).<br>

Additionally, consider that keys derived from a passphrase have their own weaknesses. For instance, the passwords or passphrases might be reused by the user or easy to guess. Please refer to the [Testing Cryptography chapter](0x04-MASDG-Cryptography_Requirements.md#weak-key-generation-functions) for more information.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Deriving Keys from User Input](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#deriving-keys-from-user-input)

#### Cleaning out Key Material

The key material should be cleared out from memory as soon as it is not need anymore. There are certain limitations of realibly cleaning up secret data in languages with garbage collector (Java) and immutable strings (Kotlin). [Java Cryptography Architecture Reference Guide](https://docs.oracle.com/en/java/javase/16/security/java-cryptography-architecture-jca-reference-guide.html#GUID-C9F76AFB-6B20-45A7-B84F-96756C8A94B4) suggests using char[] instead of String for storing sensitive data, and nullify array after usage.<br>

Note that some ciphers do not properly clean up their byte-arrays. For instance, the AES Cipher in BouncyCastle does not always clean up its latest working key leaving some copies of the byte-array in memory. Next, BigInteger based keys (e.g. private keys) cannot be removed from the heap nor zeroed out without additional effort. Clearing byte array can be achieved by writing a wrapper which implements [Destroyable](https://docs.oracle.com/javase/8/docs/api/javax/security/auth/Destroyable.html#destroy--).<br>

Reference
* [owasp-mastg Data Storage Methods Overview Cleaning out Key Material](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#cleaning-out-key-material)

Rulebook
* [Key material must be erased from memory as soon as it is no longer needed (Required)](#key-material-must-be-erased-from-memory-as-soon-as-it-is-no-longer-needed-required)


#### Storing Keys using Android KeyStore API

More user-friendly and recommended way is to use the [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html) system (itself or through KeyChain) to store key material. If it is possible, hardware-backed storage should be used. Otherwise, it should fallback to software implementation of Android Keystore. However, be aware that the AndroidKeyStore API has been changed significantly throughout various versions of Android. In earlier versions, the AndroidKeyStore API only supported storing public/private key pairs (e.g., RSA). Symmetric key support has only been added since Android 6.0 (API level 23). As a result, a developer needs to handle the different Android API levels to securely store symmetric keys.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Storing Keys using Android KeyStore API](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-using-android-keystore-api)

Rulebook
* [Save key material (Recommended)](#save-key-material-recommended)

#### Storing keys by encrypting them with other keys

In order to securely store symmetric keys on devices running on Android 5.1 (API level 22) or lower, we need to generate a public/private key pairs. We encrypt the symmetric key using the public key and store the private key in the AndroidKeyStore. The encrypted symmetric key can encoded using base64 and stored in the SharedPreferences. Whenever we need the symmetric key, the application retrieves the private key from the AndroidKeyStore and decrypts the symmetric key.<br>

Envelope encryption, or key wrapping, is a similar approach that uses symmetric encryption to encapsulate key material. Data encryption keys (DEKs) can be encrypted with key encryption keys (KEKs) which are securely stored. Encrypted DEKs can be stored in SharedPreferences or written to files. When required, the application reads the KEK, then decrypts the DEK. Refer to [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys) to learn more about encrypting cryptographic keys.<br>

Also, as the illustration of this approach, refer to the [EncryptedSharedPreferences from androidx.security.crypto package](https://developer.android.com/jetpack/androidx/releases/security).<br>

Reference
* [owasp-mastg Data Storage Methods Overview Storing keys by encrypting them with other keys](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#storing-keys-by-encrypting-them-with-other-keys)

Rulebook
* [Generate public/private key pairs for secure storage of symmetric keys under Android OS 5.1 (Required)](#generate-publicprivate-key-pairs-for-secure-storage-of-symmetric-keys-under-android-os-51-required)
* [EncryptedSharedPreferences usage (Recommended)](#encryptedsharedpreferences-usage-recommended)


#### Insecure options to store keys

A less secure way of storing encryption keys, is in the SharedPreferences of Android. When [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html) are used, the file is only readable by the application that created it. However, on rooted devices any other application with root access can simply read the SharedPreference file of other apps. This is not the case for the AndroidKeyStore. Since AndroidKeyStore access is managed on kernel level, which needs considerably more work and skill to bypass without the AndroidKeyStore clearing or destroying the keys.<br>

The last three options are to use hardcoded encryption keys in the source code, having a predictable obfuscation function or key derivation function based on stable attributes, and storing generated keys in public places like /sdcard/. Hardcoded encryption keys are an issue since this means every instance of the application uses the same encryption key. An attacker can reverse-engineer a local copy of the application in order to extract the cryptographic key, and use that key to decrypt any data which was encrypted by the application on any device.<br>

Next, when you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device in order to find the key. Lastly, storing encryption keys publicly also is highly discouraged as other applications can have permission to read the public partition and steal the keys.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Insecure options to store keys](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#insecure-options-to-store-keys)

Rulebook
* [Do not use insecure encryption key storage methods (Required)](#do-not-use-insecure-encryption-key-storage-methods-required)


### Third Party libraries

There are several different open-source libraries that offer encryption capabilities specific for the Android platform.<br>

* [Java AES Crypto](https://github.com/tozny/java-aes-crypto) - A simple Android class for encrypting and decrypting strings.
* [SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/) - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
* [Secure Preferences](https://github.com/scottyab/secure-preferences) - Android Shared preference wrapper than encrypts the keys and values of Shared Preferences.
* [Themis](https://github.com/cossacklabs/themis) - A cross-platform high-level cryptographic library that provides same API across many platforms for securing data during authentication, storage, messaging, etc.

Please keep in mind that as long as the key is not stored in the KeyStore, it is always possible to easily retrieve the key on a rooted device and then decrypt the values you are trying to protect.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Third Party libraries](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-libraries)

Rulebook
* [Encryption with third-party libraries (Deprecated)](#encryption-with-third-party-libraries-deprecated)

### Rulebook
1. [Verify that keys are stored inside security hardware (Recommended)](#verify-that-keys-are-stored-inside-security-hardware-recommended)
1. [How to use StrongBox (Recommended)](#how-to-use-strongbox-recommended)
1. [For secure key authentication, provide a certificate in the device by means of a challenge received from the server (Recommended)](#for-secure-key-authentication-provide-a-certificate-in-the-device-by-means-of-a-challenge-received-from-the-server-recommended)
1. [Check for secure implementation of key authentication in terms of security analysis (Required)](#check-for-secure-implementation-of-key-authentication-in-terms-of-security-analysis-required)
1. [On older Android OS, store keys by BouncyCastle KeyStore (Recommended)](#on-older-android-os-store-keys-by-bouncycastle-keystore-recommended)
1. [Prompt users to set a lock screen pin or password to protect certificate storage when importing into Keychain for the first time (Required)](#prompt-users-to-set-a-lock-screen-pin-or-password-to-protect-certificate-storage-when-importing-into-keychain-for-the-first-time-required)
1. [Determine if native Android mechanisms identify sensitive information (Required)](#determine-if-native-android-mechanisms-identify-sensitive-information-required)
1. [Encryption key storage method (Required)](#encryption-key-storage-method-required)
1. [Key material must be erased from memory as soon as it is no longer needed (Required)](#key-material-must-be-erased-from-memory-as-soon-as-it-is-no-longer-needed-required)
1. [Save key material (Recommended)](#save-key-material-recommended)
1. [Generate public/private key pairs for secure storage of symmetric keys under Android OS 5.1 (Required)](#generate-publicprivate-key-pairs-for-secure-storage-of-symmetric-keys-under-android-os-51-required)
1. [EncryptedSharedPreferences usage (Recommended)](#encryptedsharedpreferences-usage-recommended)
1. [Do not use insecure encryption key storage methods (Required)](#do-not-use-insecure-encryption-key-storage-methods-required)
1. [Encryption with third-party libraries (Deprecated)](#encryption-with-third-party-libraries-deprecated)

#### Verify that keys are stored inside security hardware (Recommended)

It is possible to check if the key is stored inside the security hardware (by checking if KeyInfo.isinsideSecureHardware returns true).

The method to check is as follows.
Since isinsideSecureHardware is deprecated for API level 31 and above
Apps targeting API level 31 or higher should use [getSecurityLevel](https://developer.android.com/reference/android/security/keystore/KeyInfo#getSecurityLevel()).

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

If this is not noted, the following may occur.
* The key could be read/written by the user and misused.

#### How to use StrongBox (Recommended)

Devices running Android 9 (API level 28) or later can include the StrongBox Keymaster module. This is an implementation of the Keymaster HAL that resides in a hardware security module with its own CPU, Secure Storage, true random number generator, and a mechanism to combat package tampering.
To use this feature, the setIsStrongBoxBacked Builder class or KeyProtection.
To ensure that the StrongBox is used at runtime, make sure that isInsideSecureHardware returns true and the system does not throw a StrongBoxUnavailableException. Note that isinsideSecureHardware is abolished in API level 31 and getSecurityLevel is recommended.


```java
      KeyGenParameterSpec builder = new KeyGenParameterSpec.Builder("ALIAS", KeyProperties.PURPOSE_VERIFY)
              .setIsStrongBoxBacked(true)
              .build();
```

If this is not noted, the following may occur.
* The key could be read/written by the user and misused.

#### For secure key authentication, provide a certificate in the device by means of a challenge received from the server (Recommended)
Although key authentication can be implemented only on the client side, it is recommended that it be implemented on the server side for more secure authentication.
In this case, the client needs to call the setAttestationChallenge API with the challenge received from the server, use the KeyStore.getCertificateChain method to obtain a certificate chain, and provide the certificate to the server.
The server performs key authentication using the provided certificate.

The following is a sample code of the above process.
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

If this is not noted, the following may occur.
* The device receiving the challenge may not be able to prove that it is the device in question and may not be able to perform secure key authentication.

#### Check for secure implementation of key authentication in terms of security analysis (Required)

From a security analysis perspective, analysts should perform the following checks for secure implementation of key authentication
* Ensure that key authentication is not fully implemented on the client side. If fully implemented, the same can be easily circumvented by tampering with the application or hooking a method.
* Ensure that the server uses a random challenge when initiating key authentication. Failure to do so results in an insecure implementation and makes it vulnerable to replay attacks. Also, checks should be made regarding the randomness of the challenge.
* Check that the server verifies the integrity of the key authentication response; failure to do so is an insecure implementation and should be addressed.
* Verify that the server performs basic checks on certificates in the chain, including integrity, trustworthiness, and validity; failure to do so constitutes an insecure implementation and should be addressed.

If this is not noted, the following may occur.
* Secure key authentication cannot be guaranteed.

#### On older Android OS, store keys by BouncyCastle KeyStore (Recommended)
Older versions of Android do not include KeyStore, but do include the KeyStore interface of JCA (Java Cryptography Architecture). By using a KeyStore that implements this interface, the confidentiality and integrity of keys stored in the KeyStore can be ensured. 
BouncyCastle KeyStore (BKS) is recommended.

An implementation of KeyStore using BouncyCastle KeyStore (BKS) is described below.
"BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" means provider (BouncyCastle). Using SpongyCastle as a wrapper, it is also possible to initialize a KeyStore as follows.

Note that not all KeyStores adequately protect the keys stored in the KeyStore file.

```java
KeyStore.getInstance("BKS", "SC")
```

If this is not noted, the following may occur.
* The confidentiality and integrity of the keys used may not be ensured.

#### Prompt users to set a lock screen pin or password to protect certificate storage when importing into KeyChain for the first time (Required)

When importing something into KeyChain for the first time, users are prompted to set a lock screen pin or password to protect certificate storage. It should be noted that KeyChain is system-wide and all applications have access to materials stored in KeyChain.

If this is violated, the following may occur.
* Information imported into the Keychain is available at the system level and could be used for unintended purposes if the device is used by a third party.

#### Determine if native Android mechanisms identify sensitive information (Required)

Examine the source code to determine if native Android mechanisms identify sensitive information. Sensitive information should be encrypted and should not be stored in plain text. For sensitive information that must be stored on the device, several API calls are available to protect the data via the KeyChain class. Complete the following steps.

* Verify that the app is storing encrypted information on the device.
* Verify that the app is using the Android KeyStore and Cipher mechanisms to securely store encrypted information on the device.
  
  Look for the following patterns.
  * AndroidKeystore
  * import java.security.KeyStore
  * import javax.crypto.Cipher
  * import java.security.SecureRandom, and corresponding usages

* store(OutputStream stream, char[] password) function to store the KeyStore to disk with a password. Make sure that the password is not hard-coded, but provided by the user. Sample code is shown below.
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

The following sample code shows how to install credentials in the KeyChain class.
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

If this is violated, the following may occur.
* Sensitive information may be stored in plain text and leaked to third parties.

#### Encryption key storage method (Required)

The following are secure and insecure methods of storing encryption keys.

**Recommended**.

The following are the recommended methods of key storage in order of security.
* Store the key in the Android KeyStore stored in hardware.

   The following is a sample code to save a key to Android KeyStore.
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
* All keys are stored on the server and made available after strong authentication. \* See "[Storing Keys on the Server](#storing-keys-on-the-server)" for details and precautions.
* The master key is stored on the server and used to encrypt other keys stored in Android's SharedPreferences. \* See "[Storing Keys on the Server](#storing-keys-on-the-server)" for details and precautions.
* Ensure that the key has sufficient length and Salt is derived each time from a strong passphrase provided by the user. \* See "[Deriving Keys from User Input](#deriving-keys-from-user-input)" for details and precautions.
* Store the key in the software implementation of Android KeyStore. \* See "[Cleaning out Key Material](#cleaning-out-key-material)" and "[Storing Keys using Android KeyStore API](#storing-keys-using-android-keystore-api)" for details and precautions.
* The master key is stored in the software implementation of the Android Keystore and used to encrypt other keys stored in SharedPreferences. \* See "[Cleaning out Key Material](#cleaning-out-key-material)" and "[Storing Keys using Android KeyStore API](#storing-keys-using-android-keystore-api)" for details and precautions.

**Deprecated**<br>
* Save all keys in SharedPreferences.
* Hardcode keys into source code.
* Predictable obfuscation or key derivation functions based on stable attributes.
* Store generated keys in a public location (e.g. /sdcard/).

If this is violated, the following may occur.
* Unauthorized use of keys on Android devices.

#### Key material must be erased from memory as soon as it is no longer needed (Required)

Key material should be erased from memory as soon as it is no longer needed. Languages that use garbage collectors (Java) or immutable strings (Kotlin) have certain limitations in actually cleaning up confidential data. The Java Cryptography Architecture Reference Guide suggests using char[] instead of String to store confidential data and nulling the array after use.


Example in Java:
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

Note that some ciphers do not properly clean up byte arrays. For example, BouncyCastle's AES cipher does not always clean up the latest working key, but leaves some copies of the byte array in memory. Second, BigInteger-based keys (e.g., secret keys) cannot be deleted or zeroed from the heap without additional effort. Clearing the byte array can be accomplished by creating a wrapper that implements Destroyable.


Example in Java:
```java
KeyStore.PasswordProtection ks = new KeyStore.PasswordProtection("password".toCharArray());
ks.destroy();

if(ks.isDestroyed()){
   cleartext = null;
   ciphertext = null;
}
```

If this is violated, the following may occur.
* Key material in memory may be used for other purposes.
* Languages that use garbage collectors (Java) or immutable strings (Kotlin) may not be cleaned up.

#### Save key material (Recommended)

A more user-friendly and recommended method is to use the [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html) system (by itself or via KeyChain ) system (by itself or via KeyChain) to store key material.

The storage method using the KeyStore API is as follows.

Example in Java:
```java
   // save my secret key
    javax.crypto.SecretKey mySecretKey;
    KeyStore.SecretKeyEntry skEntry =
        new KeyStore.SecretKeyEntry(mySecretKey);
    ks.setEntry("secretKeyAlias", skEntry, protParam);
```

If this is violated, the following may occur.
* Keys cannot be stored securely and may be misused.

#### Generate public/private key pairs for secure storage of symmetric keys under Android OS 5.1 (Required)

To securely store symmetric keys on devices with Android 5.1 (API level 22) or lower, a public/private key pair must be generated. The public key is used to encrypt the symmetric key, and the private key is stored in the Android KeyStore. The encrypted symmetric key can be encoded in base64 and stored in SharedPreferences. Whenever a symmetric key is needed, the application retrieves the private key from the Android KeyStore and decrypts the symmetric key.

\* No sample code due to conceptual rule.

If this is violated, the following may occur.
* Symmetric keys cannot be stored securely and may be misused.

#### EncryptedSharedPreferences usage (Recommended)

The following is how the EncryptedSharedPreferences in the androidx.security.crypto package should be handled when encrypting a key with another key.
The corresponding method is as follows.

Example in Java:
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

If this is violated, the following may occur.
* Symmetric keys cannot be stored securely and may be misused.

#### Do not use insecure encryption key storage methods (Required)
The use of SharedPreferences or hardcodes, which are considered insecure methods of storing encryption keys, is dangerous and should not be used.

Insecure methods of storing encryption keys are as follows:

* Storing in SharedPreferences; on a rooted device, other applications with root access can easily read other applications' SharedPreferences files.
* Hard-code to source code. An attacker can reverse engineer a local copy of the application, extract the encryption key, and use that key to decrypt data encrypted by the application on any device
* If there is a predictable key derivation function based on identifiers accessible by other applications, an attacker can find the key simply by finding the KDF and applying it to the device.
* Store the encryption key in public. Not recommended since other applications have the privilege to read the public partition and can steal the key.

#### Encryption with third-party libraries (Deprecated)

The following open source libraries exist that provide encryption capabilities specific to the Android platform. While the libraries are useful, their use is discouraged because it is always possible for a rooted device to easily retrieve the key and decrypt the value it is trying to protect, unless the key is stored in a KeyStore.

* Java AES Crypto: A simple Android class for encrypting and decrypting strings.
* SQL Cipher: SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
* Secure Preferences: Android Shared preference wrapper provides encryption of Shared Preferences keys and values.
* Themis: A cross-platform high-level encryption library that provides the same API on many platforms to protect authentication, storage, messaging, and other data.

The reasons for this deprecation are as follows.
* Unless the key is stored in the KeyStore, it is always possible to easily retrieve the key on a rooted device and decrypt the value you are trying to protect.

## MSTG-STORAGE-2
No sensitive data should be stored outside of the app container or system credential storage facilities.

### Internal Storage

You can save files to the device's [internal storage](https://developer.android.com/guide/topics/data/data-storage.html#filesInternal). Files saved to internal storage are containerized by default and cannot be accessed by other apps on the device. When the user uninstalls your app, these files are removed. The following code snippets would persistently store sensitive data to internal storage.<br>

Example for Java:
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

Example for Kotlin:
```kotlin
var fos: FileOutputStream? = null
fos = openFileOutput("FILENAME", Context.MODE_PRIVATE)
fos.write(test.toByteArray(Charsets.UTF_8))
fos.close()
```

You should check the file mode to make sure that only the app can access the file. You can set this access with MODE_PRIVATE. Modes such as MODE_WORLD_READABLE (deprecated) and MODE_WORLD_WRITEABLE (deprecated) may pose a security risk.<br>

Search for the class FileInputStream to find out which files are opened and read within the app.<br>

Reference
* [owasp-mastg Data Storage Methods Overview Internal Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#internal-storage)

Rulebook
* [Store sensitive data in the app container or in the system's credentials storage function (Required)](#store-sensitive-data-in-the-app-container-or-in-the-systems-credentials-storage-function-required)

### External Storage

Every Android-compatible device supports [shared external storage](https://developer.android.com/guide/topics/data/data-storage.html#filesExternal). This storage may be removable (such as an SD card) or internal (non-removable). Files saved to external storage are world-readable. The user can modify them when USB mass storage is enabled. You can use the following code snippets to persistently store sensitive information to external storage as the contents of the file password.txt.<br>

Example for Java:
```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

Example for Kotlin:
```kotlin
val password = "SecretPassword"
val path = context.getExternalFilesDir(null)
val file = File(path, "password.txt")
file.appendText(password)
```

The file will be created and the data will be stored in a clear text file in external storage once the activity has been called.

It's also worth knowing that files stored outside the application folder (data/data/\<package-name\>/) will not be deleted when the user uninstalls the application. Finally, it's worth noting that the external storage can be used by an attacker to allow for arbitrary control of the application in some cases. For more information: [see the blog from Checkpoint](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/).

Reference
* [owasp-mastg Data Storage Methods Overview External Storage](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#external-storage)

### SharedPreferences

The [SharedPreferences](https://developer.android.com/training/data-storage/shared-preferences) API is commonly used to permanently save small collections of key-value pairs. Data stored in a SharedPreferences object is written to a plain-text XML file. The SharedPreferences object can be declared world-readable (accessible to all apps) or private. Misuse of the SharedPreferences API can often lead to exposure of sensitive data. Consider the following example:

Example for Java:
```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Example for Kotlin:
```kotlin
var sharedPref = getSharedPreferences("key", Context.MODE_WORLD_READABLE)
var editor = sharedPref.edit()
editor.putString("username", "administrator")
editor.putString("password", "supersecret")
editor.commit()
```

Once the activity has been called, the file key.xml will be created with the provided data. This code violates several best practices.

* The username and password are stored in clear text in /data/data/\<package-name\>/shared_prefs/key.xml.
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

* MODE_WORLD_READABLE allows all applications to access and read the contents of key.xml.
```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118    170 2016-04-23 16:51 key.xml
```

\* Please note that MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE were deprecated starting on API level 17. Although newer devices may not be affected by this, applications compiled with an android:targetSdkVersion value less than 17 may be affected if they run on an OS version that was released before Android 4.2 (API level 17).

Reference
* [owasp-mastg Data Storage Methods Overview Shared Preferences](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#shared-preferences)

### Databases

The Android platform provides a number of database options as aforementioned in the previous list. Each database option has its own quirks and methods that need to be understood.

Reference
* [owasp-mastg  Data Storage Methods Overview Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#databases)

#### SQLite

**SQLite Database (Unencrypted)**<br>
SQLite is an SQL database engine that stores data in .db files. The Android SDK has [built-in support](https://developer.android.com/training/data-storage/sqlite) for SQLite databases. The main package used to manage the databases is android.database.sqlite. For example, you may use the following code to store sensitive information within an activity:

Example in Java:
```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure", MODE_PRIVATE, null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Example in Kotlin:
```kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
notSoSecure.close()
```

Once the activity has been called, the database file privateNotSoSecure will be created with the provided data and stored in the clear text file /data/data/\<package-name\>/databases/privateNotSoSecure.

The database's directory may contain several files besides the SQLite database:
* [Journal files](https://www.sqlite.org/tempfiles.html): These are temporary files used to implement atomic commit and rollback.
* [Lock files](https://www.sqlite.org/lockingv3.html): The lock files are part of the locking and journaling feature, which was designed to improve SQLite concurrency and reduce the writer starvation problem.

Sensitive information should not be stored in unencrypted SQLite databases.

**SQLite Databases (Encrypted)**<br>
With the library [SQLCipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/), SQLite databases can be password-encrypted.

Example in Java:
```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();
```

Example in Kotlin:
```kotlin
var secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null)
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);")
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');")
secureDB.close()
```

Secure ways to retrieve the database key include:
* Asking the user to decrypt the database with a PIN or password once the app is opened (weak passwords and PINs are vulnerable to brute force attacks)
* Storing the key on the server and allowing it to be accessed from a web service only (so that the app can be used only when the device is online)

Reference
* [owasp-mastg Data Storage Methods Overview SQLite Databases (Encrypted)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#sqlite-databases-encrypted)
* [owasp-mastg Data Storage Methods Overview SQLite Database (Unencrypted)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#sqlite-database-unencrypted)

#### Firebase

Firebase is a development platform with more than 15 products, and one of them is Firebase Real-time Database. It can be leveraged by application developers to store and sync data with a NoSQL cloud-hosted database. The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline.

A misconfigured Firebase instance can be identified by making the following network call:

`https://_firebaseProjectName_.firebaseio.com/.json`

The firebaseProjectName can be retrieved from the mobile application by reverse engineering the application. Alternatively, the analysts can use [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner), a python script that automates the task above as shown below:

```bash
python FirebaseScanner.py -p <pathOfAPKFile>

python FirebaseScanner.py -f <commaSeperatedFirebaseProjectNames>
```

Reference
* [owasp-mastg Data Storage Methods Overview Firebase Real-time Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#firebase-real-time-databases)

#### Realm

The [Realm Database for Java](https://realm.io/docs/java/latest/) is becoming more and more popular among developers. The database and its contents can be encrypted with a key stored in the configuration file.

```java
//the getKey() method either gets the key from the server or from a KeyStore, or is derived from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
  .encryptionKey(getKey())
  .build();

Realm realm = Realm.getInstance(config);
```

If the database is not encrypted, you should be able to obtain the data. If the database is encrypted, determine whether the key is hard-coded in the source or resources and whether it is stored unprotected in shared preferences or some other location.

Reference
* [owasp-mastg Data Storage Methods Overview Realm Databases](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#realm-databases)

### Rulebook

1. [Store sensitive data in the app container or in the system's credentials storage function (Required)](#store-sensitive-data-in-the-app-container-or-in-the-systems-credentials-storage-function-required)

#### Store sensitive data in the app container or in the system's credentials storage function (Required)
In order to securely store sensitive data, it is necessary to encrypt data using keys managed by the system's credentials storage function (Android Keystore) and to ensure that encrypted data is stored in the application container (internal storage). For information on how to use the Android Keystore, see "[Encryption key storage method (Required)](#encryption-key-storage-method-required)".

In order to avoid external reads, it must be implemented so that only the application can read and write files in internal storage.
One method of creating files in internal storage is to use streams. In this method, "[Context#openFileOutput](https://developer.android.com/reference/android/content/Context?hl=ja#openFileOutput(java.lang.String,%20int))" is called to obtain a "[FileOutputStream](https://developer.android.com/reference/java/io/FileOutputStream?hl=ja)" object to access a file in the filesDir directory. If the specified file does not exist, a new file is created.

In a call to Context#openFileOutput, the file mode must be specified. The file mode specified determines the read/write range of the created file.

The following are the main file modes.

* MODE_PRIVATE
* MODE_WORLD_READABLE
* MODE_WORLD_WRITEABLE

The following is an example of a Context#openFileOutput call. Note that on devices with Android 7.0 (API level 24) or later, if MODE_PRIVATE is not specified for the file mode, [SecurityException](https://developer.android.com/reference/java/lang/SecurityException?hl=ja) will occur when calling.

```java
String filename = "myfile";
String fileContents = "Hello world!";
try (FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE)) {
    fos.write(fileContents.toByteArray());
}
```

**File mode setting MODE_PRIVATE**<br>
In default mode, the created file can be accessed by the calling application or by all applications sharing the same user ID.

```java
public static final int MODE_PRIVATE
```

**File mode setting MODE_WORLD_READABLE**<br>
All other applications will have read access to the created file.
Note that the use of MODE_WORLD_READABLE has been deprecated since API level 17.

```java
public static final int MODE_WORLD_READABLE
```

**File mode setting MODE_WORLD_WRITEABLE**<br>
All other applications will have read access to the created file.
Note that the use of MODE_WORLD_WRITEABLE has been deprecated since API level 17.

```java
public static final int MODE_WORLD_WRITEABLE
```

If this is violated, the following may occur.
* Sensitive data can be read by other applications or third parties.

## MSTG-STORAGE-3
No sensitive data is written to application logs.

### Log Output

This test case focuses on identifying any sensitive application data within both system and application logs. The following checks should be performed:

* Analyze source code for logging related code.
* Check application data directory for log files.
* Gather system messages and logs and analyze for any sensitive data.

As a general recommendation to avoid potential sensitive application data leakage, logging statements should be removed from production releases unless deemed necessary to the application or explicitly identified as safe, e.g. as a result of a security audit.

Reference
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#testing-logs-for-sensitive-data-mstg-storage-3)

#### File Write

Applications will often use the [Log Class](https://developer.android.com/reference/android/util/Log.html) and [Logger Class](https://developer.android.com/reference/java/util/logging/Logger.html) to create logs. To discover this, you should audit the application's source code for any such logging classes. These can often be found by searching for the following keywords:

* Functions and classes, such as:
  * android.util.Log
  * Log.d | Log.e | Log.i | Log.v | Log.w | Log.wtf
  * Logger

* Keywords and system output:
  * System.out.print | System.err.print
  * logfile
  * logging
  * logs

Reference
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#static-analysis-2)

Rulebook
* [When outputting logs, do not include confidential information in the output content (Required)](#when-outputting-logs-do-not-include-confidential-information-in-the-output-content-required)

#### Logcat Output

Use all the mobile app functions at least once, then identify the application's data directory and look for log files (/data/data/\<package-name\>). Check the application logs to determine whether log data has been generated; some mobile applications create and store their own logs in the data directory.

Many application developers still use System.out.println or printStackTrace instead of a proper logging class. Therefore, your testing strategy must include all output generated while the application is starting, running and closing. To determine what data is directly printed by System.out.println or printStackTrace, you can use [Logcat](https://developer.android.com/tools/debugging/debugging-log.html) as explained in the chapter "Basic Security Testing", section "Monitoring System Logs".

Remember that you can target a specific app by filtering the Logcat output as follows:
```bash
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

\* If you already know the app PID you may give it directly using --pid flag.

You may also want to apply further filters or regular expressions (using logcat's regex flags -e \<expr\>, --regex=\<expr\> for example) if you expect certain strings or patterns to come up in the logs.

Reference
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#dynamic-analysis-1)

#### Deletion of logging functions by ProGuard

While preparing the production release, you can use tools like [ProGuard](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#proguard) (included in Android Studio). To determine whether all logging functions from the android.util.Log class have been removed, check the ProGuard configuration file (proguard-rules.pro) for the following options (according to this [example of removing logging code](https://www.guardsquare.com/en/products/proguard/manual/examples#logging) and this article about [enabling ProGuard in an Android Studio project](https://developer.android.com/studio/build/shrink-code#enable)):

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

Note that the example above only ensures that calls to the Log class' methods will be removed. If the string that will be logged is dynamically constructed, the code that constructs the string may remain in the bytecode. For example, the following code issues an implicit StringBuilder to construct the log statement:

Example in Java:
```java
Log.v("Private key tag", "Private key [byte format]: " + key);
```

Example in Kotlin:
```kotlin
Log.v("Private key tag", "Private key [byte format]: $key")
```

The compiled bytecode, however, is equivalent to the bytecode of the following log statement, which constructs the string explicitly:

Example in Java:
```java
Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

Example in Kotlin:
```kotlin
Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
```

ProGuard guarantees removal of the Log.v method call. Whether the rest of the code (new StringBuilder ...) will be removed depends on the complexity of the code and the [ProGuard version](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation).

This is a security risk because the (unused) string leaks plain text data into memory, which can be accessed via a debugger or memory dumping.

Unfortunately, no silver bullet exists for this issue, but one option would be to implement a custom logging facility that takes simple arguments and constructs the log statements internally.c

```java
SecureLog.v("Private key [byte format]: ", key);
```

Then configure ProGuard to strip its calls.

Reference
* [owasp-mastg Testing Logs for Sensitive Data (MSTG-STORAGE-3) Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#static-analysis-2)

### Rulebook

1. [When outputting logs, do not include confidential information in the output content (Required)](#when-outputting-logs-do-not-include-confidential-information-in-the-output-content-required)

#### When outputting logs, do not include confidential information in the output content (Required)
When outputting logs, it must be ensured that the output does not contain sensitive information.

Common log output classes include the following.

* Log
* Logger

**Log Class**

Log.v(), Log.d(), Log.i(), Log.w(), and Log.e() methods are included in the android.util package. The written logs can be viewed on Logcat.

Each method is classified by log level.
The following is a list of log levels and their associated methods.
| No | Log Level | Methods |
| :--- | :--- | :--- |
| 1 | DEBUG | Log.d |
| 2 | ERROR | Log.e |
| 3 | INFO | Log.i |
| 4 | VERBOSE | Log.v |
| 5 | WARN | Log.w |
| 6 | What a Terrible Failure | Log.wtf |

The following is an example of log output code by the Log class.
```java
private static final String TAG = "MyActivity";
Log.v(TAG, "index=" + i);
```

**Logger Class**

A class included in java.util.logging for logging output, used to log messages for a specific system or application component. It is typically named using a hierarchical, dot-delimited namespace. The Logger name can be any string, but should usually be based on the package or class name of the component being logged (e.g., java.net or javax.swing).

Below is an example of the log output code by the Logger class.
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

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

## MSTG-STORAGE-4
No sensitive data is shared with third parties unless it is a necessary part of the architecture.

### Application Data Sharing

Sensitive information might be leaked to third parties by several means, which include but are not limited to the following:

Reference
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Overview](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#overview-3)

#### Third-party Services Embedded in the App

The features these services provide can involve tracking services to monitor the user's behavior while using the app, selling banner advertisements, or improving the user experience.

The downside is that developers don't usually know the details of the code executed via third-party libraries. Consequently, no more information than is necessary should be sent to a service, and no sensitive information should be disclosed.

Most third-party services are implemented in two ways:

* with a standalone library
* with a full SDK

**Static Analtsis**<br>
To determine whether API calls and functions provided by the third-party library are used according to best practices, review their source code, requested permissions and check for any known vulnerabilities (see ["Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)"](0x08-MASDG-Code_Quality_and_Build_Setting_Requirements.md#checking-for-weaknesses-in-third-party-libraries).

All data that's sent to third-party services should be anonymized to prevent exposure of PII (Personal Identifiable Information) that would allow the third party to identify the user account. No other data (such as IDs that can be mapped to a user account or session) should be sent to a third party.

**Dynamic Analysis**<br>
Check all requests to external services for embedded sensitive information. To intercept traffic between the client and server, you can perform dynamic analysis by launching a man-in-the-middle (MITM) attack with [Burp Suite](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#burp-suite) Professional or [OWASP ZAP](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x08a-Testing-Tools.md#owasp-zap). Once you route the traffic through the interception proxy, you can try to sniff the traffic that passes between the app and server. All app requests that aren't sent directly to the server on which the main function is hosted should be checked for sensitive information, such as PII in a tracker or ad service.

Reference
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app-1)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) Third-party Services Embedded in the App Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#third-party-services-embedded-in-the-app-2)

Rulebook
* [Do not share unnecessarily confidential information to third-party libraries (Required)](#do-not-share-unnecessarily-confidential-information-to-third-party-libraries-required)

#### App Notifications

It is important to understand that [notifications](https://developer.android.com/guide/topics/ui/notifiers/notifications) should never be considered private. When a notification is handled by the Android system it is broadcasted system-wide and any application running with a [NotificationListenerService](https://developer.android.com/reference/kotlin/android/service/notification/NotificationListenerService) can listen for these notifications to receive them in full and may handle them however it wants.

There are many known malware samples such as [Joker](https://research.checkpoint.com/2020/new-joker-variant-hits-google-play-with-an-old-trick/), and [Alien](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise.html) which abuses the NotificationListenerService to listen for notifications on the device and then send them to attacker-controlled C2 infrastructure. Commonly this is done in order to listen for two-factor authentication (2FA) codes that appear as notifications on the device which are then sent to the attacker. A safer alternative for the user would be to use a 2FA application that does not generate notifications.

Furthermore there are a number of apps on the Google Play Store that provide notification logging, which basically logs locally any notifications on the Android system. This highlights that notifications are in no way private on Android and accessible by any other app on the device.

For this reason all notification usage should be inspected for confidential or high risk information that could be used by malicious applications.

**Static Analtsis**<br>
Search for any usage of the NotificationManager class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is [generating the notifications](https://developer.android.com/training/notify-user/build-notification#SimpleNotification) and which data ends up being shown.

**Dynamic Analysis**<br>
Run the application and start tracing all calls to functions related to the notifications creation, e.g. setContentTitle or setContentText from [NotificationCompat.Builder.](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) Observe the trace in the end and evaluate if it contains any sensitive information which another app might have eavesdropped.

Reference
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-1)
* [owasp-mastg Determining Whether Sensitive Data Is Shared with Third Parties (MSTG-STORAGE-4) App Notifications Dynamic Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-2)

Rulebook
* [Do not include confidential information in the notification (Required)](#do-not-include-confidential-information-in-the-notification-required)

### Rulebook
1. [Do not share unnecessarily confidential information to third-party libraries (Required)](#do-not-share-unnecessarily-confidential-information-to-third-party-libraries-required)
1. [Do not include confidential information in the notification (Required)](#do-not-include-confidential-information-in-the-notification-required)

#### Do not share unnecessarily confidential information to third-party libraries (Required)
When using a third-party library, make sure that no non-essential confidential information is set as a parameter to be passed to the library.
If non-essential confidential information is set, be aware that it may be used maliciously in the library's internal processing.

Since the library may be required for communication, if the above concerns are considered, it is necessary to encrypt confidential information using an encryption method decided between the server and client in advance and pass it to the library, etc.

If this is violated, the following may occur.
* May be exploited in the processing of third-party libraries.

#### Do not include confidential information in the notification (Required)
The [NotificationManager](https://developer.android.com/reference/android/app/NotificationManager) class is used to notify users of events that have occurred.

The components of the notification (display content) are specified in the [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) object.<br>
Builder class provides methods for specifying the components of a notification. The following is an example of a method for specification.

* setContentTitle: Specifies the title (first line) of the notification in a standard notification.
* setContentText: In a standard notification, specifies the text of the notification (second line).

When using notifications, note that setContentTitle and setContentText are not set with sensitive information.

The following is an example of source code that specifies the components of a notification to the NotificationCompat.Builder class and displays the notification using the NotificationManager class.

```kotlin
    var builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.notification_icon)
            .setContentTitle(textTitle)
            .setContentText(textContent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
    with(NotificationManagerCompat.from(this)) {
        // Pass notificationID and builder.build()
        notify(notificationID, builder.build())
    }
```

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

## MSTG-STORAGE-5
The keyboard cache is disabled on text inputs that process sensitive data.

### Automatic entry of confidential data

When users type in input fields, the software automatically suggests data. This feature can be very useful for messaging apps. However, the keyboard cache may disclose sensitive information when the user selects an input field that takes this type of information.

**Static Analysis**<br>
In the layout definition of an activity, you can define TextViews that have XML attributes. If the XML attribute android:inputType is given the value textNoSuggestions, the keyboard cache will not be shown when the input field is selected. The user will have to type everything manually.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

The code for all input fields that take sensitive information should include this XML attribute to [disable the keyboard suggestions](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_FLAG_NO_SUGGESTIONS).

**Dynamic Analysis**<br>
Start the app and click in the input fields that take sensitive data. If strings are suggested, the keyboard cache has not been disabled for these fields.

Reference
* [owasp-mastg Determining Whether the Keyboard Cache Is Disabled for Text Input Fields MSTG-STORAGE-5)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#determining-whether-the-keyboard-cache-is-disabled-for-text-input-fields-mstg-storage-5)

Rulebook
* [Implement code for all input fields for sensitive information to disable keyboard suggestions (Required)](#implement-code-for-all-input-fields-for-sensitive-information-to-disable-keyboard-suggestions-required)
* [All input field layouts for sensitive information should be implemented to disable keyboard suggestions (Required)](#all-input-field-layouts-for-sensitive-information-should-be-implemented-to-disable-keyboard-suggestions-required)

### Rulebook
1. [Implement code for all input fields for sensitive information to disable keyboard suggestions (Required)](#implement-code-for-all-input-fields-for-sensitive-information-to-disable-keyboard-suggestions-required)
1. [All input field layouts for sensitive information should be implemented to disable keyboard suggestions (Required)](#all-input-field-layouts-for-sensitive-information-should-be-implemented-to-disable-keyboard-suggestions-required)

#### Implement code for all input fields for sensitive information to disable keyboard suggestions (Required)

Use the EditText class for text input and modification. When defining a text editing widget, the android.R.styleable#TextView_inputType attribute must be set.

In the code for fields where confidential information is to be entered, set the TYPE_TEXT_FLAG_NO_SUGGESTIONS flag to the inputType attribute.
However, if the field is for a password or pin, set the TYPE_TEXT_VARIATION_PASSWORD flag to the inputType attribute for masking (see [Input Text](#input-text)).

Below is an example of a code that sets TYPE_TEXT_FLAG_NO_SUGGESTIONS as a flag for the inputType attribute on the code.

```kotlin
val editText1: EditText = findViewById(R.id.editText1)
editText1.apply {
    inputType = InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
}
```

It is also necessary to make sure that the cache is not overwritten with a value that would re-enable it.

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

#### All input field layouts for sensitive information should be implemented to disable keyboard suggestions (Required)
In the layout of a field for inputting confidential information (EditText), set "textNoSuggestions" to the inputType attribute.
However, if the field is for a password or pin, set the "textPassword" to the inputType attribute for masking (see [Input Text](#input-text)).

Below is an example of code that sets "textNoSuggestions" as the inputType attribute on the code.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

## MSTG-STORAGE-6
No sensitive data is exposed via IPC mechanisms.

### Access to sensitive data via ContentProvider

As part of Android's IPC mechanisms, content providers allow an app's stored data to be accessed and modified by other apps. If not properly configured, these mechanisms may leak sensitive data.

**Static Analysis**<br>
The first step is to look at AndroidManifest.xml to detect content providers exposed by the app. You can identify content providers by the \<provider\> element. Complete the following steps:

* Determine whether the value of the export tag (android:exported) is "true". Even if it is not, the tag will be set to "true" automatically if an \<intent-filter\> has been defined for the tag. If the content is meant to be accessed only by the app itself, set android:exported to "false". If not, set the flag to "true" and define proper read/write permissions.
* Determine whether the data is being protected by a permission tag (android:permission). Permission tags limit exposure to other apps.
* Determine whether the android:protectionLevel attribute has the value signature. This setting indicates that the data is intended to be accessed only by apps from the same enterprise (i.e., signed with the same key). To make the data accessible to other apps, apply a security policy with the \<permission\> element and set a proper android:protectionLevel. If you use android:permission, other applications must declare corresponding \<uses-permission\> elements in their manifests to interact with your content provider. You can use the android:grantUriPermissions attribute to grant more specific access to other apps; you can limit access with the \<grant-uri-permission\> element.

Inspect the source code to understand how the content provider is meant to be used. Search for the following keywords:
* android.content.ContentProvider
* android.database.Cursor
* android.database.sqlite
* .query
* .update
* .delete

\* To avoid SQL injection attacks within the app, use parameterized query methods, such as query, update, and delete. Be sure to properly sanitize all method arguments; for example, the selection argument could lead to SQL injection if it is made up of concatenated user input.

If you expose a content provider, determine whether parameterized [query methods](https://developer.android.com/reference/android/content/ContentProvider#query%28android.net.Uri%2C%20java.lang.String%5B%5D%2C%20java.lang.String%2C%20java.lang.String%5B%5D%2C%20java.lang.String%29) (query, update, and delete) are being used to prevent SQL injection. If so, make sure all their arguments are properly sanitized.

We will use the vulnerable password manager app [Sieve](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk) as an example of a vulnerable content provider.

**Inspect the Android Manifest**<br>
Identify all defined \<provider\> elements:

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

As shown in the AndroidManifest.xml above, the application exports two content providers. <br>
Note that one path ("/Keys") is protected by read and write permissions.

**Inspect the source code**<br>
Inspect the query function in the DBContentProvider.java file to determine whether any sensitive information is being leaked:

Example in Java:
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

Example in Kotlin:
```kotlin
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

Here we see that there are actually two paths, "/Keys" and "/Passwords", and the latter is not being protected in the manifest and is therefore vulnerable.

When accessing a URI, the query statement returns all passwords and the path Passwords/. We will address this in the "Dynamic Analysis" section and show the exact URI that is required.

**Dynamic Analysis**<br>
**Testing Content Providers**<br>
To dynamically analyze an application's content providers, first enumerate the attack surface: pass the app's package name to the Drozer module app.provider.info:

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

In this example, two content providers are exported. Both can be accessed without permission, except for the /Keys path in the DBContentProvider. With this information, you can reconstruct part of the content URIs to access the DBContentProvider (the URIs begin with content://).

To identify content provider URIs within the application, use Drozer's scanner.provider.finduris module. This module guesses paths and determines accessible content URIs in several ways:

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

Once you have a list of accessible content providers, try to extract data from each provider with the app.provider.query module:

```bash
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
_id: 1
service: Email
username: incognitoguy50
password: PSFjqXIMVa5NJFudgDuuLVgJYFD+8w== (Base64 - encoded)
email: incognitoguy50@gmail.com
```

You can also use Drozer to insert, update, and delete records from a vulnerable content provider:

* Insert record
  ```bash
  dz> run app.provider.insert content://com.vulnerable.im/messages
                --string date 1331763850325
                --string type 0
                --integer _id 7
  ```
* Update record
  ```bash
  dz> run app.provider.update content://settings/secure
                --selection "name=?"
                --selection-args assisted_gps_enabled
                --integer value 0
  ```
* Delete record
  ```bash
  dz> run app.provider.delete content://settings/secure
                --selection "name=?"
                --selection-args my_setting
  ```

**SQL Injection in Content Providers**<br>
The Android platform promotes SQLite databases for storing user data. Because these databases are based on SQL, they may be vulnerable to SQL injection. <br>
You can use the Drozer module app.provider.query to test for SQL injection by manipulating the projection and selection fields that are passed to the content provider:

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"
unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')
```

If an application is vulnerable to SQL Injection, it will return a verbose error message. SQL Injection on Android may be used to modify or query data from the vulnerable content provider. In the following example, the Drozer module app.provider.query is used to list all the database tables:

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "*
FROM SQLITE_MASTER WHERE type='table';--"
| type  | name             | tbl_name         | rootpage | sql              |
| table | android_metadata | android_metadata | 3        | CREATE TABLE ... |
| table | Passwords        | Passwords        | 4        | CREATE TABLE ... |
| table | Key              | Key              | 5        | CREATE TABLE ... |
```

SQL Injection may also be used to retrieve data from otherwise protected tables:

```default
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
| Password | pin |
| thisismypassword | 9876 |
```

You can automate these steps with the scanner.provider.injection module, which automatically finds vulnerable content providers within an app:

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

**File System Based Content Providers**<br>
Content providers can provide access to the underlying filesystem. This allows apps to share files (the Android sandbox normally prevents this).You can use the Drozer modules app.provider.read and app.provider.download to read and download files, respectively, from exported file-based content providers.These content providers are susceptible to directory traversal, which allows otherwise protected files in the target application's sandbox to be read.

```default
dz> run app.provider.download content://com.vulnerable.app.FileProvider/../../../../../../../../data/data/com.vulnerable.app/database.db /home/user/database.db
Written 24488 bytes
```

Use the scanner.provider.traversal module to automate the process of finding content providers that are susceptible to directory traversal:

```default
dz> run scanner.provider.traversal -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Vulnerable Providers:
  content://com.mwr.example.sieve.FileBackupProvider/
  content://com.mwr.example.sieve.FileBackupProvider
```

Note that adb can also be used to query content providers:
```bash
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
Row: 0 id=1, username=admin, password=StrongPwd
Row: 1 id=2, username=test, password=test
...
```

Reference
* [owasp-mastg Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms (MSTG-STORAGE-6)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#determining-whether-sensitive-stored-data-has-been-exposed-via-ipc-mechanisms-mstg-storage-6)

Rulebook
* [Set appropriate access permissions for ContentProvider (Required)](#set-appropriate-access-permissions-for-contentprovider-required)
* [Take measures against SQL injection when using SQL databases (Required)](#take-measures-against-sql-injection-when-using-sql-databases-required)
* [Take measures against directory traversal when using ContentProvider (Required)](#take-measures-against-directory-traversal-when-using-contentprovider-required)

### Rulebook
1. [Set appropriate access permissions for ContentProvider (Required)](#set-appropriate-access-permissions-for-contentprovider-required)
1. [Take measures against SQL injection when using SQL databases (Required)](#take-measures-against-sql-injection-when-using-sql-databases-required)
1. [Take measures against directory traversal when using ContentProvider (Required)](#take-measures-against-directory-traversal-when-using-contentprovider-required)

#### Set appropriate access permissions for ContentProvider (Required)

All ContentProviders in the app must be defined in the \<provider\> element in AndroidManifest.xml. If undefined, the system will not recognize the ContentProvider and will not execute it.

Declare only the ContentProvider that is part of the target application, and do not declare any ContentProvider that is used within the target application but is part of another application.

The following is an example of a definition of the \<provider\> element in AndroidManifest.xml
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
Content providers must be configured appropriately considering the data to be accessed.

**Tags that configure whether ContentProvider can be used by other apps android:exported**<br>
This tag allows you to configure whether other apps can use ContentProvider.
The following are the possible settings
* true ：Other apps can use ContentProvider. Any application can access ContentProvider using the content URI of ContentProvider according to the permissions specified for ContentProvider.
* false ：Other apps cannot use ContentProvider. When android:exported="false" is set, access to ContentProvider is limited to the target application.When this is set, apps that can access the ContentProvider are limited to apps that have the same user ID (UID) as the ContentProvider, or apps that have been granted temporary access rights by the android:grantUriPermissions tag.

Since this tag was introduced in API level 17, all devices with API level 16 or lower will behave as if this tag were set to "true".<br>
If android:targetSdkVersion is set to 17 or higher, the default value is "false" for devices with API level 17 or higher.

\* Note that even if exported is false, if an \<intent-filter> is defined, the situation is the same as if exported were set to true. 

**Tag android:permission to set the \<permission\> element name needed for ContentProvider data read/write.**

Sets the \<permission\>  element name required by the client when reading/writing ContentProvider data.This attribute is useful for setting a single authorization for both reading and writing. However, the [android:readPermission](https://developer.android.com/guide/topics/manifest/provider-element#rprmsn), [android:writePermission](https://developer.android.com/guide/topics/manifest/provider-element#wprmsn), and [android:grantUriPermissions](https://developer.android.com/guide/topics/manifest/provider-element#gprmsn) attributes take precedence over this attribute. If the android:readPermission attribute is also set, access to query ContentProvider is controlled. If the android:writePermission attribute is set, access to change data in ContentProvider is controlled.

By setting the level of protection to the [android:protectionLevel](https://developer.android.com/guide/topics/manifest/permission-element#plevel) tag within the \<permission\> element, one can specify the risks that may be included in the authorization and the steps that the system must follow when deciding whether to grant the authorization to the requesting app.

Each protection level specifies a basic authority type and [protectionLevel](https://developer.android.com/reference/android/R.attr#protectionLevel).<br>
The following is a list of basic authority types

| Basic Authority Type | Description. |
| :--- | :--- |
| normal | Default Value. Low-risk permissions that provide access to isolated app-level functionality to the requesting app. |
| dangerous | High-risk permissions that allow the requesting app to access personal data or control the device, which could negatively impact the user. |
| signature | Authority granted by the system only if the same certificate as the app declaring the authority is used to sign the requesting app. |
| signatureOrSystem | Authority granted by the system only to apps installed in a dedicated folder in the Android system image or apps signed using the same certificate as the app that declared the authority. Note that this is deprecated in API level 23. |

**Temporarily grant access to ContentProvider data tag android:grantUriPermissions**

 Sets whether users who do not have permission to access ContentProvider data can be granted such privileges. If granted, the restrictions imposed by the [android:readPermission](https://developer.android.com/guide/topics/manifest/provider-element#rprmsn), [android:writePermission](https://developer.android.com/guide/topics/manifest/provider-element#wprmsn), [android:permission](https://developer.android.com/guide/topics/manifest/provider-element#prmsn), and [android:exported](https://developer.android.com/guide/topics/manifest/provider-element#exported) attributes are temporarily lifted. Set to "true" if permission can be granted, otherwise set to "false". If set to "true", permissions can be granted for any data in ContentProvider. If set to "false", authorization can only be granted for the data subset (if any) listed in the [<grant-uri-permission>](https://developer.android.com/guide/topics/manifest/grant-uri-permission-element) sub-element. The default value is "false".

If this is violated, the following may occur.
* Sensitive data may be unintentionally leaked to other apps.

#### Take measures against SQL injection when using SQL databases (Required)
When using SQL databases in ContentProvider, it is necessary to take measures against SQL injection.

The measures to be taken are described below.
1. If you do not need to expose ContentProvider to other apps:
   * In the manifest, change the [/<provider>](https://developer.android.com/guide/topics/manifest/provider-element) tag of the target ContentProvider and set it to [android:exported="false"](https://developer.android.com/guide/topics/manifest/provider-element.html#exported). This will prevent other apps from sending intents to the target ContentProvider.
   *The [android:permission](https://developer.android.com/guide/topics/manifest/provider-element.html#prmsn) attribute can also be set to the [permission](https://developer.android.com/guide/topics/manifest/permission-element.html) of the [android:protectionLevel="signature"](https://developer.android.com/guide/topics/manifest/permission-element.html#plevel) to prevent apps written by other developers from sending intents to the target ContentProvider.
1. If you need to expose ContentProvider to other apps:

   The sql to be passed to the query() method is pre-validated, and unnecessary characters are escaped. Also, using ? as a substitutable parameter in a select clause and a separate array of select arguments reduces risk by binding user input directly to the query rather than interpreting it as part of the SQL statement. A sample code is shown below.
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

If this is violated, the following may occur.
* SQL injection vulnerabilities may be exploited.

#### Take measures against directory traversal when using ContentProvider (Required)
When using ContentProvider, directory traversal must be addressed.

The measures to be taken are described below.
1. If you do not need to expose ContentProvider to other apps:
   * In the manifest, change the [/<provider>](https://developer.android.com/guide/topics/manifest/provider-element) tag of the target ContentProvider and set it to [android:exported="false"](https://developer.android.com/guide/topics/manifest/provider-element.html#exported). This will prevent other apps from sending intents to the target ContentProvider.
   * The [android:permission](https://developer.android.com/guide/topics/manifest/provider-element.html#prmsn) attribute can also be set to the [permission](https://developer.android.com/guide/topics/manifest/permission-element.html) of the [android:protectionLevel="signature"](https://developer.android.com/guide/topics/manifest/permission-element.html#plevel) to prevent apps written by other developers from sending intents to the target ContentProvider.


1. If you need to expose ContentProvider to other apps:

   When the input to openFile contains path traversal characters, it must be configured correctly so that the app will never return an unexpected file. To do so, check the canonical path of the file. A sample code is shown below.
   
   ```java
   public ParcelFileDescriptor openFile (Uri uri, String mode) throws FileNotFoundException {
       File f = new File(DIR, uri.getLastPathSegment());
       if (!f.getCanonicalPath().startsWith(DIR)) {
           throw new IllegalArgumentException();
       }
       return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
   }
   ```

If this is violated, the following may occur.
* Directory traversal vulnerabilities may be exploited.

## MSTG-STORAGE-7
No sensitive data, such as passwords or pins, is exposed through the user interface.

### Checking for Sensitive Data Disclosure Through the User Interface

Entering sensitive information when, for example, registering an account or making payments, is an essential part of using many apps. This data may be financial information such as credit card data or user account passwords. The data may be exposed if the app doesn't properly mask it while it is being typed.

In order to prevent disclosure and mitigate risks such as [shoulder surfing](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) you should verify that no sensitive data is exposed via the user interface unless explicitly required (e.g. a password being entered). For the data required to be present it should be properly masked, typically by showing asterisks or dots instead of clear text.

Carefully review all UI components that either show such information or take it as input. Search for any traces of sensitive information and evaluate if it should be masked or completely removed.


Reference
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#checking-for-sensitive-data-disclosure-through-the-user-interface-mstg-storage-7)

#### Input text

**Static Analysis**<br>
To make sure an application is masking sensitive user input, check for the following attribute in the definition of EditText:

```xml
android:inputType="textPassword"
```

With this setting, dots (instead of the input characters) will be displayed in the text field, preventing the app from leaking passwords or pins to the user interface.

**Dynamic Analysis**<br>
If the information is masked by, for example, replacing input with asterisks or dots, the app isn't leaking data to the user interface.

Reference
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7) Text Fields](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#text-fields)

Rulebook
* [Masking in fields for sensitive passwords and pins (Required)](#masking-in-fields-for-sensitive-passwords-and-pins-required)

#### App Notifications

**Static Analysis**<br>
When statically assessing an application, it is recommended to search for any usage of the NotificationManager class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is [generating the notifications](https://developer.android.com/training/notify-user/build-notification#SimpleNotification).

These code locations can be fed into the Dynamic Analysis section below, providing an idea of where in the application notifications may be dynamically generated.

**Dynamic Analysis**<br>

To identify the usage of notifications run through the entire application and all its available functions looking for ways to trigger any notifications. Consider that you may need to perform actions outside of the application in order to trigger certain notifications.

While running the application you may want to start tracing all calls to functions related to the notifications creation, e.g. setContentTitle or setContentText from [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder). Observe the trace in the end and evaluate if it contains any sensitive information.

Reference
* [owasp-mastg Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7) App Notifications](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05d-Testing-Data-Storage.md#app-notifications-3)

Rulebook
* [Implement with an understanding of how the application generates notifications and which data to display (Required)](#implement-with-an-understanding-of-how-the-application-generates-notifications-and-which-data-to-display-required)

### Rulebook
1. [Masking in fields for sensitive passwords and pins (Required)](#masking-in-fields-for-sensitive-passwords-and-pins-required)
1. [Implement with an understanding of how the application generates notifications and which data to display (Required)](#implement-with-an-understanding-of-how-the-application-generates-notifications-and-which-data-to-display-required)

#### Masking in fields for sensitive passwords and pins (Required)
Passwords and pins, which are confidential information, can be leaked by being displayed. Therefore, they should be masked or hidden in the field.

Below is a method for masking input fields.

For layouts:.
```xml
   <EditText
        android:id= @+id/Password
        android:inputType="textPassword" />
```

For code:.
```kotlin
val editText1: EditText = findViewById(R.id.editText1)
editText1.apply {
    inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD
}
```

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

#### Implement with an understanding of how the application generates notifications and which data to display (Required)

Use the [NotificationManager](https://developer.android.com/reference/android/app/NotificationManager) class to notify users of events that have occurred.

The components of the notification (display content) are specified in the [NotificationCompat.Builder](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) object.<br>
The NotificationCompat.Builder class provides methods for specifying the components of the notification. The following is an example of a method for specifying.

* setContentTitle ： In a standard notification, specify the title (first line) of the notification.
* setContentText ： In a standard notification, specify the text of the notification (second line).

The following is an example of source code that specifies the components of a notification to the NotificationCompat.Builder class and displays the notification using the NotificationManager class.

```kotlin
    var builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.notification_icon)
            .setContentTitle(textTitle)
            .setContentText(textContent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
    with(NotificationManagerCompat.from(this)) {
        // Pass notificationID and builder.build()
        notify(notificationID, builder.build())
    }
```

If this is violated, the following may occur.
* Third parties will be able to read confidential information.

## MSTG-STORAGE-12
The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app.	

### Testing User Education on Data Privacy on the App Marketplace
At this point, we're only interested in knowing which privacy-related information is being disclosed by the developers and trying to evaluate if it seems reasonable (similarly as you'd do when testing for permissions).

It's possible that the developers are not declaring certain information that is indeed being collected and or shared, but that's a topic for a different test extending this one here. As part of this test, you are not supposed to provide privacy violation assurance.

Reference
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Testing User Education on Data Privacy on the App Marketplace](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#testing-user-education-on-data-privacy-on-the-app-marketplace)

### Static Analysis
You can follow these steps:

1. Search for the app in the corresponding app marketplace (e.g. Google Play, App Store).
1. Go to the section ["Privacy Details"](https://developer.apple.com/app-store/app-privacy-details/) (App Store) or ["Safety Section"](https://developer.android.com/guide/topics/data/collect-share) (Google Play).
1. Verify if there's any information available at all.

The test passes if the developer has compiled with the app marketplace guidelines and included the required labels and explanations. Store and provide the information you got from the app marketplace as evidence, so that you can later use it to evaluate potential violations of privacy or data protection.

Reference
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Static Analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#static-analysis)

### Dynamic analysis
As an optional step, you can also provide some kind of evidence as part of this test. For instance, if you're testing an iOS app you can easily enable app activity recording and export a [Privacy Report](https://developer.apple.com/documentation/network/privacy_management/inspecting_app_activity_data) containing detailed app access to different resources such as photos, contacts, camera, microphone, network connections, etc.

Doing this has actually many advantages for testing other MASVS categories. It provides very useful information that you can use to [test network communication](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05g-Testing-Network-Communication.md) in MASVS-NETWORK or when [testing app permissions](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x05h-Testing-Platform-Interaction.md#testing-app-permissions-mstg-platform-1) in MASVS-PLATFORM. While testing these other categories you might have taken similar measurements using other testing tools. You can also provide this as evidence for this test.

Ideally, the information available should be compared against what the app is actually meant to do. However, that's far from a trivial task that could take from several days to weeks to complete depending on your resources and support from automated tooling. It also heavily depends on the app functionality and context and should be ideally performed on a white box setup working very closely with the app developers.

Reference
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Dynamic analysis](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#dynamic-analysis)

### Testing User Education on Security Best Practices
Testing this might be especially challenging if you intend to automate it. We recommend using the app extensively and try to answer the following questions whenever applicable:

* Fingerprint usage: when fingerprints are used for authentication providing access to high-risk transactions/information,
    does the app inform the user about potential issues when having multiple fingerprints of other people registered to the device as well?
* Rooting/Jailbreaking: when root or jailbreak detection is implemented,
    does the app inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device?
* Specific credentials: when a user gets a recovery code, a password or a pin from the application (or sets one),
    does the app instruct the user to never share this with anyone else and that only the app will request it?
* Application distribution: in case of a high-risk application and in order to prevent users from downloading compromised versions of the application,
    does the app manufacturer properly communicate the official way of distributing the app (e.g. from Google Play)?
* Prominent Disclosure: in any case,
    does the app display prominent disclosure of data access, collection, use, and sharing? e.g. does the app use the [Best practices for prominent disclosure and consent](https://support.google.com/googleplay/android-developer/answer/11150561?hl=en) to ask for the permission on Android?

Reference
* [owasp-mastg Testing User Education (MSTG-STORAGE-12) Testing User Education Testing User Education on Security Best Practices](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04i-Testing-User-Privacy-Protection.md#testing-user-education-on-security-best-practices)

Rulebook
* [Use the app extensively to answer questions about security best practices (Recommended)](#use-the-app-extensively-to-answer-questions-about-security-best-practices-recommended)

### Rulebook
1. [Use the app extensively to answer questions about security best practices (Recommended)](#use-the-app-extensively-to-answer-questions-about-security-best-practices-recommended)

#### Use the app extensively to answer questions about security best practices (Recommended)

It is recommended that the app be used extensively to answer the following questions regarding security best practices

* Fingerprint usage: when fingerprints are used for authentication providing access to high-risk transactions/information,
    does the app inform the user about potential issues when having multiple fingerprints of other people registered to the device as well?
* Rooting/Jailbreaking: when root or jailbreak detection is implemented,
    does the app inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device?
* Specific credentials: when a user gets a recovery code, a password or a pin from the application (or sets one),
    does the app instruct the user to never share this with anyone else and that only the app will request it?
* Application distribution: in case of a high-risk application and in order to prevent users from downloading compromised versions of the application,
    does the app manufacturer properly communicate the official way of distributing the app (e.g. from Google Play)?
* Prominent Disclosure: in any case,
    does the app display prominent disclosure of data access, collection, use, and sharing? e.g. does the app use the [Best practices for prominent disclosure and consent](https://support.google.com/googleplay/android-developer/answer/11150561?hl=en) to ask for the permission on Android?

If this is not noted, the following may occur.
* Confidential information is used in an unintended process.
* Third parties will be able to read confidential information.