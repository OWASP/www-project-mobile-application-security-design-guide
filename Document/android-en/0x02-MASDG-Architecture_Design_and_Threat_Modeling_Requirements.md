# Architecture, Design and Threat Modeling Requirements

## MSTG-ARCH-1
All app components are identified and known to be needed.

### Component
Get to know all the components of your application and remove unnecessary ones.<br>

The main types of components are as follows.
* Activity
* Fragment
* Intent
* BroadcastReceiver
* ContentProvider
* Service

## MSTG-ARCH-2
Security controls are never enforced only on the client side, but on the respective remote endpoints.

### Falsification of Authentication/Authorization information

#### Appropriate authentication response

Perform the following steps when testing authentication and authorization.

* Identify the additional authentication factors the app uses.
* Locate all endpoints that provide critical functionality.
* Verify that the additional factors are strictly enforced on all server-side endpoints.

Authentication bypass vulnerabilities exist when authentication state is not consistently enforced on the server and when the client can tamper with the state. While the backend service is processing requests from the mobile client, it must consistently enforce authorization checks: verifying that the user is logged in and authorized every time a resource is requested.

Consider the following example from the [OWASP Web Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema). In the example, a web resource is accessed through a URL, and the authentication state is passed through a GET parameter:

```
http://www.site.com/page.asp?authenticated=no
```

The client can arbitrarily change the GET parameters sent with the request. Nothing prevents the client from simply changing the value of the authenticated parameter to "yes", effectively bypassing authentication.<br>

Although this is a simplistic example that you probably won't find in the wild, programmers sometimes rely on "hidden" client-side parameters, such as cookies, to maintain authentication state. They assume that these parameters can't be tampered with. Consider, for example, the following [classic vulnerability in Nortel Contact Center Manager](http://seclists.org/bugtraq/2009/May/251). The administrative web application of Nortel's appliance relied on the cookie "isAdmin" to determine whether the logged-in user should be granted administrative privileges. Consequently, it was possible to get admin access by simply setting the cookie value as follows:<br>

```
isAdmin=True
```

Security experts used to recommend using session-based authentication and maintaining session data on the server only. This prevents any form of client-side tampering with the session state. However, the whole point of using stateless authentication instead of session-based authentication is to not have session state on the server. Instead, state is stored in client-side tokens and transmitted with every request. In this case, seeing client-side parameters such as isAdmin is perfectly normal.<br>


To prevent tampering cryptographic signatures are added to client-side tokens. Of course, things may go wrong, and popular implementations of stateless authentication have been vulnerable to attacks. For example, the signature verification of some JSON Web Token (JWT) implementations could be deactivated by [setting the signature type to "None"](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/). We'll discuss this attack in more detail in the "Testing JSON Web Tokens" chapter.<br>


Reference
* [owasp-mastg Verifying that Appropriate Authentication is in Place (MSTG-ARCH-2 and MSTG-AUCH-1)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#verifying-that-appropriate-authentication-is-in-place-mstg-arch-2-and-mstg-auth-1)


### Injection Flaws

An injection flaw describes a class of security vulnerability occurring when user input is inserted into backend queries or commands. By injecting meta-characters, an attacker can execute malicious code that is inadvertently interpreted as part of the command or query. For example, by manipulating a SQL query, an attacker could retrieve arbitrary database records or manipulate the content of the backend database.

Vulnerabilities of this class are most prevalent in server-side web services. Exploitable instances also exist within mobile apps, but occurrences are less common, plus the attack surface is smaller.

For example, while an app might query a local SQLite database, such databases usually do not store sensitive data (assuming the developer followed basic security practices). This makes SQL injection a non-viable attack vector. Nevertheless, exploitable injection vulnerabilities sometimes occur, meaning proper input validation is a necessary best practice for programmers.

Reference
* [owasp-mastg Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2)

Rulebook
* [Enforce appropriate input validation (Required)](#enforce-appropriate-input-validation-required)

#### SQL Injection

A SQL injection attack involves integrating SQL commands into input data, mimicking the syntax of a predefined SQL command. A successful SQL injection attack allows the attacker to read or write to the database and possibly execute administrative commands, depending on the permissions granted by the server.

Apps on both Android and iOS use SQLite databases as a means to control and organize local data storage. Assume an Android app handles local user authentication by storing the user credentials in a local database (a poor programming practice we’ll overlook for the sake of this example). Upon login, the app queries the database to search for a record with the username and password entered by the user:

```java
SQLiteDatabase db;

String sql = "SELECT * FROM users WHERE username = '" +  username + "' AND password = '" + password +"'";

Cursor c = db.rawQuery( sql, null );

return c.getCount() != 0;
```	

Let's further assume an attacker enters the following values into the "username" and "password" fields:

```sql
username = 1' or '1' = '1
password = 1' or '1' = '1
```	

This results in the following query:

```sql
SELECT * FROM users WHERE username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
```	

Because the condition '1' = '1' always evaluates as true, this query return all records in the database, causing the login function to return true even though no valid user account was entered.

Ostorlab exploited the sort parameter of [Yahoo's weather mobile application](https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html) with adb using this SQL injection payload.

Another real-world instance of client-side SQL injection was discovered by Mark Woods within the "Qnotes" and "Qget" Android apps running on QNAP NAS storage appliances. These apps exported content providers vulnerable to SQL injection, allowing an attacker to retrieve the credentials for the NAS device. A detailed description of this issue can be found on the [Nettitude Blog](https://blog.nettitude.com/uk/qnap-android-dont-provide).

Reference
* [owasp-mastg Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2) SQL Injection](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#sql-injection)

#### XML Injection

In a XML injection attack, the attacker injects XML meta-characters to structurally alter XML content. This can be used to either compromise the logic of an XML-based application or service, as well as possibly allow an attacker to exploit the operation of the XML parser processing the content.

A popular variant of this attack is [XML eXternal Entity (XXE)](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing). Here, an attacker injects an external entity definition containing an URI into the input XML. During parsing, the XML parser expands the attacker-defined entity by accessing the resource specified by the URI. 

The integrity of the parsing application ultimately determines capabilities afforded to the attacker, where the malicious user could do any (or all) of the following: access local files, trigger HTTP requests to arbitrary hosts and ports, launch a [cross-site request forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) attack, and cause a denial-of-service condition. The OWASP web testing guide contains the [following example for XXE](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection):


```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```	

In this example, the local file /dev/random is opened where an endless stream of bytes is returned, potentially causing a denial-of-service.

The current trend in app development focuses mostly on REST/JSON-based services as XML is becoming less common. However, in the rare cases where user-supplied or otherwise untrusted content is used to construct XML queries, it could be interpreted by local XML parsers, such as NSXMLParser on iOS. As such, said input should always be validated and meta-characters should be escaped.


Reference
* [owasp-mastg Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2) XML Injection](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#xml-injection)

Rulebook
* [Input should always be validated and meta-characters should be escaped (Required)](#input-should-always-be-validated-and-meta-characters-should-be-escaped-required)

#### Injection Attack Vectors

The attack surface of mobile apps is quite different from typical web and network applications. Mobile apps don't often expose services on the network, and viable attack vectors on an app's user interface are rare. Injection attacks against an app are most likely to occur through inter-process communication (IPC) interfaces, where a malicious app attacks another app running on the device.

Locating a potential vulnerability begins by either:


* Identifying possible entry points for untrusted input then tracing from those locations to see if the destination contains potentially vulnerable functions.
* Identifying known, dangerous library / API calls (e.g. SQL queries) and then checking whether unchecked input successfully interfaces with respective queries.

During a manual security review, you should employ a combination of both techniques. In general, untrusted inputs enter mobile apps through the following channels:

* IPC calls
* Custom URL schemes
* QR codes
* Input files received via Bluetooth, NFC, or other means
* Pasteboards
* User interface

Verify that the following best practices have been followed:

* Untrusted inputs are type-checked and/or validated using a list of acceptable values.
* Prepared statements with variable binding (i.e. parameterized queries) are used when performing database queries. If prepared statements are defined, user-supplied data and SQL code are automatically separated.
* When parsing XML data, ensure the parser application is configured to reject resolution of external entities in order to prevent XXE attack.
* When working with X.509 formatted certificate data, ensure that secure parsers are used. For instance Bouncy Castle below version 1.6 allows for Remote Code Execution by means of unsafe reflection.

We will cover details related to input sources and potentially vulnerable APIs for each mobile OS in the OS-specific testing guides.

Reference
* [owasp-mastg Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2) Injection Attack Vectors](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04h-Testing-Code-Quality.md#injection-attack-vectors)

Rulebook
* [Do not include potentially vulnerable functions in the destination (Required)](#do-not-include-potentially-vulnerable-functions-in-the-destination-required)
* [Unchecked inputs are successfully linked to their respective queries (Required)](#unchecked-inputs-are-successfully-linked-to-their-respective-queries-required)
* [Check for untrusted input (Required)](#check-for-untrusted-input-required)
* [Parser application is configured to refuse to resolve external entities (Required)](#parser-application-is-configured-to-refuse-to-resolve-external-entities-required)
* [Use a secure parser when using certificate data in X.509 format (Required)](#use-a-secure-parser-when-using-certificate-data-in-x509-format-required)

### Rulebook
1. [Enforce appropriate input validation (Required)](#enforce-appropriate-input-validation-required)
1. [Input should always be validated and meta-characters should be escaped (Required)](#input-should-always-be-validated-and-meta-characters-should-be-escaped-required)
1. [Do not include potentially vulnerable functions in the destination (Required)](#do-not-include-potentially-vulnerable-functions-in-the-destination-required)
1. [Unchecked inputs are successfully linked to their respective queries (Required)](#unchecked-inputs-are-successfully-linked-to-their-respective-queries-required)
1. [Check for untrusted input (Required)](#check-for-untrusted-input-required)
1. [Parser application is configured to refuse to resolve external entities (Required)](#parser-application-is-configured-to-refuse-to-resolve-external-entities-required)
1. [Use a secure parser when using certificate data in X.509 format (Required)](#use-a-secure-parser-when-using-certificate-data-in-x509-format-required)

#### Enforce appropriate input validation (Required)
Proper input validation is a necessary best practice for programmers, as injection vulnerabilities can be exploited.

Below is an example of input validation.
* Regular expression check
* Length/size check

If this is violated, the following may occur.
* An injection vulnerability may be exploited.

#### Input should always be validated and meta-characters should be escaped (Required)

If an XML query is created using user-supplied or untrusted content, XML metacharacters may be interpreted as XML content by the local XML parser.Therefore, input should always be validated and meta-characters should be escaped.

Below is an example of input validation.
* Regular expression check
* Length/size check

Below is an example of a meta-character.
| Character | Item Name | Entity Reference Notation |
| :--- | :--- | :--- |
| \< | Right Greater Than | \&lt; |
| \> | Left Greater Than | \&gt; |
| \& | Ampersand | \&amp; |
| \" | Double Quotation | \&quot; |
| \' | Single Quotation | \&apos; |

If this is violated, the following may occur.
* XML meta characters may be interpreted as XML content by the local XML parser.

#### Do not include potentially vulnerable functions in the destination (Required)
Identify potential entry points for untrusted inputs and trace from that location to see if the destination contains potentially vulnerable functions (third-party functions).

If this is violated, the following may occur.
* A malicious app could attack another app running on the device via the Inter-Process Communication (IPC) interface.

#### Unchecked inputs are successfully linked to their respective queries (Required)
Identify known dangerous library /API calls (e.g., SQL queries) and verify that unchecked inputs work with the respective queries successfully.
Also, check the reference of the library/API to be used and confirm that it is not deprecated.

Android API Reference：[https://developer.android.com/](https://developer.android.com/)

If this is violated, the following may occur.
* A malicious app could attack another app running on the device via the Inter-Process Communication (IPC) interface.

#### Check for untrusted input (Required)
In general, untrusted inputs enter mobile apps through the following channels:

Below is an example of keywords that identify channel use.
* IPC calls： ContentProvider
* Custom URL schemes： scheme
* QR codes： qr, camera
* Input files received via Bluetooth, NFC, or other means： bluetoothAdapter
* Pasteboards： ClipboardManager
* User interface：EditText

If this is violated, the following may occur.
* A malicious app could attack another app running on the device via the Inter-Process Communication (IPC) interface.

#### Parser application is configured to refuse to resolve external entities (Required)
To prevent XXE attacks, parser applications should be configured to refuse to resolve external entities.

The safest way to prevent XXE is always to disable DTDs (External Entities) completely. Depending on the parser, the method should be similar to the following:

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Disabling [DTD](https://www.w3schools.com/xml/xml_dtd.asp) also makes the parser secure against denial of services (DOS) attacks such as [Billion Laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack). If it is not possible to disable DTDs completely, then external entities and external document type declarations must be disabled in the way that's specific to each parser.

If this is violated, the following may occur.
* Be vulnerable to XXE attacks.

Reference
* [OWASP Cheat Sheet Series XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#general-guidance)

#### Use a secure parser when using certificate data in X.509 format (Required)
Use a secure parser when handling X.509 format certificate data.

Below is an example of a safe parser.
* Bouncy Castle (Version 1.6 or higher)

If this is violated, the following may occur.
* Vulnerable to injection attacks, such as remote code execution via insecure reflection.

## MSTG-ARCH-3
A high-level architecture for the mobile app and all connected remote services has been defined and security has been addressed in that architecture.

<span style="color: red; ">\* Guide description is omitted in this document as this chapter is about support on the remote service side.</span>

## MSTG-ARCH-4
Data considered sensitive in the context of the mobile app is clearly identified.<br>

Classifications of sensitive information differ by industry and country. In addition, organizations may take a restrictive view of sensitive data, and they may have a data classification policy that clearly defines sensitive information.<br>
If a data classification policies is not available, use the following list of information generally considered sensitive.

Reference
* [owasp-mastg Penetration Testing (a.k.a. Pentesting) Identifying Sensitive Data](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data)

Rulebook
* [Identify sensitive data according to data classification policies (Required)](#identify-sensitive-data-according-to-data-classification-policies-required)

### User authentication information

User authentication information (credentials, PIN, etc.).

### Personally Identifiable Information

Personally Identifiable Information (PII) that can be abused for identity theft: social security numbers, credit card numbers, bank account numbers, health information.

### Device Identifier

Device identifiers that may identify a person

### Sensitive data

Highly sensitive data whose compromise would lead to reputational harm and/or financial costs.

### Data whose protection is a legal obligation

Data whose protection is a legal obligation.

### Technical data

Technical data generated by the app (or its related systems) and used to protect other data or the system itself (e.g., encryption keys).

### Rulebook
1. [Identify sensitive data according to data classification policies (Required)](#identify-sensitive-data-according-to-data-classification-policies-required)

#### Identify sensitive data according to data classification policies (Required)
Identify sensitive data according to a data classification policy that is clearly defined by the industry, country, and organization. If a data classification policy is not available, use the following list of information generally considered confidential.

* User authentication information (credentials, PINs, etc.)
* Personally Identifiable Information (PII) that can be abused for identity theft: social security numbers, credit card numbers, bank account numbers, health information
* Device identifiers that may identify a person
* Highly sensitive data whose compromise would lead to reputational harm and/or financial costs
* Data whose protection is a legal obligation
* Technical data generated by the app (or its related systems) and used to protect other data or the system itself (e.g., encryption keys).

A definition of "sensitive data" must be decided before testing begins because detecting sensitive data leakage without a definition may be impossible.

If this is violated, the following may occur.
* Sensitive data that could be compromised based on the results of penetration testing may not be recognized as sensitive data, and may not be identified and addressed as a risk.

## MSTG-ARCH-12
The app should comply with privacy laws and regulations.

### General Privacy Laws and Regulations

Reference
* [V6.1 Data Classification](https://github.com/OWASP/ASVS/raw/v4.0.3/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.pdf)

#### Personal Information and Privacy
If personal information is handled, it must comply with GDPR and Act on the Protection of Personal Information.

#### Medical Data
If medical data is handled, it must be HIPAA and HITECH compliant.

#### Financial Information
**Credit Card Information**

If credit card information is handled, it must be PCI DSS compliant.

### Privacy rules on Google Play
We’re committed to protecting user privacy and providing a safe and secure environment for our users. Apps that are deceptive, malicious, or intended to abuse or misuse any network, device, or personal data are strictly prohibited.

Reference
* [Google Play Policy Center Privacy, Deception and Device Abuse](https://support.google.com/googleplay/android-developer/topic/9877467?hl=en)

#### User Data
You must be transparent in how you handle user data (for example, information collected from or about a user, including device information). That means disclosing the access, collection, use, handling, and sharing of user data from your app, and limiting the use of the data to the policy compliant purposes disclosed. Please be aware that any handling of personal and sensitive user data is also subject to additional requirements in the "Personal and Sensitive User Data" section below. These Google Play requirements are in addition to any requirements prescribed by applicable privacy and data protection laws.

If you include third party code (for example, an SDK) in your app, you must ensure that the third party code used in your app, and that third party’s practices with respect to user data from your app, are compliant with Google Play Developer Program policies, which include use and disclosure requirements. For example, you must ensure that your SDK providers do not sell personal and sensitive user data from your app. This requirement applies regardless of whether user data is transferred after being sent to a server, or by embedding third-party code in your app.

**Personal and Sensitive User Data**

Personal and sensitive user data includes, but isn't limited to, personally identifiable information, financial and payment information, authentication information, phonebook, contacts, [device location](https://developer.android.com/training/location), SMS and call related data, [health data](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en#type-health-info&zippy=data-types), [Health Connect](https://support.google.com/googleplay/android-developer/answer/9888170#ahp) data, inventory of other apps on the device, microphone, camera, and other sensitive device or usage data. If your app handles personal and sensitive user data, then you must:

* Limit the access, collection, use, and sharing of personal and sensitive user data acquired through the app to app and service functionality and policy conforming purposes reasonably expected by the user:
  * Apps that extend usage of personal and sensitive user data for serving advertising must comply with Google Play’s [Ads Policy](https://support.google.com/googleplay/android-developer/answer/9857753#location-data).
  * You may also transfer data as necessary to [service providers](https://support.google.com/googleplay/android-developer/answer/10787469#service-provider&zippy=%2Csharing%2Cdata-sharing) or for legal reasons such as to comply with a valid governmental request, applicable law, or as part of a merger or acquisition with legally adequate notice to users.
* Handle all personal and sensitive user data securely, including transmitting it using modern cryptography (for example, over HTTPS).
* Use a runtime permissions request whenever available, prior to accessing data gated by [Android permissions](https://developer.android.com/guide/topics/permissions/overview).
* Not sell personal and sensitive user data.
  * "Sale" means the exchange or transfer of personal and sensitive user data to a [third party](https://support.google.com/googleplay/android-developer/answer/10787469#first-and-third&zippy=%2Csharing%2Cdata-sharing) for monetary consideration.
    * User-initiated transfer of personal and sensitive user data (for example, when the user is using a feature of the app to transfer a file to a third party, or when the user chooses to use a dedicated purpose research study app), is not regarded as sale.

**Prominent Disclosure & Consent Requirement**

In cases where your app’s access, collection, use, or sharing of personal and sensitive user data may not be within the reasonable expectation of the user of the product or feature in question (for example, if data collection occurs in the background when the user is not engaging with your app), you must meet the following requirements:

**Prominent disclosure: You must provide an in-app disclosure of your data access, collection, use, and sharing. The in-app disclosure:**

* Must be within the app itself, not only in the app description or on a website;
* Must be displayed in the normal usage of the app and not require the user to navigate into a menu or settings;
* Must describe the data being accessed or collected;
* Must explain how the data will be used and/or shared;
* Cannot only be placed in a privacy policy or terms of service; and
* Cannot be included with other disclosures unrelated to personal and sensitive user data collection.

**Consent and runtime permissions: Requests for in-app user consent and runtime permission requests must be immediately preceded by an in-app disclosure that meets the requirement of this policy. The app's request for consent:**

* Must present the consent dialog clearly and unambiguously;
* Must require affirmative user action (for example, tap to accept, tick a check-box);
* Must not interpret navigation away from the disclosure (including tapping away or pressing the back or home button) as consent;
* Must not use auto-dismissing or expiring messages as a means of obtaining user consent; and
* Must be granted by the user before your app can begin to collect or access the personal and sensitive user data.

Apps that rely on other legal bases to process personal and sensitive user data without consent, such as a legitimate interest under the EU GDPR, must comply with all applicable legal requirements and provide appropriate disclosures to the users, including in-app disclosures as required under this policy.

To meet policy requirements, it’s recommended that you reference the following example format for Prominent Disclosure when it’s required:
* "This app" collects/transmits/syncs/stores "type of data" to enable  "feature", "in what scenario."
* Example: “Fitness Funds collects location data to enable fitness tracking even when the app is closed or not in use and is also used to support advertising.” 
* Example: “Call buddy collects read and write call log data to enable contact organization even when the app is not in use.”

If your app integrates third party code (for example, an SDK) that is designed to collect personal and sensitive user data by default, you must, within 2 weeks of receipt of a request from Google Play (or, if Google Play’s request provides for a longer time period, within that time period), provide sufficient evidence demonstrating that your app meets the Prominent Disclosure and Consent requirements of this policy, including with regard to the data access, collection, use, or sharing via the third party code.

**Examples of Common Violations**

* An app collects device location but does not have a prominent disclosure explaining which feature uses this data and/or indicates the app’s usage in the background.
* An app has a runtime permission requesting access to data before the prominent disclosure which specifies what the data is used for.
* An app that accesses a user's inventory of installed apps and doesn't treat this data as personal or sensitive data subject to the above Privacy Policy, data handling, and Prominent Disclosure and Consent requirements.
* An app that accesses a user's phone or contact book data and doesn't treat this data as personal or sensitive data subject to the above Privacy Policy, data handling, and Prominent Disclosure and Consent requirements.
* An app that records a user’s screen and doesn't treat this data as personal or sensitive data subject to this policy.
* An app that collects [device location](https://developer.android.com/training/location) and does not comprehensively disclose its use and obtain consent in accordance with the above requirements.
* An app that uses restricted permissions in the background of the app including for tracking, research, or marketing purposes and does not comprehensively disclose its use and obtain consent in accordance with the above requirements. 
* An app with an SDK that collects personal and sensitive user data and doesn’t treat this data as subject to this User Data Policy, access, data handling (including disallowed sale), and prominent disclosure and consent requirements.

Refer to this [article](https://support.google.com/googleplay/android-developer/answer/11150561) for more information on the Prominent Disclosure and Consent requirement.

**Restrictions for Personal and Sensitive Data Access**

In addition to the requirements above, the table below describes requirements for specific activities.
| Activity | Requirement |
| :--- | :--- |
| Your app handles financial or payment information or government identification numbers | Your app must never publicly disclose any personal and sensitive user data related to financial or payment activities or any government identification numbers. |
| Your app handles non-public phonebook or contact information | We don't allow unauthorized publishing or disclosure of people's non-public contacts. |
| Your app contains anti-virus or security functionality, such as anti-virus, anti-malware, or security-related features | Your app must post a privacy policy that, together with any in-app disclosures, explain what user data your app collects and transmits, how it's used, and the type of parties with whom it's shared. |
| Your app targets children | Your app must not include an SDK that is not approved for use in child-directed services. See [Designing Apps for Children and Families](https://support.google.com/googleplay/android-developer/answer/9893335) for full policy language and requirements. |
| Your app collects or links persistent device identifiers (e.g., IMEI, IMSI, SIM Serial #, etc.) | Persistent device identifiers may not be linked to other personal and sensitive user data or resettable device identifiers except for the purposes of <br><br>・Telephony linked to a SIM identity (e.g., wifi calling linked to a carrier account), and<br>・Enterprise device management apps using device owner mode.<br><br>These uses must be prominently disclosed to users as specified in the [User Data Policy](https://support.google.com/googleplay/android-developer/answer/10144311). <br>Please [consult this resource](https://developer.android.com/training/articles/user-data-ids) for alternative unique identifiers.<br>Please read the [Ads policy](https://support.google.com/googleplay/android-developer/answer/9857753) for additional guidelines for Android Advertising ID.|

**Data safety section**

All developers must complete a clear and accurate Data safety section for every app detailing collection, use, and sharing of user data. The developer is responsible for the accuracy of the label and keeping this information up-to-date. Where relevant, the section must be consistent with the disclosures made in the app’s privacy policy. 

Please refer to [this article](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en#zippy=%2Cdata-types) for additional information on completing the Data safety section.

**Privacy Policy**

All apps must post a privacy policy link in the designated field within Play Console, and a privacy policy link or text within the app itself. The privacy policy must, together with any in-app disclosures, comprehensively disclose how your app accesses, collects, uses, and shares user data, not limited by the data disclosed in the privacy label. This must include: 

* Developer information and a privacy point of contact or a mechanism to submit inquiries.
* Disclosing the types of personal and sensitive user data your app accesses, collects, uses, and shares; and any parties with which any personal or sensitive user data is shared.
* Secure data handling procedures for personal and sensitive user data.
* The developer’s data retention and deletion policy.
* Clear labeling as a privacy policy (for example, listed as “privacy policy” in title).

The entity (for example, developer, company) named in the app’s Google Play store listing must appear in the privacy policy or the app must be named in the privacy policy. Apps that do not access any personal and sensitive user data must still submit a privacy policy.

Please make sure your privacy policy is available on an active, publicly accessible and non-geofenced URL (no PDFs) and is non-editable.

**Usage of App Set ID**

Android will introduce a new ID to support essential use cases such as analytics and fraud prevention. Terms for the use of this ID are below.

* Usage: App set ID must not be used for ads personalization and ads measurement. 
* Association with personally-identifiable information or other identifiers: App set ID may not be connected to any Android identifiers (e.g., AAID) or any personal and sensitive data for advertising purposes.
* Transparency and consent: The collection and use of the app set ID and commitment to these terms must be disclosed to users in a legally adequate privacy notification, including your privacy policy. You must obtain users’ legally valid consent where required. To learn more about our privacy standards, please review our [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311).

**EU-U.S., Swiss Privacy Shield**

If you access, use, or process personal information made available by Google that directly or indirectly identifies an individual and that originated in the European Union or Switzerland (“EU Personal Information”), then you must:

* Comply with all applicable privacy, data security, and data protection laws, directives, regulations, and rules;
* Access, use or process EU Personal Information only for purposes that are consistent with the consent obtained from the individual to whom the EU Personal Information relates;
* Implement appropriate organizational and technical measures to protect EU Personal Information against loss, misuse, and unauthorized or unlawful access, disclosure, alteration and destruction; and
* Provide the same level of protection as is required by the [Privacy Shield Principles](https://www.privacyshield.gov/EU-US-Framework).

You must monitor your compliance with these conditions on a regular basis. If, at any time, you cannot meet these conditions (or if there is a significant risk that you will not be able to meet them), you must immediately notify us by email to data-protection-office@google.com and immediately either stop processing EU Personal Information or take reasonable and appropriate steps to restore an adequate level of protection.

As of July 16, 2020, Google no longer relies on the EU-U.S. Privacy Shield to transfer personal data that originated in the European Economic Area or the UK to the United States. ([Learn More](https://policies.google.com/privacy/frameworks?hl=en).)  More information is set forth in Section 9 of the DDA.

Reference
* [Google Play Developer Policy Center User Data](https://support.google.com/googleplay/android-developer/answer/10144311?hl=en&ref_topic=9877467)

#### Permissions and APIs that Access Sensitive Information
Requests for permission and APIs that access sensitive information should make sense to users. You may only request permissions and APIs that access sensitive information that are necessary to implement current features or services in your app that are promoted in your Google Play listing. You may not use permissions or APIs that access sensitive information that give access to user or device data for undisclosed, unimplemented, or disallowed features or purposes. Personal or sensitive data accessed through permissions or APIs that access sensitive information may never be sold nor shared for a purpose facilitating sale.

Request permissions and APIs that access sensitive information to access data in context (via incremental requests), so that users understand why your app is requesting the permission. Use the data only for purposes that the user has consented to. If you later wish to use the data for other purposes, you must ask users and make sure they affirmatively agree to the additional uses.

**Restricted Permissions**

In addition to the above, restricted permissions are permissions that are designated as [Dangerous](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions), [Special](https://developer.android.com/guide/topics/permissions/overview#special_permissions),  [Signature](https://developer.android.com/guide/topics/permissions/overview#signature_permissions), or as documented below. These permissions are subject to the following additional requirements and restrictions:

* User or device data accessed through Restricted Permissions is considered as personal and sensitive user data. The requirements of the [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311) apply.
* Respect users’ decisions if they decline a request for a Restricted Permission, and users may not be manipulated or forced into consenting to any non-critical permission. You must make a reasonable effort to accommodate users who do not grant access to sensitive permissions (for example, allowing a user to manually enter a phone number if they’ve restricted access to Call Logs).
* Use of permissions in violation of Google Play [malware policies](https://support.google.com/googleplay/android-developer/answer/9888380) (including [Elevated Privilege Abuse](https://support.google.com/googleplay/android-developer/answer/9888380)) is expressly prohibited.

Certain Restricted Permissions may be subject to additional requirements as detailed below. The objective of these restrictions is to safeguard user privacy. We may make limited exceptions to the requirements below in very rare cases where apps provide a highly compelling or critical feature and where there is no alternative method available to provide the feature. We evaluate proposed exceptions against the potential privacy or security impacts on users.

**SMS and Call Log Permissions**

SMS and Call Log Permissions are regarded as personal and sensitive user data subject to the [Personal and Sensitive Information](https://support.google.com/googleplay/android-developer/answer/10144311) policy, and the following restrictions:

| Restricted Permission | Requirement |
| :--- | :--- |
| Call Log permission group (e.g. READ_CALL_LOG, WRITE_CALL_LOG, PROCESS_OUTGOING_CALLS) | It must be actively registered as the default Phone or Assistant handler on the device. |
| SMS permission group (e.g. READ_SMS, SEND_SMS, WRITE_SMS, RECEIVE_SMS, RECEIVE_WAP_PUSH, RECEIVE_MMS) | It must be actively registered as the default SMS or Assistant handler on the device. |

Apps lacking default SMS, Phone, or Assistant handler capability may not declare use of the above permissions in the manifest. This includes placeholder text in the manifest. Additionally, apps must be actively registered as the default SMS, Phone, or Assistant handler before prompting users to accept any of the above permissions and must immediately stop using the permission when they’re no longer the default handler. The permitted uses and exceptions are available on [this Help Center page](https://support.google.com/googleplay/android-developer/answer/10208820).

Apps may only use the permission (and any data derived from the permission) to provide approved core app functionality Core functionality is defined as the main purpose of the app. This may include a set of core features, which must all be prominently documented and promoted in the app’s description. Without the core feature(s), the app is “broken” or rendered unusable. The transfer, sharing, or licensed use of this data must only be for providing core features or services within the app, and its use may not be extended for any other purpose (e.g., improving other apps or services, advertising, or marketing purposes). You may not use alternative methods (including other permissions, APIs, or third-party sources) to derive data attributed to Call Log or SMS related permissions.

**Location Permissions**

[Device location](https://developer.android.com/training/location) is regarded as personal and sensitive user data subject to the [Personal and Sensitive Information](https://support.google.com/googleplay/android-developer/answer/10144311) policy and the [Background Location policy](https://support.google.com/googleplay/android-developer/answer/9799150?hl=en#zippy=), and the following requirements:

* Apps may not access data protected by location permissions (e.g., ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION) after it is no longer necessary to deliver current features or services in your app.
* You should never request location permissions from users for the sole purpose of advertising or analytics. Apps that extend permitted usage of this data for serving advertising must be in compliance with our [Ads Policy](https://support.google.com/googleplay/android-developer/answer/9857753).
* Apps should request the minimum scope necessary (i.e., coarse instead of fine, and foreground instead of background) to provide the current feature or service requiring location and users should reasonably expect that the feature or service needs the level of location requested. For example, we may reject apps that request or access background location without compelling justification.
Background location may only be used to provide features beneficial to the user and relevant to the core functionality of the app.

Apps are allowed to access location using foreground service (when the app only has foreground access e.g., "while in use") permission if the use:

* has been initiated as a continuation of an in-app user-initiated action, and
* is terminated immediately after the intended use case of the user-initiated action is completed by the application.

Apps designed specifically for children must comply with the [Designed for Families](https://support.google.com/googleplay/android-developer/answer/9893335#designed_for_families_prog) policy.

For more information on the policy requirements, please see [this help article](https://support.google.com/googleplay/android-developer/answer/9799150?hl=en&ref_topic=2364761).

**All Files Access Permission**

Files and directory attributes on a user’s device are regarded as personal and sensitive user data subject to the [Personal and Sensitive Information](https://support.google.com/googleplay/android-developer/answer/10144311) policy and the following requirements:

* Apps should only request access to device storage which is critical for the app to function, and may not request access to device storage on behalf of any third-party for any purpose that is unrelated to critical user-facing app functionality.
* Android devices running R or later, will require the [MANAGE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#MANAGE_EXTERNAL_STORAGE) permission in order to manage access in shared storage. All apps that target R and request broad access to shared storage (“All files access”) must successfully pass an appropriate access review prior to publishing. Apps allowed to use this permission must clearly prompt users to enable “All files access” for their app under “Special app access” settings. For more information on the R requirements, please see this [help article](https://support.google.com/googleplay/android-developer/answer/9956427).

**Package (App) Visibility Permission**

The inventory of installed apps queried from a device are regarded as personal and sensitive user data subject to the [Personal and Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888076/) policy,  and the following requirements:

Apps that have a core purpose to launch, search, or interoperate with other apps on the device, may obtain scope-appropriate visibility to other installed apps on the device as outlined below:

* **Broad app visibility**: Broad visibility is the capability of an app to have extensive (or “broad”) visibility of the installed apps (“packages”) on a device.
  * For apps targeting [API level 30 or later](https://developer.android.com/studio/releases/platforms), broad visibility to installed apps via the [QUERY_ALL_PACKAGES](https://developer.android.com/reference/kotlin/android/Manifest.permission#query_all_packages) permission is restricted to specific use cases where awareness of and/or interoperability with any and all apps on the device are required for the app to function. 
    * You may not use QUERY_ALL_PACKAGES if your app can operate with a more [targeted scoped package visibility declaration](https://developer.android.com/training/basics/intents/package-visibility#declare-other-apps)(e.g. querying and interacting with specific packages instead of requesting broad visibility).
  * Use of alternative methods to approximate the broad visibility level associated with QUERY_ALL_PACKAGES permission are also restricted to user-facing core app functionality and interoperability with any apps discovered via this method.
  * Please see this [Help Center article](https://support.google.com/googleplay/android-developer/answer/10158779) for allowable use cases for the QUERY_ALL_PACKAGES permission.
* **Limited app visibility**: Limited visibility is when an app minimizes access to data by querying for specific apps using more targeted (instead of “broad”) methods (e.g. querying for specific apps that satisfy your app’s manifest declaration). You may use this method to query for apps in cases where your app has policy compliant interoperability, or management of these apps. 
* Visibility to the inventory of installed apps on a device must be directly related to the core purpose or core functionality that users access within your app. 

App inventory data queried from Play-distributed apps may never be sold nor shared for analytics or ads monetization purposes.

**Accessibility API**

The Accessibility API cannot be used to:

* Change user settings without their permission or prevent the ability for users to disable or uninstall any app or service unless authorized by a parent or guardian through a parental control app or by authorized administrators through enterprise management software; 
* Work around Android built-in privacy controls and notifications; or
* Change or leverage the user interface in a way that is deceptive or otherwise violates Google Play Developer Policies. 

The Accessibility API is not designed and cannot be requested for remote call audio recording. 

The use of the Accessibility API must be documented in the Google Play listing.

**Guidelines for IsAccessibilityTool**

Apps with a core functionality intended to directly support people with disabilities are eligible to use the **IsAccessibilityTool** to appropriately publicly designate themselves as an accessibility app.

Apps not eligible for **IsAccessibilityTool** may not use the flag and must meet prominent disclosure and consent requirements as outlined in the [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311?hl=en&ref_topic=9877467) as the accessibility related functionality is not obvious to the user. Please refer to the [AccessibilityService API](https://support.google.com/googleplay/android-developer/answer/10964491?hl=en) help center article for more information.

Apps must use more narrowly scoped [APIs and permissions](https://developer.android.com/privacy/best-practices#permissions) in lieu of the Accessibility API when possible to achieve the desired functionality.

**Request Install Packages Permission**

The [REQUEST_INSTALL_PACKAGES](https://developer.android.com/reference/android/Manifest.permission#REQUEST_INSTALL_PACKAGES) permission allows an application to request the installation of app packages.​​ To use this permission, your app’s core functionality must include: 

* Sending or receiving app packages; and
* Enabling user-initiated installation of app packages. 

Permitted functionalities include:

* Web browsing or search; or
* Communication services that support attachments; or
* File sharing, transfer or management; or
* Enterprise device management. 
* Backup & restore
* Device Migration / Phone Transfer

Core functionality is defined as the main purpose of the app. The core functionality, as well as any core features that comprise this core functionality, must all be prominently documented and promoted in the app's description. 

The REQUEST_INSTALL_PACKAGES permission may not be used to perform self updates, modifications, or the bundling of other APKs in the asset file unless for device management purposes. All updates or installing of packages must abide by Google Play’s [Device and Network Abuse](https://support.google.com/googleplay/android-developer/answer/9888379?hl=en&ref_topic=9877467) policy and must be initiated and driven by the user.

**Health Connect by Android Permissions**

Data accessed through Health Connect Permissions is regarded as personal and sensitive user data subject to the [User Data](https://support.google.com/googleplay/android-developer/answer/10144311#personal-sensitive) policy, and the following additional requirements:

**Appropriate Access to and Use of Health Connect**

Requests to access data through Health Connect must be clear and understandable. Health Connect may only be used in accordance with the applicable policies, terms and conditions, and for approved use cases as set forth in this policy. This means you may only request access to permissions when your application or service meets one of the approved use cases.

Approved use cases for access to Health Connect Permissions are:

* Applications or services with one or more features to benefit users' health and fitness via a user interface allowing users to directly **journal, report, monitor, and/or analyze** their physical activity, sleep, mental well-being, nutrition, health measurements, physical descriptions, and/or other health or fitness-related descriptions and measurements.
* Applications or services with one or more features to benefit users' health and fitness via a user interface allowing users to **store** their physical activity, sleep, mental well-being, nutrition, health measurements, physical descriptions, and/or other health or fitness-related descriptions and measurements on their phone and/or wearable, and share their data with other on-device apps that satisfy these use cases.

Health Connect is a general purpose data storage and sharing platform that allows users to aggregate health and fitness data from various sources on their Android device and share it with third parties at their election. The data may originate from various sources as determined by the users. Developers must assess whether Health Connect is appropriate for their intended use and to investigate and vet the source and quality of any data from Health Connect in connection with any purpose, and, in particular, for research, health, or medical uses.

* Apps conducting health-related human subject research using data obtained through Health Connect must obtain consent from participants or, in the case of minors, their parent or guardian. Such consent must include the (a) nature, purpose, and duration of the research; (b) procedures, risks, and benefits to the participant; (c) information about confidentiality and handling of data (including any sharing with third parties); (d) a point of contact for participant questions; and (e) the withdrawal process. Apps conducting health-related human subject research using data obtained through Health Connect must receive approval from an independent board whose aim is 1) to protect the rights, safety, and well-being of participants and 2) with the authority to scrutinize, modify, and approve human subjects research. Proof of such approval must be provided upon request.
* It is also your responsibility for ensuring compliance with any regulatory or legal requirements that may apply based on your intended use of Health Connect and any data from Health Connect. Except as explicitly noted in the labeling or information provided by Google for specific Google products or services, Google does not endorse the use of or warrant the accuracy of any data contained in Health Connect for any use or purpose, and, in particular, for research, health, or medical uses. Google disclaims all liability associated with use of data obtained through Health Connect.

**Limited Use**

Upon using Health Connect for an appropriate use, your use of the data accessed through Health Connect must also comply with the below requirements. These requirements apply to the raw data obtained from Health Connect, and data aggregated, de-identified, or derived from the raw data.

* Limit your use of Health Connect data to providing or improving your appropriate use case or features that are visible and prominent in the requesting application's user interface.
* Only transfer user data to third parties:
  * To provide or improve your appropriate use case or features that are clear from the requesting application's user interface and only with the user’s consent;
  * If necessary for security purposes (for example, investigating abuse);
  * To comply with applicable laws and/or regulations; or,
  * As part of a merger, acquisition or sale of assets of the developer after obtaining explicit prior consent from the user.
* Do not allow humans to read user data, unless:
  * The user's explicit consent to read specific data is obtained;
  * It’s necessary for security purposes (for example, investigating abuse);
  * To comply with applicable laws; or,
  * The data (including derivations) is aggregated and used for internal operations in accordance with applicable privacy and other jurisdictional legal requirements.

All other transfers, uses, or sale of Health Connect data is prohibited, including:
* Transferring or selling user data to third parties like advertising platforms, data brokers, or any information resellers.
* Transferring, selling, or using user data for serving ads, including personalized or interest-based advertising.
* Transferring, selling, or using user data to determine credit-worthiness or for lending purposes.
* Transferring, selling, or using the user data with any product or service that may qualify as a medical device pursuant to Section 201(h) of the Federal Food Drug & Cosmetic Act if the user data will be used by the medical device to perform its regulated function.
* Transferring, selling, or using user data for any purpose or in any manner involving Protected Health Information (as defined by HIPAA) unless you receive prior written approval to such use from Google.

Access to Health Connect may not be used in violation of this policy or other applicable Health Connect terms and conditions or policies, including for the following purposes:
* Do not use Health Connect in developing, or for incorporation into, applications, environments or activities where the use or failure of Health Connect could reasonably be expected to lead to death, personal injury, or environmental or property damage (such as the creation or operation of nuclear facilities, air traffic control, life support systems, or weaponry).
* Do not access data obtained through Health Connect using headless apps. Apps must display a clearly identifiable icon in the app tray, device app settings, notification icons, etc.
* Do not use Health Connect with apps that sync data between incompatible devices or platforms.
* Health Connect cannot connect to applications, services or features that solely target children. Health Connect is not approved for use in primarily child-directed services.

An affirmative statement that your use of Health Connect data complies with Limited Use restrictions must be disclosed in your application or on a website belonging to your web-service or application; for example, a link on a homepage to a dedicated page or privacy policy noting: “The use of information received from Health Connect will adhere to the Health Connect Permissions policy, including the [Limited Use requirements](https://support.google.com/googleplay/android-developer/answer/11995078#limited_use_preview).”

**Minimum Scope**

You may only request access to permissions that are critical to implementing your application or service's functionality. 

This means:

* Don't request access to information that you don't need. Only request access to the permissions necessary to implement your product's features or services. If your product does not require access to specific permissions, then you must not request access to these permissions.

**Transparent and Accurate Notice and Control**

Health Connect handles health and fitness data, which includes personal and sensitive information. All applications and services must contain a privacy policy, which must comprehensively disclose how your application or service collects, uses, and shares user data. This includes the types of parties to which any user data is shared, how you use the data, how you store and secure the data, and what happens to the data when an account is deactivated and/or deleted.

In addition to the requirements under applicable law, you must also adhere to the following requirements:

* You must provide a disclosure of your data access, collection, use, and sharing. The disclosure:
  * Must accurately represent the identity of the application or service that seeks access to user data;
  * Must provide clear and accurate information explaining the types of data being accessed, requested, and/or collected;
  * Must explain how the data will be used and/or shared: if you request data for one reason, but the data will also be utilized for a secondary purpose, you must notify users of both use cases.
* You must provide user help documentation that explains how users can manage and delete their data from your app.

**Secure Data Handling**

You must handle all user data securely. Take reasonable and appropriate steps to protect all applications or systems that make use of Health Connect against unauthorized or unlawful access, use, destruction, loss, alteration, or disclosure.

Recommended security practices include implementing and maintaining an Information Security Management System such as outlined in ISO/IEC 27001 and ensuring your application or web service is robust and free from common security issues as set out by the OWASP Top 10.

Depending on the API being accessed and number of user grants or users, we will require that your application or service undergo a periodic security assessment and obtain a Letter of Assessment from a designated third party if your product transfers data off the user's own device.

For more information on requirements for apps connecting to Health Connect, please see this [help article](https://support.google.com/googleplay/android-developer/answer/12991134).

**VPN Service**

The [VpnService](https://developer.android.com/reference/android/net/VpnService) is a base class for applications to extend and build their own VPN solutions. Only apps that use the VpnService and have VPN as their core functionality can create a secure device-level tunnel to a remote server. Exceptions include apps that require a remote server for core functionality such as:

* Parental control and enterprise management apps.
* App usage tracking.
* Device security apps (for example, anti-virus, mobile device management, firewall).
* Network related tools (for example, remote access).
* Web browsing apps.
* Carrier apps that require the use of VPN functionality to provide telephony or connectivity services.

The VpnService cannot be used to:

* Collect personal and sensitive user data without prominent disclosure and consent.
* Redirect or manipulate user traffic from other apps on a device for monetization purposes (for example, redirecting ads traffic through a country different than that of the user).
* Manipulate ads that can impact apps monetization.

Apps that use the VpnService must: 

* Document use of the VpnService in the Google Play listing, and
* Must encrypt the data from the device to VPN tunnel end point, and
* Abide by all [Developer Program Policies](https://support.google.com/googleplay/android-developer/topic/9858052?hl=en) including the [Ad Fraud](https://support.google.com/googleplay/android-developer/answer/9969955?hl=en&ref_topic=9969691#zippy=%2Cexamples-of-common-violations), [Permissions](https://support.google.com/googleplay/android-developer/answer/9888170?hl=en&ref_topic=9877467), and [Malware](https://support.google.com/googleplay/android-developer/answer/9888380?hl=en&ref_topic=9975838) policies.  

Reference
* [Google Play Developer Policy Center Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170?hl=en&ref_topic=9877467)

#### Device and Network Abuse
We don’t allow apps that interfere with, disrupt, damage, or access in an unauthorized manner the user’s device, other devices or computers, servers, networks, application programming interfaces (APIs), or services, including but not limited to other apps on the device, any Google service, or an authorized carrier’s network.

Apps on Google Play must comply with the default Android system optimization requirements documented in the [Core App Quality guidelines for Google Play](http://developer.android.com/distribute/essentials/quality/core.html#listing).

An app distributed via Google Play may not modify, replace, or update itself using any method other than Google Play's update mechanism. Likewise, an app may not download executable code (e.g., dex, JAR, .so files) from a source other than Google Play. This restriction does not apply to code that runs in a virtual machine or an interpreter where either provides indirect access to Android APIs (such as JavaScript in a webview or browser). 

Apps or third-party code (e.g., SDKs) with interpreted languages (JavaScript, Python, Lua, etc.) loaded at run time (e.g., not packaged with the app) must not allow potential violations of Google Play policies.

We don’t allow code that introduces or exploits security vulnerabilities. Check out the [App Security Improvement Program](https://developer.android.com/google/play/asi.html#campaigns) to find out about the most recent security issues flagged to developers.

**Flag Secure Requirements**

[FLAG_SECURE](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE) is a display flag declared in an app’s code to indicate that its UI contains sensitive data intended to be limited to a secure surface while using the app. This flag is designed to prevent the data from appearing in screenshots or from being viewed on non-secure displays. Developers declare this flag when the app’s content should not be broadcast, viewed, or otherwise transmitted outside of the app or users’ device.

For security and privacy purposes, all apps distributed on Google Play are required to respect the FLAG_SECURE declaration of other apps. Meaning, apps must not facilitate or create workarounds to bypass the FLAG_SECURE settings in other apps.

Apps that qualify as an [Accessibility Tool](https://support.google.com/googleplay/android-developer/answer/10964491?hl=en) are exempt from this requirement, as long as they do not transmit, save, or cache FLAG_SECURE protected content for access outside of the user's device.

**Examples of Common Violations**

* Apps that block or interfere with another app displaying ads.
* Game cheating apps that affect the gameplay of other apps.
* Apps that facilitate or provide instructions on how to hack services, software or hardware, or circumvent security protections.
* Apps that access or use a service or API in a manner that violates its terms of service.
* Apps that are not [eligible for whitelisting](https://developer.android.com/training/monitoring-device-state/doze-standby.html#whitelisting-cases) and attempt to bypass [system power management](https://developer.android.com/training/monitoring-device-state/doze-standby.html) .
* Apps that facilitate proxy services to third parties may only do so in apps where that is the primary, user-facing core purpose of the app.
* Apps or third party code (e.g., SDKs) that download executable code, such as dex files or native code, from a source other than Google Play.
* Apps that install other apps on a device without the user's prior consent.
* Apps that link to or facilitate the distribution or installation of malicious software.
* Apps or third party code (e.g., SDKs) containing a webview with added JavaScript Interface that loads untrusted web content (e.g., http:// URL) or unverified URLs obtained from untrusted sources (e.g., URLs obtained with untrusted Intents).

Reference
* [Google Play Developer Policy Center Device and Network Abuse](https://support.google.com/googleplay/android-developer/answer/9888379?hl=en&ref_topic=9877467)

#### Deceptive Behavior
We don't allow apps that attempt to deceive users or enable dishonest behavior including but not limited to apps which are determined to be functionally impossible. Apps must provide an accurate disclosure, description and images/video of their functionality in all parts of the metadata. Apps must not attempt to mimic functionality or warnings from the operating system or other apps. Any changes to device settings must be made with the user's knowledge and consent and be reversible by the user.

**Misleading Claims**

We don’t allow apps that contain false or misleading information or claims, including in the description, title, icon, and screenshots.

**Examples of Common Violations**

* Apps that misrepresent or do not accurately and clearly describe their functionality:
  * An app that claims to be a racing game in its description and screenshots, but is actually a puzzle block game using a picture of a car.
  * An app that claims to be an antivirus app, but only contains a text guide explaining how to remove viruses.
* Apps that claim functionalities that are not possible to implement, such as insect repellent apps, even if it is represented as a prank, fake, joke, etc.
* Apps that are improperly categorized, including but not limited to the app rating or app category.
* Demonstrably deceptive or false content that may interfere with voting processes.
* Apps that falsely claim affiliation with a government entity or to provide or facilitate government services for which they are not properly authorized.
* Apps that falsely claim to be the official app of an established entity. Titles like “Justin Bieber Official” are not allowed without the necessary permissions or rights.

**Deceptive Device Settings Changes**

We don’t allow apps that make changes to the user’s device settings or features outside of the app without the user’s knowledge and consent. Device settings and features include system and browser settings, bookmarks, shortcuts, icons, widgets, and the presentation of apps on the homescreen.

Additionally, we do not allow:

* Apps that modify device settings or features with the user’s consent but do so in a way that is not easily reversible.
* Apps or ads that modify device settings or features as a service to third parties or for advertising purposes.
* Apps that mislead users into removing or disabling third-party apps or modifying device settings or features.
* Apps that encourage or incentivize users into removing or disabling third-party apps or modifying device settings or features unless it is part of a verifiable security service.

**Enabling Dishonest Behavior**

We don't allow apps that help users to mislead others or are functionally deceptive in any way, including, but not limited to: apps that generate or facilitate the generation of ID cards, social security numbers, passports, diplomas, credit cards, bank accounts, and driver's licenses. Apps must provide accurate disclosures, titles, descriptions, and images/video regarding the app's functionality and/or content and should perform as reasonably and accurately expected by the user.

Additional app resources (for example, game assets) may only be downloaded if they are necessary for the users' use of the app. Downloaded resources must be compliant with all Google Play policies, and before beginning the download, the app should prompt users and clearly disclose the download size.

Any claim that an app is a "prank", "for entertainment purposes" (or other synonym) does not exempt an app from application of our policies.

**Examples of Common Violations**

* Apps that mimic other apps or websites to trick users into disclosing personal or authentication information.
* Apps that depict or display unverified or real world phone numbers, contacts, addresses, or personally identifiable information of non-consenting individuals or entities.
* Apps with different core functionality based on a user’s geography, device parameters, or other user-dependent data where those differences are not prominently advertised to the user in the store listing.  
* Apps that change significantly between versions without alerting the user (e.g., [‘what’s new’ section](https://support.google.com/googleplay/android-developer/answer/7159011?hl=en)) and updating the store listing.
* Apps that attempt to modify or obfuscate behavior during review.
* Apps with content delivery network (CDN) facilitated downloads that fail to prompt the user and disclose the download size prior to downloading.

**Manipulated Media**

We don't allow apps that promote or help create false or misleading information or claims conveyed through imagery, videos and/or text. We disallow apps determined to promote or perpetuate demonstrably misleading or deceptive imagery, videos and/or text, which may cause harm pertaining to a sensitive event, politics, social issues, or other matters of public concern.

Apps that manipulate or alter media, beyond conventional and editorially acceptable adjustments for clarity or quality, must prominently disclose or watermark altered media when it may not be clear to the average person that the media has been altered. Exceptions may be provided for public interest or obvious satire or parody.

**Examples of Common Violations**

* Apps adding a public figure to a demonstration during a politically sensitive event.
* Apps using public figures or media from a sensitive event to advertise media altering capability within an app's store listing.
* Apps that alter media clips to mimic a news broadcast.

Reference
* [Google Play Developer Policy Center Deceptive Behavior](https://support.google.com/googleplay/android-developer/answer/9888077?hl=en&ref_topic=9877467)

#### Misrepresentation
We do not allow apps or developer accounts that:
* impersonate any person or organization, or that misrepresent or conceal their ownership or primary purpose. 
* that engage in coordinated activity to mislead users. This includes, but isn’t limited to, apps or developer accounts that misrepresent or conceal their country of origin and that direct content at users in another country.
* coordinate with other apps, sites, developers, or other accounts to conceal or misrepresent developer or app identity or other material details, where app content relates to politics, social issues or matters of public concern.

Reference
* [Google Play Developer Policy Center Misrepresentation](https://support.google.com/googleplay/android-developer/answer/9888689?hl=en&ref_topic=9877467)

#### Google Play's Target API Level Policy
To provide users with a safe and secure experience, Google Play requires the following target API levels for **all apps**:

**New apps and app updates MUST** target an Android API level within one year of the latest major Android version release. New apps and app updates that fail to meet this requirement will be prevented from app submission in Play Console.

**Existing Google Play apps that are not updated** and that do not target an API level within two years of the latest major Android version release, will not be available to new users with devices running newer versions of Android OS. Users who have previously installed the app from Google Play will continue to be able to discover, re-install, and use the app on any Android OS version that the app supports.

For technical advice on how to meet the target API level requirement, please consult the [migration guide](https://developer.android.com/distribute/best-practices/develop/target-sdk.html). 

For exact timelines, please refer to this [Help Center article](https://support.google.com/googleplay/android-developer/answer/11926878).

Reference
* [Google Play Developer Policy Center Google Play's Target API Level Policy](https://support.google.com/googleplay/android-developer/answer/11917020?hl=en&ref_topic=9877467)

### Intellectual Property Rights/Intellectual Property Rules on Google Play
We don’t allow apps or developer accounts that infringe on the intellectual property rights of others (including trademark, copyright, patent, trade secret, and other proprietary rights). We also don’t allow apps that encourage or induce infringement of intellectual property rights.

We will respond to clear notices of alleged copyright infringement. For more information or to file a DMCA request, please visit our [copyright procedures](https://support.google.com/legal/troubleshooter/1114905#ts=1115643).

To submit a complaint regarding the sale or promotion for sale of counterfeit goods within an app, please submit a [counterfeit notice](https://support.google.com/legal/contact/lr_counterfeit?product=googleplay&uraw=).

If you are a trademark owner and you believe there is an app on Google Play that infringes on your trademark rights, we encourage you to reach out to the developer directly to resolve your concern. If you are unable to reach a resolution with the developer, please submit a trademark complaint through this [form](https://support.google.com/legal/contact/lr_trademark?product=googleplay&vid=null).

If you have written documentation proving that you have permission to use a third party's intellectual property in your app or store listing (such as brand names, logos and graphic assets), [contact the Google Play team](https://support.google.com/googleplay/android-developer/answer/6320428) in advance of your submission to ensure that your app is not rejected for an intellectual property violation.

Reference
* [Google Play Developer Policy Center Intellectual Property](https://support.google.com/googleplay/android-developer/answer/9888072?hl=en&ref_topic=9876963)

#### Unauthorized Use of Copyrighted Content
We don’t allow apps that infringe copyright. Modifying copyrighted content may still lead to a violation. Developers may be required to provide evidence of their rights to use copyrighted content.

Please be careful when using copyrighted content to demonstrate the functionality of your app. In general, the safest approach is to create something that’s original.

**Examples of Common Violations**

* Cover art for music albums, video games, and books.
* Marketing images from movies, television, or video games.
* Artwork or images from comic books, cartoons, movies, music videos, or television.
* College and professional sports team logos.
* Photos taken from a public figure’s social media account.
* Professional images of public figures.
* Reproductions or “fan art” indistinguishable from the original work under copyright.
* Apps that have soundboards that play audio clips from copyrighted content.
* Full reproductions or translations of books that are not in the public domain.

#### Encouraging Infringement of Copyright
We don’t allow apps that induce or encourage copyright infringement. Before you publish your app, look for ways your app may be encouraging copyright infringement and get legal advice if necessary.

**Examples of Common Violations**

* Streaming apps that allow users to download a local copy of copyrighted content without authorization.
* Apps that encourage users to stream and download copyrighted works, including music and video, in violation of applicable copyright law:

#### Trademark Infringement
We don’t allow apps that infringe on others’ trademarks. A trademark is a word, symbol, or combination that identifies the source of a good or service. Once acquired, a trademark gives the owner exclusive rights to the trademark usage with respect to certain goods or services.

Trademark infringement is improper or unauthorized use of an identical or similar trademark in a way that is likely to cause confusion as to the source of that product. If your app uses another party’s trademarks in a way that is likely to cause confusion, your app may be suspended.

#### Counterfeit
We don't allow apps that sell or promote for sale counterfeit goods. Counterfeit goods contain a trademark or logo that is identical to or substantially indistinguishable from the trademark of another. They mimic the brand features of the product in an attempt to pass themselves off as a genuine product of the brand owner.