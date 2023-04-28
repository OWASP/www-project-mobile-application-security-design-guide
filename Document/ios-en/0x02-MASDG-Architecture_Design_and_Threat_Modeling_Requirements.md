# Architecture, Design and Threat Modeling Requirements

## MSTG-ARCH-1
All app components are identified and known to be needed.

### Component
Get to know all the components of your application and remove unnecessary ones.<br>

The main types of components are as follows
* Content
  * Charts
  * Image views
  * Text views
  * Web views

* Layout and Organization
  * Boxes
  * Collections
  * Column views
  * Disclosure Controls
  * Labels
  * Lists and tables
  * Lockups
  * Outline views
  * Split views
  * Tab views

* Menus and Actions
  * Activity views
  * Buttons
  * Context menus
  * Dock menus
  * Edit menus
  * Menus
  * Pop-up buttons
  * Pull-down buttons
  * Toolbars

* Navigation and Search
  * Navigation bars
  * Path controls
  * Search fields
  * Sidebars
  * Tab bars
  * Token fields

* Presentation
  * Action sheets
  * Alerts
  * Page controls
  * Panels
  * Popovers
  * Scroll views
  * Sheets
  * Windows

* Selection and Entry
  * Color wells
  * Combo boxes
  * Digit entry views
  * Image wells
  * Onscreen keyboards
  * Pickers
  * Segmented controls
  * Sliders
  * Steppers
  * Text fields
  * Toggles

* Condition
  * Activity rings
  * Gauges
  * Progress indicators
  * Rating indicators

* System
  * Complications
  * Home Screen quick actions
  * Live Activities
  * The menu bar
  * Notifications
  * Status bars
  * Top Shelf
  * Watch faces
  * Widgets

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
* [owasp-mastg Verifying that Appropriate Authentication is in Place (MSTG-ARCH-2 and MSTG-AUTH-1)](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04e-Testing-Authentication-and-Session-Management.md#verifying-that-appropriate-authentication-is-in-place-mstg-arch-2-and-mstg-auth-1)


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
* A malicious app could attack another app running on the device via the Interprocess Communication (IPC) interface.

#### Unchecked inputs are successfully linked to their respective queries (Required)
Identify known dangerous library /API calls (e.g., SQL queries) and verify that unchecked inputs work with the respective queries successfully.
Also, check the reference of the library/API to be used and confirm that it is not deprecated.

iOS API Reference：[https://developer.apple.com/documentation/](https://developer.apple.com/documentation/)

If this is violated, the following may occur.
* A malicious app could attack another app running on the device via the Interprocess Communication (IPC) interface.

#### Check for untrusted input (Required)
In general, untrusted inputs enter mobile apps through the following channels:

Below is an example of keywords that identify channel use.
* IPC calls： NSXPCConnection, XPC Services
* Custom URL schemes： deeplink, URL Schemes, identifier 
* QR codes： qr, camera
* Input files received via Bluetooth, NFC, or other means： MCNearbyServiceBrowser, MCNearbyServiceAdvertiser, Core Bluetooth
* Pasteboards： UIPasteboard
* User interface： UITextField

If this is violated, the following may occur.
* A malicious app could attack another app running on the device via the Interprocess Communication (IPC) interface.

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
* [SecCertificateCreateWithData](https://developer.apple.com/documentation/security/1396073-seccertificatecreatewithdata)

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
* [owasp-mastg Mobile Application Security Testing Identifying Sensitive Datas](https://github.com/OWASP/owasp-mastg/blob/v1.5.0/Document/0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data)

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

### App Store privacy rules
Protecting user privacy is paramount in the Apple ecosystem, and you should use care when handling personal data to ensure you’ve complied with [privacy best practices](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/), applicable laws, and the terms of the [Apple Developer Program License Agreement](https://developer.apple.com/support/terms/), not to mention customer expectations. More particularly:

Reference
* [App Store Legal 5.1 Privacy](https://developer.apple.com/app-store/review/guidelines/#privacy)

#### Data Collection and Storage

1. **Privacy Policies**
    App Store Connect metadata field and within the app in an easily accessible manner. The privacy policy must clearly and explicitly:
    * Identify what data, if any, the app/service collects, how it collects that data, and all uses of that data.
    * Confirm that any third party with whom an app shares user data (in compliance with these Guidelines)—such as analytics tools, advertising networks and third-party SDKs, as well as any parent, subsidiary or other related entities that will have access to user data—will provide the same or equal protection of user data as stated in the app’s privacy policy and required by these Guidelines.
    * Explain its data retention/deletion policies and describe how a user can revoke consent and/or request deletion of the user’s data.
1. **Permission**
    Apps that collect user or usage data must secure user consent for the collection, even if such data is considered to be anonymous at the time of or immediately following collection. Paid functionality must not be dependent on or require a user to grant access to this data. Apps must also provide the customer with an easily accessible and understandable way to withdraw consent. Ensure your purpose strings clearly and completely describe your use of the data. Apps that collect data for a legitimate interest without consent by relying on the terms of the European Union’s General Data Protection Regulation (“GDPR”) or similar statute must comply with all terms of that law. Learn more about [Requesting Permission](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/).
1. **Data Minimization**
    Apps should only request access to data relevant to the core functionality of the app and should only collect and use data that is required to accomplish the relevant task. Where possible, use the out-of-process picker or a share sheet rather than requesting full access to protected resources like Photos or Contacts.
1. **Access**
    Apps must respect the user’s permission settings and not attempt to manipulate, trick, or force people to consent to unnecessary data access. For example, apps that include the ability to post photos to a social network must not also require microphone access before allowing the user to upload photos. Where possible, provide alternative solutions for users who don’t grant consent. For example, if a user declines to share Location, offer the ability to manually enter an address.
1. **Account Sign-In**
    If your app doesn’t include significant account-based features, let people use it without a login. If your app supports account creation, you must also [offer account deletion within the app](https://developer.apple.com/support/offering-account-deletion-in-your-app/). Apps may not require users to enter personal information to function, except when directly relevant to the core functionality of the app or required by law. If your core app functionality is not related to a specific social network (e.g. Facebook, WeChat, Weibo, Twitter, etc.), you must provide access without a login or via another mechanism. Pulling basic profile information, sharing to the social network, or inviting friends to use the app are not considered core app functionality. The app must also include a mechanism to revoke social network credentials and disable data access between the app and social network from within the app. An app may not store credentials or tokens to social networks off of the device and may only use such credentials or tokens to directly connect to the social network from the app itself while the app is in use.
1. Developers that use their apps to surreptitiously discover passwords or other private data will be removed from the Apple Developer Program.
1. SafariViewController must be used to visibly present information to users; the controller may not be hidden or obscured by other views or layers. Additionally, an app may not use SafariViewController to track users without their knowledge and consent.
1. Apps that compile personal information from any source that is not directly from the user or without the user’s explicit consent, even public databases, are not permitted on the App Store.
1. Apps that provide services in highly regulated fields (such as banking and financial services, healthcare, gambling, legal cannabis use, and air travel) or that require sensitive user information should be submitted by a legal entity that provides the services, and not by an individual developer. Apps that facilitate the legal sale of cannabis must be geo-restricted to the corresponding legal jurisdiction.
1. Apps may request basic contact information (such as name and email address) so long as the request is optional for the user, features and services are not conditional on providing the information, and it complies with all other provisions of these guidelines, including limitations on collecting information from kids.

Reference
* [App Store Legal 5.1.1 Data Collection and Storage](https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage)

#### Data Use and Sharing
1. Unless otherwise permitted by law, you may not use, transmit, or share someone’s personal data without first obtaining their permission. You must provide access to information about how and where the data will be used. Data collected from apps may only be shared with third parties to improve the app or serve advertising (in compliance with the [Apple Developer Program License Agreement](https://developer.apple.com/support/terms/)). You must receive explicit permission from users via the App Tracking Transparency APIs to track their activity. Learn more about [tracking](https://developer.apple.com/app-store/user-privacy-and-data-use/). Apps that share user data without user consent or otherwise complying with data privacy laws may be removed from sale and may result in your removal from the Apple Developer Program.
1. Data collected for one purpose may not be repurposed without further consent unless otherwise explicitly permitted by law.
1. Apps should not attempt to surreptitiously build a user profile based on collected data and may not attempt, facilitate, or encourage others to identify anonymous users or reconstruct user profiles based on data collected from Apple-provided APIs or any data that you say has been collected in an “anonymized,” “aggregated,” or otherwise non-identifiable way.
1. Do not use information from Contacts, Photos, or other APIs that access user data to build a contact database for your own use or for sale/distribution to third parties, and don’t collect information about which other apps are installed on a user’s device for the purposes of analytics or advertising/marketing.
1. Do not contact people using information collected via a user’s Contacts or Photos, except at the explicit initiative of that user on an individualized basis; do not include a Select All option or default the selection of all contacts. You must provide the user with a clear description of how the message will appear to the recipient before sending it (e.g. What will the message say? Who will appear to be the sender?).
1. Data gathered from the HomeKit API, HealthKit, Clinical Health Records API, MovementDisorder APIs, ClassKit or from depth and/or facial mapping tools (e.g. ARKit, Camera APIs, or Photo APIs) may not be used for marketing, advertising or use-based data mining, including by third parties. Learn more about best practices for implementing [CallKit](https://developer.apple.com/documentation/callkit), [HealthKit](https://developer.apple.com/documentation/healthkit), [ClassKit](https://developer.apple.com/documentation/classkit),and [ARKit](https://developer.apple.com/documentation/arkit/).
1. Apps using Apple Pay may only share user data acquired via Apple Pay with third parties to facilitate or improve delivery of goods and services.

Reference
* [App Store Legal 5.1.2 Data Use and Sharing](https://developer.apple.com/app-store/review/guidelines/#data-use-and-sharing)

#### Health and Health Research
Health, fitness, and medical data are especially sensitive and apps in this space have some additional rules to make sure customer privacy is protected:
1. Apps may not use or disclose to third parties data gathered in the health, fitness, and medical research context—including from the Clinical Health Records API, HealthKit API, Motion and Fitness, MovementDisorder APIs, or health-related human subject research—for advertising, marketing, or other use-based data mining purposes other than improving health management, or for the purpose of health research, and then only with permission. Apps may, however, use a user’s health or fitness data to provide a benefit directly to that user (such as a reduced insurance premium), provided that the app is submitted by the entity providing the benefit, and the data is not shared with a third party. You must disclose the specific health data that you are collecting from the device.
1. Apps must not write false or inaccurate data into HealthKit or any other medical research or health management apps, and may not store personal health information in iCloud.
1. Apps conducting health-related human subject research must obtain consent from participants or, in the case of minors, their parent or guardian. Such consent must include the (a) nature, purpose, and duration of the research; (b) procedures, risks, and benefits to the participant; (c) information about confidentiality and handling of data (including any sharing with third parties); (d) a point of contact for participant questions; and (e) the withdrawal process.
1. Apps conducting health-related human subject research must secure approval from an independent ethics review board. Proof of such approval must be provided upon request.

Reference
* [App Store Legal 5.1.3 Health and Health Research](https://developer.apple.com/app-store/review/guidelines/#health-and-health-research)

#### Kids
For many reasons, it is critical to use care when dealing with personal data from kids, and we encourage you to carefully review all the requirements for complying with laws like the Children’s Online Privacy Protection Act (“COPPA”), the European Union’s General Data Protection Regulation (“GDPR”), and any other applicable regulations or laws.

Apps may ask for birthdate and parental contact information only for the purpose of complying with these statutes, but must include some useful functionality or entertainment value regardless of a person’s age.

Apps intended primarily for kids should not include third-party analytics or third-party advertising. This provides a safer experience for kids. In limited cases, third-party analytics and third-party advertising may be permitted provided that the services adhere to the same terms set forth in [Guideline 1.3](https://developer.apple.com/app-store/review/guidelines/#1.3).

Moreover, apps in the Kids Category or those that collect, transmit, or have the capability to share personal information (e.g. name, address, email, location, photos, videos, drawings, the ability to chat, other personal data, or persistent identifiers used in combination with any of the above) from a minor must include a privacy policy and must comply with all applicable children’s privacy statutes. For the sake of clarity, the [parental gate requirement](https://developer.apple.com/app-store/review/guidelines/#kids-category) for the Kid’s Category is generally not the same as securing parental consent to collect personal data under these privacy statutes.

As a reminder, [Guideline 2.3.8](https://developer.apple.com/app-store/review/guidelines/#2.3.8) requires that use of terms like “For Kids” and “For Children” in app metadata is reserved for the Kids Category. Apps not in the Kids Category cannot include any terms in app name, subtitle, icon, screenshots or description that imply the main audience for the app is children.

Reference
* [App Store Legal 5.1.4 Kids](https://developer.apple.com/app-store/review/guidelines/#kids)

#### Location Services
Use Location services in your app only when it is directly relevant to the features and services provided by the app. Location-based APIs shouldn’t be used to provide emergency services or autonomous control over vehicles, aircraft, and other devices, except for small devices such as lightweight drones and toys, or remote control car alarm systems, etc. Ensure that you notify and obtain consent before collecting, transmitting, or using location data. If your app uses location services, be sure to explain the purpose in your app; refer to the [Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/patterns/accessing-private-data/) for best practices for doing so.

Reference
* [App Store Legal 5.1.5 Location Services](https://developer.apple.com/app-store/review/guidelines/#location)

### Intellectual Property App Store Rules
Make sure your app only includes content that you created or that you have a license to use. Your app may be removed if you’ve stepped over the line and used content without permission. Of course, this also means someone else’s app may be removed if they’ve “borrowed” from your work. If you believe your intellectual property has been infringed by another developer on the App Store, submit a claim via our [web form](https://www.apple.com/legal/internet-services/itunes/appstorenotices/#?lang=en). Laws differ in different countries and regions, but at the very least, make sure to avoid the following common errors:
1. **Generally**
    Don’t use protected third-party material such as trademarks, copyrighted works, or patented ideas in your app without permission, and don’t include misleading, false, or copycat representations, names, or metadata in your app bundle or developer name. Apps should be submitted by the person or legal entity that owns or has licensed the intellectual property and other relevant rights.
1. **Third-Party Sites/Services**
     If your app uses, accesses, monetizes access to, or displays content from a third-party service, ensure that you are specifically permitted to do so under the service’s terms of use. Authorization must be provided upon request.
1. **Audio/Video Downloading**
    Apps should not facilitate illegal file sharing or include the ability to save, convert, or download media from third-party sources (e.g. Apple Music, YouTube, SoundCloud, Vimeo, etc.) without explicit authorization from those sources. Streaming of audio/video content may also violate Terms of Use, so be sure to check before your app accesses those services. Documentation must be provided upon request.
1. **Apple Endorsements**
    Don’t suggest or imply that Apple is a source or supplier of the App, or that Apple endorses any particular representation regarding quality or functionality. If your app is selected as an “Editor’s Choice,” Apple will apply the badge automatically.
1. **Apple Products**
    Don’t create an app that appears confusingly similar to an existing Apple product, interface (e.g. Finder), app (such as the App Store, iTunes Store, or Messages) or advertising theme. Apps and extensions, including third-party keyboards and Sticker packs, may not include Apple emoji. Music from iTunes and Apple Music previews may not be used for their entertainment value (e.g. as the background music to a photo collage or the soundtrack to a game) or in any other unauthorized manner. If you provide music previews from iTunes or Apple Music, you must display a link to the corresponding music in iTunes or Apple Music. If your app displays Activity rings, they should not visualize Move, Exercise, or Stand data in a way that resembles the Activity control. The [Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/patterns/workouts#activity-rings) have more information on how to use Activity rings. If your app displays Apple Weather data, it should follow the attribution requirements provided in the [WeatherKit documentation](https://developer.apple.com/weatherkit/get-started/index.html#attribution-requirements).

Reference
* [App Store Legal 5.2 Intellectual Property](https://developer.apple.com/app-store/review/guidelines/#intellectual-property)
