<a href="assets/images/masdg_cover.png"><img width="180px" align="right" style="float: right;" src="assets/images/masdg_cover.png"></a>

# Mobile Application Security Design Guide
OWASP Foundation Web Respository

[![OWASP Flagship project](https://img.shields.io/badge/OWASP-incubator-brightgreen)](https://owasp.org/projects/)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/owasp-mastg)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

![HTML Document](https://img.shields.io/badge/HTML%20Document-passing-blue)
![Markdown Document](https://img.shields.io/badge/Markdown-passing-blue)
![release date](https://img.shields.io/badge/release%20date-April%202023-red)
![platform](https://img.shields.io/badge/platform-iOS%20Android-lightgrey)

This is the official GitHub Repository of the Mobile Application Security Design Guide (MASDG). The MASDG is a document aimed at establishing a framework for designing, developing, and testing secure mobile applications on Mobile Devices, incorporating our own evaluation criteria (rulebook) and sample code into the [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "MASVS") and [OWASP Mobile Application Security Testing Guide (MASTG) ](https://github.com/OWASP/owasp-mastg "OWASP Mobile Application Security Testing Guide")published by OWASP.

MASDG deals with best practices and samples that are specific to the design requirements for security, supporting the creation of security designs from security requirements considered based on MASVS1.5, as well as evaluating the security design for any issues before conducting testing methods indicated in MASTG.

Our proprietary rulebook targets the MASVS1.5 L1 verification standard and aims to provide comprehensive security baselines when developing mobile applications. While new technologies will always bring risks and create privacy and safety issues, we have created this document to address the threats posed by mobile applications.

<BR>

![MASDG_position](assets/images/masdg_position.png)



<BR>

We have received feedback on MASVS and MASTG from various communities and industries, and we have developed and published MASDG as we believe it is essential to tackle the security risks associated with mobile applications that have become indispensable in our society. We welcome feedback from everyone.



<BR>

## Read the OWASP MASDG PDF(English/Japanese)
 
<ul dir="auto">
 <li><a href="https://github.com/OWASP/www-project-mobile-application-security-design-guide/releases/tag/1.1.7" rel="nofollow"><img src="assets/images/arrow_forward.png" width="22px" style="max-width: 100%;"> Download the PDF Document </a> (Mobile Application Security Design Guide)<img src="assets/images/blue_book.png" width="22px" style="max-width: 100%;"> </li>

 </ul>
 

<BR>

## Related Documents the OWASP MASDG Checklist(English/Japanese)
 
<ul dir="auto">
 <li><a href="https://github.com/OWASP/www-project-mobile-application-security-design-guide/releases/tag/1.2.0" rel="nofollow"><img src="assets/images/arrow_forward.png" width="22px" style="max-width: 100%;"> Download the XLSX Document </a> (MASDG Checklist)<img src="assets/images/blue_book.png" width="22px" style="max-width: 100%;"> </li>

 </ul>
 

<BR>

## Related Document the OWASP MASDG to NIST SP800-218(Secure Software Development Framework)(English/Japanese)
 
<ul dir="auto">
 <li><a href="https://github.com/OWASP/www-project-mobile-application-security-design-guide/releases/tag/1.2.1" rel="nofollow"><img src="assets/images/arrow_forward.png" width="22px" style="max-width: 100%;"> Download the XLSX Document </a> (OWASP MASDG to NISP SP800-218)<img src="assets/images/blue_book.png" width="22px" style="max-width: 100%;"> </li>

 </ul>
 
<BR>

<BR>

**Copyright and License**

[![Creative Commons License](assets/images/CC-license.png)](https://creativecommons.org/licenses/by-sa/4.0/)

Copyright © The OWASP Foundation. This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). For any reuse or distribution, you must make clear to others the license terms of this work.

* The contents of this guide are current as of the time of writing. Please be aware of this if you use the sample code.
* The authors are not responsible for any consequences resulting from the use of this guide. Please use at your own risk.
* Android is a trademark or registered trademark of Google LLC. Company names, product names, and service names mentioned in this document are generally registered trademarks or trademarks of their respective companies. The ®, TM, and © symbols are not used throughout this document.
* Some of the content in this document is based on the materials provided by OWASP MASVS and OWASP MASTG, and has been replicated and revised.

<BR>

**Originator**  
Project Site - <https://owasp.org/www-project-mobile-app-security/>  
Project Repository - <https://github.com/OWASP/www-project-mobile-app-security>  
MAS Official Site - <https://mas.owasp.org/>  
MAS Document Site - <https://mas.owasp.org/MASVS/>  
MAS Document Site - <https://mas.owasp.org/MASTG/>  
Document Site - <https://mobile-security.gitbook.io/masvs>  
Document Repository - <https://github.com/OWASP/owasp-masvs>  
Document Site - <https://coky-t.gitbook.io/owasp-masvs-ja/>  
Document Repository - <https://github.com/owasp-ja/owasp-masvs-ja>  
Document Site - <https://mobile-security.gitbook.io/mobile-security-testing-guide>  
Document Repository - <https://github.com/OWASP/owasp-mastg>  
Document Site - <https://coky-t.gitbook.io/owasp-mastg-ja/>  
Document Repository - <https://github.com/coky-t/owasp-mastg-ja>  

<BR>

**OWASP MASVS Authors**  
| Project Lead | Lead Author | Contributors and Reviewes |
| ------- | --- | ----------------- |
| Sven Schleier and Carlos Holguera | Bernhard Mueller, Sven Schleier, Jeroen Willemsen and Carlos Holguera | Alexander Antukh, Mesheryakov Aleksey, Elderov Ali, Bachevsky Artem, Jeroen Beckers, Jon-Anthoney de Boer, Damien Clochard, Ben Cheney, Will Chilcutt, Stephen Corbiaux, Manuel Delgado, Ratchenko Denis, Ryan Dewhurst, @empty_jack, Ben Gardiner, Anton Glezman, Josh Grossman, Sjoerd Langkemper, Vinícius Henrique Marangoni, Martin Marsicano, Roberto Martelloni, @PierrickV, Julia Potapenko, Andrew Orobator, Mehrad Rafii, Javier Ruiz, Abhinav Sejpal, Stefaan Seys, Yogesh Sharma, Prabhant Singh, Nikhil Soni, Anant Shrivastava, Francesco Stillavato, Abdessamad Temmar, Pauchard Thomas, Lukasz Wierzbicki |

<BR>

**OWASP MASTG Authors**  
Bernhard Mueller  
Sven Schleier  
Jeroen Willemsen  
Carlos Holguera  
Romuald Szkudlarek  
Jeroen Beckers  
Vikas Gupta

<BR>

**OWASP MASVS ja Author**  
Koki Takeyama

<BR>

**OWASP MASTG ja Author**  
Koki Takeyama

## Project Supporter
Riotaro Okada

## Revision history
**2023-04-01**
### Repository
* [https://github.com/OWASP/www-project-mobile-application-security-design-guide](#)

## Changelog

All our Changelogs are available online at the OWASP MASDG GitHub repository, see the Releases page:

* <https://github.com/OWASP//www-project-mobile-application-security-design-guide/releases>

## Connect with Us
  - [Yoshiaki Yasuda](mailto:yoshiaki.yasuda@owasp.org), Project Lead (X: [@Yoshiaki Yasuda](https://twitter.com/yoshiaki_yasuda))

## 日本語訳について
OWASP モバイルアプリケーションセキュリティデザインガイドは、モバイルアプリケーション開発時に要求されるセキュア設計の推奨事項をルールブックとして公開しています。
AndroidOS、iOS のアプリ開発時にご参照いただけますと幸いです。
