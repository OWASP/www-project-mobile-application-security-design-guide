# モバイルアプリケーションのセキュリティ設計ガイド iOS版

**2023年04月01日版**&#010;<br>

モバイルアプリケーションのセキュリティ設計ガイド（MASDG） iOS版へようこそ。

モバイルアプリケーションのセキュリティ設計ガイド iOS版は OWASP が公開している MASVS および MASTG に本プロジェクト独自の判定基準（ルールブック）やサンプルコードを組み込みんだ iOS 上のセキュアなモバイルアプリケーションを設計、開発、テストするときに必要となるセキュリティ設計のフレームワークを確立するためのドキュメントです。

MASDG は、セキュリティ要件に対する具体的な設計内容に特化したベストプラクティスやサンプル等を取り扱うことで、MASVS を元に検討したセキュリティ要件からセキュリティ設計を作成することをサポートすることや、MASTG で示されているテスト方法を実施する前にセキュリティ設計に問題が無いかを評価することをサポートします。

本プロジェクトの独自のルールブックは MASVS L1検証標準を対象としておりモバイルアプリを開発する際に網羅的なセキュリティベースラインを提供することを目的としています。これから創出される新しいテクノロジーは必ずリスクをもたらしプライバシーやセーフティーの課題を生じますがモバイルアプリに関する脅威に立ち向かうべく本ドキュメントの作成を行いました。

MASVS および MASTG に対しては様々なコミュニティや業界からフィードバックを受けていますが、本プロジェクトとしても社会生活に不可欠となったモバイルアプリケーションに対するセキュリティリスクの課題に取り組んで行きたいと考えておりますのでMASDG を開発し公開しました。皆様からのフィードバックを歓迎します。

**著作権とライセンス**  
<a href="https://creativecommons.org/licenses/by-sa/4.0/"><img src="images/0x01/by-sa.png" alt="CC BY-SA 4.0" width="200"></a>

Copyright © The OWASP Foundation. 本著作物は [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/) に基づいてライセンスされています。再使用または配布する場合は、他者に対し本著作物のライセンス条項を明らかにする必要があります。

* 本ガイドの内容は執筆時点のものです。サンプルコードを使用する場合はこの点にあらかじめご注意ください。
* 執筆関係者は、このガイド文書に関するいかなる責任も負うものではありません。全ては自己責任にてご活用ください。
* iOS は、Apple Inc. の商標または登録商標です。また、本文書に登場する会社名、製品名、サービス名は、一般に各社の登録商標または商標です。本文中では®、TM、© マークは明記していません。
* この文書の内容の一部は、OWASP MASVS, OWASP MASTG が作成、提供しているコンテンツをベースに複製、改版したものです。

**Originator**  
Project Site - https://owasp.org/www-project-mobile-app-security/  
Project Repository - https://github.com/OWASP/www-project-mobile-app-security  
MAS Official Site - https://mas.owasp.org/  
MAS Document Site - https://mas.owasp.org/MASVS/  
MAS Document Site - https://mas.owasp.org/MASTG/  
Document Site - https://mobile-security.gitbook.io/masvs  
Document Repository - https://github.com/OWASP/owasp-masvs  
Document Site - https://coky-t.gitbook.io/owasp-masvs-ja/  
Document Repository - https://github.com/owasp-ja/owasp-masvs-ja  
Document Site - https://mobile-security.gitbook.io/mobile-security-testing-guide  
Document Repository - https://github.com/OWASP/owasp-mastg  
Document Site - https://coky-t.gitbook.io/owasp-mastg-ja/  
Document Repository - https://github.com/coky-t/owasp-mastg-ja  
<br>

**OWASP MASVS Authors**  
| Project Lead | Lead Author | Contributors and Reviewers |
| :--- | :--- | :--- |
| Sven Schleier, Carlos Holguera | Bernhard Mueller, Sven Schleier, Jeroen Willemsen and Carlos Holguera | Alexander Antukh, Mesheryakov Aleksey, Elderov Ali, Bachevsky Artem, Jeroen Beckers, Jon-Anthoney de Boer, Damien Clochard, Ben Cheney, Will Chilcutt, Stephen Corbiaux, Manuel Delgado, Ratchenko Denis, Ryan Dewhurst, @empty_jack, Ben Gardiner, Anton Glezman, Josh Grossman, Sjoerd Langkemper, Vinícius Henrique Marangoni, Martin Marsicano, Roberto Martelloni, @PierrickV, Julia Potapenko, Andrew Orobator, Mehrad Rafii, Javier Ruiz, Abhinav Sejpal, Stefaan Seys, Yogesh Sharma, Prabhant Singh, Nikhil Soni, Anant Shrivastava, Francesco Stillavato, Abdessamad Temmar, Pauchard Thomas, Lukasz Wierzbicki |

**OWASP MASTG Authors**  
Bernhard Mueller  
Sven Schleier  
Jeroen Willemsen  
Carlos Holguera  
Romuald Szkudlarek  
Jeroen Beckers  
Vikas Gupta

**OWASP MASVS ja Author**  
Koki Takeyama

**OWASP MASTG ja Author**  
Koki Takeyama

**Table of Contents**  
- [アーキテクチャ・設計・脅威モデリング要件](0x02-MASDG-Architecture_Design_and_Threat_Modeling_Requirements.md)
- [データストレージとプライバシー要件](0x03-MASDG-Data_Storage_and_Privacy_Requirements.md)
- [暗号化要件](0x04-MASDG-Cryptography_Requirements.md)
- [認証とセッション管理要件](0x05-MASDG-Authentication_and_Session_Management_Requirements.md)
- [ネットワーク通信要件](0x06-MASDG-Network_Communication_Requirements.md)
- [プラットフォーム連携要件](0x07-MASDG-Platform_Interaction_Requirements.md)
- [コード品質とビルド設定要件](0x08-MASDG-Code_Quality_and_Build_Setting_Requirements.md)

## Project Supporter
Riotaro Okada

## 更新履歴
**2023-04-01**

&nbsp;&nbsp;&nbsp;&nbsp;初版