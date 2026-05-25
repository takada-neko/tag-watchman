# 🔒 TagWatchman — AWS Untagged Resource Auto-Isolator

**タグのないAWSリソースをリアルタイムで検知・隔離・削除する、CloudFormationワンクリックエージェント**

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![CloudFormation](https://img.shields.io/badge/deploy-CloudFormation-orange)](https://console.aws.amazon.com/cloudformation)

---

## なぜ TagWatchman が必要か

AWSはリソースを作るのが簡単な分、**「誰が・何のために作ったかわからないリソース」** が気づかないうちに増えていきます。

- 離任したメンバーが作ったEC2が動き続けている
- テスト用のRDSがそのまま本番環境に残っている
- 攻撃者がバックドアとして作ったインスタンスかもしれない

AWS Organizations や SCP を使えばこの問題を防げますが、**個人・スタートアップ・小規模チームにはオーバースペック**です。

TagWatchman は、SCPなしでも **タグ管理によるセキュリティガバナンス** を実現します。

---

## 特徴

| | TagWatchman | 既存OSSツール |
|---|---|---|
| 検知方式 | ✅ リアルタイム（EventBridge） | ❌ 定期スキャン（数時間遅延） |
| 対応サービス | ✅ ほぼ全てのAWSサービス | ❌ EC2・RDSのみ |
| 隔離フェーズ | ✅ あり（即時ネットワーク遮断） | ❌ なし（通知か即削除） |
| 人間の承認 | ✅ メールのワンクリック承認 | ❌ なし |
| 導入方法 | ✅ CloudFormationワンクリック | ❌ CLI手順が複雑 |

---

## 動作フロー

### 通常フロー（タグ不足リソース）

```
① リソース作成（EC2・RDS・S3・Lambda など）
        ↓ リアルタイム検知（数秒以内）
② 必須タグチェック
        ↓ タグ不足
③ 即時隔離（通信遮断）+ メール①通知
        ↓ 7日間の猶予
        ├─ タグ付与 → 自動復旧・削除キャンセル ✅
        └─ タグなし → メール②（削除承認依頼）
                ↓ 承認URLクリック
④ リソース削除
```

### CloudTrail 専用フロー

```
CloudTrail 無効化・削除・設定変更を検知
        ↓ タグ関係なく即時発動
StopLogging  → 自動再有効化 + 🚨 CRITICAL警告メール
DeleteTrail  → 🚨 CRITICAL警告メール（手動再作成が必要）
UpdateTrail  → ⚠️ WARNING警告メール
```

> **⚠️ タグを付与すれば削除はキャンセルされます。**  
> 誤検知でも猶予期間内にタグを付ければ安全です。

---

## 対応AWSサービス

| カテゴリ | サービス | 隔離方法 |
|---|---|---|
| コンピューティング | EC2, Lambda, ECS, EKS, Workspaces | SGを全拒否に差し替え / 同時実行数を0に設定 |
| データベース | RDS, DynamoDB, ElastiCache, Redshift | SGを全拒否に差し替え / リソースポリシーで全拒否 |
| ストレージ | S3, ECR | バケット/リポジトリポリシーで全拒否 |
| メッセージング | SQS, SNS, Kinesis | ポリシーで全拒否 |
| 分析 | Glue, OpenSearch | ポリシーで全拒否 |
| オーケストレーション | Step Functions | リソースポリシーで全拒否 |
| ネットワーク | IGW, NAT Gateway, VPC Peering | 条件付き即時削除 ※1 |
| 認証・認可 | IAM Role, IAM User | ポリシー全剥奪 + アクセスキー無効化 ※2 |
| API | API Gateway | ステージ削除によるエンドポイント無効化 |
| 監査 | CloudTrail | 専用フロー（自動再有効化） |

**※1 ネットワーク系の挙動**
- IGW: アタッチなし → 即時削除 / アタッチあり → 通知のみ（手動対応）
- NAT Gateway / VPC Peering: タグ不足の場合は即時削除

**※2 IAMリソースの挙動**
- ポリシー剥奪・キー無効化は自動で実施
- 復旧（ポリシー再付与・キー再作成）は**人間が手動で対応**が必要
- メール通知に手動対応が必要な旨を明記

---

## クイックスタート

### 前提条件

- AWS CLI が設定済みであること
- CloudTrail が有効になっていること（未設定の場合は[こちら](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html)）
- デプロイ先VPCのIDを確認しておくこと（隔離用SGの作成に必要）

### 1. デプロイ

```bash
sam build
sam deploy --guided
```

パラメータ入力例：

```
Stack Name: tagwatchman
NotificationEmail: your@email.com        # 通知・承認メールの送信先（カンマ区切りで複数指定可）
RequiredTags: Env,Project,Owned          # 必須タグキー（カンマ区切り）
TagAllowedValues: Env:prod|stg|test,Project:your-project-name  # ※ your-project-name は自身のプロジェクト名に変更
TagMatchMode: Env:exact,Project:prefix   # Env=完全一致 / Project=前方一致
DeleteDelaySeconds: 604800               # 猶予期間（デフォルト7日 = 604800秒）
VpcId: vpc-xxxxxxxx                      # 隔離用SGを作成するVPC ID
DryRun: true                             # 最初は必ず true で動作確認
```

> **💡 `your-project-name` は自身のプロジェクト名に変更してください。**  
> `Project:my-api` と設定した場合、`my-api` `my-api-v2` `my-api-batch` など前方一致でOKになります。

### 2. 動作確認（DryRun）

`DryRun: true` の状態でタグなしリソースを作成し、メール通知が届くことを確認します。

### 3. 本番適用

```bash
sam deploy --parameter-overrides DryRun=false
```

---

## 設定のカスタマイズ

猶予期間などの設定は **AWS Systems Manager Parameter Store** から変更できます。再デプロイ不要です。

| パラメータ名 | デフォルト | 説明 |
|---|---|---|
| `/tagwatchman/required-tags` | `Env,Owner,Project` | 必須タグキー |
| `/tagwatchman/delete-delay-seconds` | `604800`（7日） | 猶予期間（秒） |
| `/tagwatchman/dry-run` | `false` | trueにすると削除しない |

---

## アーキテクチャ

<img height="800" alt="image" src="https://github.com/user-attachments/assets/0c03b2e1-b968-4ba9-b907-f2ace73e7efc" />

---

## 料金

TagWatchman 自体の AWS 利用料はほぼ無料です。

| サービス | 月額概算 |
|---|---|
| Lambda（8関数） | $0〜 |
| Step Functions | $0〜 |
| EventBridge | $0〜 |
| SNS・SES | $0〜 |
| API Gateway | $0〜 |
| **CloudTrail** | **未設定の場合 $2〜** |

> CloudTrail がすでに有効な環境では**追加費用ゼロ**で導入できます。

## 販売価格

近日販売開始予定です。リリース通知を受け取りたい方は ⭐ Star をお願いします！

| プラン | 価格（税込） |
|---|---|
| エージェント単体 | ¥4,400 |
| タグ設計ガイド + IaCテンプレートセット | ¥9,900 |

---

## よくある質問

**Q. Owned タグにはどんな値を入れればいいですか？**  
A. 値は自由ですが、個人名（`Takada`）よりチーム名（`backend`、`infra` など）を推奨します。チーム名にしておくとメンバーの異動・追加時にタグの更新が不要になります。空文字のみ違反となります。

**Q. タグの許可値はどこで変更できますか？**  
A. AWS Systems Manager Parameter Store の `/tagwatchman/tag-allowed-values` を更新してください。再デプロイ不要で即時反映されます。  

**Q. タグを付与するタイミングが遅れた場合は？**  
A. 隔離後7日以内であれば、タグを付与した時点で自動的にキャンセルされます。また最初は `DryRun: true` で動作確認することを推奨しています。

**Q. タグを付けて管理しているリソースは影響を受けますか？**  
A. 一切影響を受けません。TagWatchman は「タグが不足している」ことのみをトリガーに動作します。タグが付いているリソース = 管理されているリソースとして扱い、隔離・削除の対象になりません。

**Q. IGWにタグが付いていてもアタッチされていれば削除されますか？**  
A. タグが付いていれば隔離・削除の対象になりません。タグが不足していてアタッチされている場合は通知のみで自動削除はしません。手動での対応が必要です。

**Q. IAMリソースが隔離された場合、自動で復旧しますか？**  
A. タグを付与すれば隔離タグは自動で削除されますが、剥奪されたポリシーの再付与とアクセスキーの再作成は人間が手動で行う必要があります。メール通知に手順の案内が記載されます。

**Q. 対応していないサービスはどうなりますか？**  
A. 検知はされますが、隔離・削除対象として登録されていない場合はスキップされます。

---

## ロードマップ

- [ ] タグ設計ガイド + 準拠IaCテンプレート集
- [ ] 既存リソースの定期スキャン通知（オプション）
- [ ] EIP対応（アタッチなし → 即時解放）
- [ ] VPN Gateway / Transit Gateway / CloudFront 通知のみ対応
- [ ] Slack通知対応
- [ ] 承認ダッシュボード
- [ ] マルチリージョン対応

---

## ライセンス

All Rights Reserved © 2025 TagWatchman
