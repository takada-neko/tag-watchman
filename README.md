# 🔒 TagWatchman — AWS Untagged Resource Auto-Isolator
 
**タグのないAWSリソースをリアルタイムで検知・隔離・削除する、CloudFormationデプロイ型エージェント**
 
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![CloudFormation](https://img.shields.io/badge/deploy-CloudFormation-orange)](https://console.aws.amazon.com/cloudformation)
 
---
 
## なぜ TagWatchman が必要か
 
AWSはリソースを作るのが簡単な分、**「誰が・何のために作ったかわからないリソース」** が気づかないうちに増えていきます。
 
- 離任したメンバーが作ったEC2が動き続けている
- テスト用のRDSがそのまま本番環境に残っている
- 管理外のリソースはコスト・運用・セキュリティ上のリスクになりうる
タグでルールを定めても「タグを付け忘れたら動かせない」という強制力がなければ、運用は形骸化しがちです。AWS Organizations や SCP を使えば組織レベルで強制できますが、**個人・スタートアップ・小規模チームにはオーバースペック**です。
 
TagWatchman は、SCPなしでも **タグ管理によるガバナンス** を実現します。タグの付与を実質的に強制し、その副次効果として管理外リソースを無害化することで、セキュリティリスクの低減にも寄与します。
 
---
 
## 特徴
 
| | TagWatchman | 既存OSSツール |
|---|---|---|
| 検知方式 | ✅ リアルタイム（EventBridge） | ❌ 定期スキャン（数時間遅延） |
| 対応サービス | ✅ ほぼ全てのAWSサービス | ❌ EC2・RDSのみ |
| 隔離フェーズ | ✅ あり（即時操作遮断）**例外あり※** | ❌ なし（通知か即削除） |
| 人間の承認 | ✅ メールのワンクリック承認 | ❌ なし |
| 導入方法 | ✅ IaCデプロイ（SAM対応） | ❌ CLI手順が複雑 |
 
※一部AWSサービスは、技術的またはセキュリティ的な観点からネットワーク隔離以外の対応をしています。
 
👉 [リソース別の挙動詳細はこちら](docs/resource_behavior.md)
 
---
 
## 動作フロー
 
### 通常フロー（タグ不足リソース）
 
```
① リソース作成（EC2・RDS・S3・Lambda など）
        ↓ リアルタイム検知（数秒以内）
② 必須タグチェック
        ↓ タグ不足
③ 即時隔離（操作遮断）+ メール①通知
        ↓ 7日間の猶予
        ├─ タグ付与（operatorロール経由）→ 自動復旧・削除キャンセル ✅
        └─ タグなし → メール②（削除承認依頼）
                ↓ 承認URLクリック
④ リソース削除
```
 
### CloudTrail 専用フロー
 
```
CloudTrail 無効化・削除・設定変更を検知
        ↓ タグ関係なく即時発動
StopLogging       → 自動再有効化 + 🚨 CRITICAL警告メール
DeleteTrail       → 🚨 CRITICAL警告メール（手動再作成が必要）
UpdateTrail       → ⚠️ WARNING警告メール
PutEventSelectors → ⚠️ WARNING警告メール
```
 
> **⚠️ タグを付与すれば削除はキャンセルされます。**  
> 誤検知でも猶予期間内にタグを付ければ安全です。
 
### 対応AWSサービス
 
各サービスとも、隔離は「データの読み書きや主要な操作を拒否する」もので、タグ付与など復旧に必要な操作は許可されています（「害を与えられない状態」にしつつ復旧の導線を残す設計）。
 
| カテゴリ | サービス | 隔離方法 | 復旧方法 |
|---|---|---|---|
| コンピューティング | EC2, Lambda, ECS, EKS | SGを全拒否に差し替え / 同時実行数を0に設定 | タグ付与で自動復旧 |
| データベース | RDS, DynamoDB, Redshift | SGを全拒否に差し替え / リソースポリシーで主要操作を拒否 | タグ付与で自動復旧 |
| ストレージ | S3, ECR | バケット/リポジトリポリシーで主要操作を拒否 | タグ付与で自動復旧 |
| メッセージング | SQS, SNS, Kinesis | ポリシーで主要操作を拒否 | タグ付与で自動復旧 |
| 分析 | OpenSearch | ポリシーで主要操作を拒否 | タグ付与で自動復旧 |
| 分析（通知のみ） | Glue | **通知のみ ※1** | — |
| オーケストレーション | Step Functions | リソースポリシーで主要操作を拒否 | タグ付与で自動復旧 |
| ネットワーク | IGW, NAT Gateway, VPC Peering, ElasticIP | **条件付き即時削除 ※2** | — |
| 通知のみ | VPC, Glue, ElastiCache, Workspaces | **通知のみ（隔離・削除なし）※3** | — |
| 認証・認可 | IAM Role, IAM User | **ポリシー全剥奪＆アクセスキー無効化 ※4** | タグ付与でタグ削除（ポリシー再付与は手動） |
| API | API Gateway | ステージ削除によるエンドポイント無効化 | タグ付与で自動復旧 |
| 監査 | CloudTrail | 専用フロー（自動再有効化） | — |
 
👉 [リソース別の挙動詳細はこちら](docs/resource_behavior.md)
 
**※1 Glueを通知のみにする理由**

- リソースポリシーがデータカタログ全体に適用されるため、database単位での隔離が不可能

**※2 ネットワーク系（条件付き即時削除）の挙動**

- IGW: アタッチなし → 即時削除 / アタッチあり → 通知のみ
- NAT Gateway / VPC Peering: 即時削除
- ElasticIP: アタッチなし → 即時解放 / アタッチあり → 通知のみ

**※3 通知のみにする理由**

- VPC: 削除すると内部の全リソースの通信が止まり、影響範囲が大きすぎるため自動対応不可
- ElastiCache: 状態反映の特性上、ネットワーク隔離が確実に効かないため通知のみ
- Glue / Workspaces: サービス特性上ネットワーク隔離が適さないため通知のみ

**※4 IAMリソースの挙動**

- ポリシー剥奪・キー無効化は自動で実施
- 復旧（ポリシー再付与・キー再作成）は**人間が手動で対応**が必要
- メール通知に手動対応が必要な旨を明記
---
 
## 隔離リソースの復旧（オペレーターロール）
 
隔離されたリソースは、**必須タグを付与すると自動的に復旧**します。ただし誰でもタグを付与できると、攻撃者が自分でタグを付けて隔離を解除できてしまうため、タグ付与は専用のオペレーターロール（`tagwatchman-operator`）経由でのみ許可しています。
 
```
通常のユーザー・管理者              → 隔離リソースへのタグ付与は拒否される
tagwatchman-operator にスイッチロール → タグ付与が可能（＝復旧のトリガー）
```
 
このロールを使える人は、デプロイ時の `TrustedPrincipals` パラメータで指定します（複数指定可）。
 
**復旧手順の例（CLI）**
 
```bash
# 1. オペレーターロールにスイッチ
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/tagwatchman-operator \
  --role-session-name tag-restore \
  --query 'Credentials' --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['SessionToken'])")
 
# 2. 必須タグを付与（例: S3バケット）
aws s3api put-bucket-tagging --bucket <BUCKET_NAME> \
  --tagging 'TagSet=[{Key=Env,Value=prod},{Key=Project,Value=your-project},{Key=Owned,Value=your-team}]'
 
# 3. 元の権限に戻す
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```
 
タグ付与後、TagWatchmanが自動的に隔離を解除します。
 
> **補足：** タグ付与制限が厳密に効くのはリソースポリシー対応サービス（S3 / DynamoDB / SQS / SNS / Kinesis / ECR / Step Functions）です。SGの差し替えで隔離するサービス（EC2 / RDS など）のタグ付与はIAMで制御されるため、運用上はタグ付与権限を絞ることを推奨します。
 
---
 
## クイックスタート
 
### 前提条件
 
- AWS CLI / AWS SAM CLI が設定済みであること（CloudShellでも可）
- CloudTrail が有効になっていること（未設定の場合は[こちら](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html)）
- デプロイ先VPCのIDを確認しておくこと（隔離用SGの作成に必要）
- `tagwatchman-operator` ロールを使わせるIAMエンティティのARNを確認しておくこと
### 1. デプロイ
 
```bash
sam build
sam deploy --guided --capabilities CAPABILITY_NAMED_IAM
```
 
> **💡 `--capabilities CAPABILITY_NAMED_IAM` は必須です。**  
> TagWatchmanは名前付きIAMロール（`tagwatchman-operator` など）を作成するため、この指定がないとデプロイがエラーになります。
 
パラメータ入力例：
 
```
Stack Name: tagwatchman
NotificationEmail: your@email.com        # 通知・承認メールの送信先
RequiredTags: Env,Project,Owned          # 必須タグキー（カンマ区切り）
TagAllowedValues: Env:prod|stg|test,Project:your-project-name  # ※ your-project-name は自身のプロジェクト名に変更
TagMatchMode: Env:exact,Project:prefix   # Env=完全一致 / Project=前方一致
DeleteDelaySeconds: 604800               # 猶予期間（デフォルト7日 = 604800秒）
VpcId: vpc-xxxxxxxx                      # 隔離用SGを作成するVPC ID
DryRun: true                             # 最初は必ず true で動作確認
TrustedPrincipals: arn:aws:iam::123456789012:role/Admin  # operatorロールを使えるARN（カンマ区切りで複数可）
OperatorAllowedCidr:                     # 任意。operatorロールの利用元IPを制限（例: 203.0.113.0/24）。空白で制限なし
```
 
> **💡 `TrustedPrincipals` には、隔離リソースにタグを付与（＝復旧）できる人のARNを指定します。**  
> 自分のARNは `aws sts get-caller-identity` で確認できます。`assumed-role/Admin/xxx` のような形式なら、ベースロールの `arn:aws:iam::<ACCOUNT_ID>:role/Admin` を指定してください。
 
> **💡 `your-project-name` は自身のプロジェクト名に変更してください。**  
> `Project:my-api` と設定した場合、`my-api` `my-api-v2` `my-api-batch` など前方一致でOKになります。
 
### 2. 動作確認（DryRun）
 
`DryRun: true` の状態でタグなしリソースを作成し、メール通知が届くことを確認します。
 
### 3. 本番適用
 
```bash
sam deploy --parameter-overrides DryRun=false
```
 
---
 
## アンインストール（スタック削除）
 
```bash
sam delete --stack-name tagwatchman
```
 
> **💡 削除前に、実行中のStep Functions実行を停止してください。**  
> 隔離中で猶予待ち（実行中）のステートマシンが残っていると、スタック削除が進まないことがあります。Step Functionsコンソールから対象の実行を停止してから削除してください。
 
---
 
## 設定のカスタマイズ
 
タグの判定ルール・猶予期間などは **AWS Systems Manager Parameter Store** から変更できます。再デプロイ不要です。
 
| パラメータ名 | デフォルト | 説明 |
|---|---|---|
| `/tagwatchman/required-tags` | `Env,Project,Owned` | 必須タグキー |
| `/tagwatchman/delete-delay-seconds` | `604800`（7日） | 猶予期間（秒） |
| `/tagwatchman/dry-run` | `false` | trueにすると削除しない |
 
> 詳細な設定方法（タグの判定ルール・許可値の設定など）は購入者向けのドキュメントに記載しています。
 
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
| SNS | $0〜 |
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
 
**Q. なぜ普通の管理者権限では隔離リソースにタグを付与できないのですか？**  
A. 誰でもタグを付与できると、攻撃者が自分でタグを付けて隔離を解除できてしまうためです。タグ付与は `tagwatchman-operator` ロール経由に限定し、このロールを使える人を `TrustedPrincipals` で絞ることで、復旧操作を信頼できる人だけに制限しています。
 
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
 
- [ ] 既存リソースの定期スキャン通知（オプション）
- [ ] Slack通知対応
- [ ] 承認ダッシュボード
- [ ] マルチリージョン対応
- [ ] HTTP API（API Gateway v2）対応
- [ ] オペレーターロールのIP制限の高度化
---
 
## ライセンス
 
All Rights Reserved © 2026 TagWatchman
 
