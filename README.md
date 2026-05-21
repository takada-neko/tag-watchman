🔒 TagWatchman — AWS Untagged Resource Auto-Isolator
タグのないAWSリソースをリアルタイムで検知・隔離・削除する、CloudFormationワンクリックエージェント
画像を表示
画像を表示

なぜ TagWatchman が必要か
AWSはリソースを作るのが簡単な分、「誰が・何のために作ったかわからないリソース」 が気づかないうちに増えていきます。

退職したメンバーが作ったEC2が動き続けている
テスト用のRDSがそのまま本番環境に残っている
攻撃者がバックドアとして作ったインスタンスかもしれない

AWS Organizations や SCP を使えばこの問題を防げますが、個人・スタートアップ・小規模チームにはオーバースペックです。
TagWatchman は、SCPなしでも タグ管理によるセキュリティガバナンス を実現します。

特徴
TagWatchman既存OSSツール検知方式✅ リアルタイム（EventBridge）❌ 定期スキャン（数時間遅延）対応サービス✅ 全AWSサービス❌ EC2・RDSのみ隔離フェーズ✅ あり（即時ネットワーク遮断）❌ なし（通知か即削除）人間の承認✅ メールのワンクリック承認❌ なし導入方法✅ CloudFormationワンクリック❌ CLI手順が複雑

動作フロー
① リソース作成（EC2・RDS・S3・Lambda・DynamoDB など）
        ↓ リアルタイム検知（数秒以内）
② 必須タグチェック
        ↓ タグ不足
③ 即時ネットワーク隔離（SGを全拒否ルールに差し替え）
        ↓
④ メール通知（不足タグ・実行者・リソース情報）
        ↓ 3日間の猶予（この間にタグを付与すれば自動キャンセル）
⑤ 削除承認メール送信（ワンクリックURL付き）
        ↓ 承認
⑥ リソース削除

⚠️ タグを付与すれば削除はキャンセルされます。
誤検知でも猶予期間内にタグを付ければ安全です。


対応AWSサービス
Resource Groups Tagging API を使用しているため、新サービスへの対応にコード変更は不要です。
カテゴリサービスコンピューティングEC2, Lambda, ECS, EKSデータベースRDS, DynamoDB, ElastiCacheストレージS3メッセージングSQS, SNS, Kinesis分析Glue, OpenSearch

クイックスタート
前提条件

AWS CLI が設定済みであること
CloudTrail が有効になっていること（未設定の場合はこちら）

1. デプロイ
bash# SAM CLI を使う場合
sam build
sam deploy --guided
パラメータ入力例：
Stack Name: tagguard
NotificationEmail: your@email.com   # 通知・承認メールの送信先
RequiredTags: Env,Owner,Project      # 必須タグキー（カンマ区切り）
DeleteDelaySeconds: 259200           # 猶予期間（デフォルト3日 = 259200秒）
DryRun: true                         # 最初は必ず true で動作確認
2. 動作確認（DryRun）
DryRun: true の状態でタグなしリソースを作成し、メール通知が届くことを確認します。
3. 本番適用
bashsam deploy --parameter-overrides DryRun=false

設定のカスタマイズ
猶予期間などの設定は AWS Systems Manager Parameter Store から変更できます。再デプロイ不要です。
パラメータ名デフォルト説明/tagguard/required-tagsEnv,Owner,Project必須タグキー/tagguard/delete-delay-seconds259200（3日）猶予期間（秒）/tagguard/dry-runfalsetrueにすると削除しない

アーキテクチャ
EventBridge（全CloudTrailイベント）
    │
    ▼
┌─────────────────┐
│ Detector Lambda │  ARN抽出 + タグチェック
└────────┬────────┘
         │ タグ不足
         ▼
┌─────────────────────────────────────────┐
│           Step Functions                │
│                                         │
│  Notifier → Wait（3日）→ Recheck → 判定 │
│                              ↓ まだ不足 │
│                           Deleter       │
└─────────────────────────────────────────┘
         │
         ▼
      SNS → メール通知・承認URL

料金
TagWatchman 自体の AWS 利用料はほぼ無料です。
サービス月額概算Lambda（4関数）$0〜Step Functions$0〜EventBridge$0〜SNS・SES$0〜CloudTrail未設定の場合 $2〜

CloudTrail がすでに有効な環境では追加費用ゼロで導入できます。


よくある質問
Q. 本番リソースが誤って削除されませんか？
A. 3日間の猶予期間中にタグを付与すれば削除はキャンセルされます。また最初は DryRun: true で動作確認することを推奨しています。
Q. タグを付与するタイミングが遅れた場合は？
A. 隔離後3日以内であれば、タグを付与した時点で自動的にキャンセルされます。
Q. 対応していないサービスはどうなりますか？
A. 検知はされますが、削除対象のサービスとして登録されていない場合はスキップされます。

ロードマップ

 Slack通知対応
 承認ダッシュボード
 マルチリージョン対応
 タグ設計ガイド + 準拠IaCテンプレート集（有料）


ライセンス
MIT License
