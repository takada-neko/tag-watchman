"""
notifier/index.py
─────────────────
2種類のメールを送信する。

メール① 検知・隔離通知（即時）
  - タグ不足リソースを検知・隔離したことを通知
  - 猶予期間中にタグを付与すれば自動復旧することを案内

メール② 削除承認依頼（7日後）
  - 承認URLを含む
  - クリックで削除実行
"""

import json
import logging
import os
import re
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN        = os.environ.get("SNS_TOPIC_ARN", "")
DELETE_DELAY_SECONDS = int(os.environ.get("DELETE_DELAY_SECONDS", "604800"))
APPROVAL_BASE_URL    = os.environ.get("APPROVAL_BASE_URL", "")  # API GatewayのURL

sns = boto3.client("sns")


def lambda_handler(event, context):
    mail_type = event.get("mailType", "detection")  # "detection" or "approval"

    if mail_type == "detection":
        _send_detection_mail(event)
    elif mail_type == "approval":
        _send_approval_mail(event)
    else:
        logger.warning("Unknown mailType: %s", mail_type)

    return event


# ─────────────────────────────────────────────────────────────
# 元リソースポリシーの Statement 概要を抽出するヘルパー
# ─────────────────────────────────────────────────────────────
def _summarize_policy_statements(body: str) -> list:
    """元バケットポリシー JSON から Sid / Effect のリストを抽出して整形する。
    パース失敗時や Statement 不在時は安全に fallback する。
    """
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return ["    (本文のパースに失敗したため概要を生成できません)"]
    stmts = doc.get("Statement") if isinstance(doc, dict) else None
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list) or not stmts:
        return ["    (Statement が見つかりません)"]
    lines = []
    for i, s in enumerate(stmts, 1):
        if not isinstance(s, dict):
            lines.append(f"    [{i}] (非 dict Statement)")
            continue
        sid    = s.get("Sid", "(no Sid)")
        effect = s.get("Effect", "(no Effect)")
        lines.append(f"    [{i}] Sid={sid} / Effect={effect}")
    return lines


# ─────────────────────────────────────────────────────────────
# メール① 検知・隔離通知
# ─────────────────────────────────────────────────────────────
def _send_detection_mail(event: dict):
    arn           = event["arn"]
    missing_tags  = event["missingTags"]
    required_tags = event["requiredTags"]
    principal     = event.get("principal", "unknown")
    region        = event.get("region", "unknown")
    event_name    = event.get("eventName", "unknown")
    delay_days    = DELETE_DELAY_SECONDS // 86400
    is_iam        = re.search(r"arn:aws:iam:.+:(role|user)/", arn) is not None
    iso        = event.get("isolation", {})
    iso_status = iso.get("isolationStatus") if isinstance(iso, dict) else None
    lost       = iso.get("lostPolicy", {}) if isinstance(iso, dict) else {}
    lost_note = ""
    if not is_iam and lost.get("had") and lost.get("body"):
        body = lost.get("body", "")
        summary_lines = _summarize_policy_statements(body)
        lost_note = "\n".join([
            "",
            "【⚠️ 元のリソースポリシーは自動復元されません】",
            "  隔離時に元のポリシーは全拒否ポリシーで上書きされました。",
            "  タグ付与による自動復旧では deny を外すのみで、元ポリシーは戻りません。",
            "",
            "  元ポリシーの Statement 概要:",
            *summary_lines,
            "",
            "  必要なら以下を手動で再適用してください（sha256 はリソースタグに保存済み）:",
            "",
            body,
        ])

    subject = f"[TagWatchman] Resource quarantined: {arn.split('/')[-1]}"

    # 全置換系 API（put_bucket_tagging 等）を持つサービス向けの運用案内
    retag_note = "\n".join([
        "  ※既存タグ(tagwatchman:で始まる痕跡タグ等)は削除せず保持してください。",
        "    AWS コンソールからの追加、または CLI の場合は既存タグを取得",
        "    してから必須タグを追加する形で付与することを推奨します。",
    ])

    # isolationStatus に応じた専用メッセージ（status 不在時のみ regex フォールバック）
    if iso_status == "isolation_failed":
        isolation_note = "\n".join([
            "【⚠️ 自動隔離に失敗しました】",
            "  リソースの自動隔離処理がエラーで完了しませんでした。",
            "  リソースは隔離されていない可能性があります。",
            "",
            "【⚠️ 人間による対応が必要です】",
            "  1. リソースの状態を確認し、必要なら手動で隔離・停止してください。",
            "  2. 必須タグを付与してください。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    elif iso_status == "permissions_revoked" or (iso_status is None and is_iam):
        recovery_lines = []
        if lost.get("had") and lost.get("body"):
            recovery_lines = [
                "",
                "【剥奪した権限（復旧用・自動復旧はされません）】",
                "  以下は隔離前に付与されていた内容です。手動復旧の際に参照してください。",
                "",
                lost.get("body", ""),
            ]
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・アタッチ済みポリシーをすべて剥奪しました",
            "  ・アクセスキーをすべて無効化しました(IAM Userの場合)",
            "",
            "【⚠️ 人間による対応が必要です】",
            "  IAMリソースの復旧は自動化できません。",
            "  心当たりのあるリソースの場合は以下を手動で対応してください:",
            "  1. 必須タグを付与する",
            "  2. 必要なポリシーを再アタッチする",
            "  3. 必要なアクセスキーを再作成・有効化する",
            *recovery_lines,
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    elif iso_status == "notify_only":
        isolation_note = "\n".join([
            "【検知のみ・隔離は行っていません】",
            "  このサービスは自動隔離・自動削除の対象外です。",
            "  (隔離方式が AWS 仕様上適用できない、または隔離リスクが高いため)",
            "",
            "【⚠️ 人間による対応が必要です】",
            "  1. 必須タグを付与してください。",
            "  2. 不要なリソースの場合は手動で削除してください。",
            "",
            "  ※このリソースは自動削除されません(削除承認メールも送信されません)。",
        ])
    elif iso_status == "skipped":
        isolation_note = "\n".join([
            "【検知のみ・隔離は行っていません】",
            "  このリソース種別は自動隔離に未対応、またはリソースが既に存在しません。",
            "",
            "【対応方法】",
            "  リソースが存在する場合は必須タグを付与してください。",
            "",
            "  ※このリソースは自動削除されません(削除承認メールも送信されません)。",
        ])
    elif iso_status == "self_protected":
        isolation_note = "\n".join([
            "【検知のみ・隔離は行っていません】",
            "  TagWatchman 自身の構成リソースのため、隔離・削除の対象外です。",
            "",
            "【対応方法】",
            "  必要に応じて必須タグを付与してください。",
            "",
            "  ※このリソースは自動削除されません(削除承認メールも送信されません)。",
        ])
    elif iso_status == "dry_run":
        isolation_note = "\n".join([
            "【DRY RUN・隔離は行っていません】",
            "  検証モードのため、実際の隔離処理はスキップされました。",
        ])
    elif iso_status == "policy_denied":
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・リソースポリシーで全操作を拒否しました(APIアクセス遮断)",
            "",
            "【対応方法】",
            "  上記の必須タグをリソースに付与してください。",
            "  タグ付与後、自動的に隔離が解除されます。",
            "",
            retag_note,
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    elif iso_status == "concurrency_zero":
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・同時実行数を 0 に設定しました(新規実行をすべて拒否)",
            "",
            "【対応方法】",
            "  上記の必須タグをリソースに付与してください。",
            "  タグ付与後、自動的に隔離が解除されます。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    elif iso_status == "stages_deleted":
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・全ステージを削除しました(エンドポイント無効化)",
            "  ・ステージ構成はリソースタグに保存済みです",
            "",
            "【対応方法】",
            "  上記の必須タグをリソースに付与してください。",
            "  タグ付与後、自動的に隔離が解除されます。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    elif iso_status == "network_immediate_delete":
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・未使用リソースのため即時削除しました",
            "",
            "【対応方法】",
            "  対応は不要です。意図して作成したリソースだった場合は",
            "  再作成し、作成時に必須タグを付与してください。",
            "",
            "  ※削除承認メールは送信されません(処理は完了しています)。",
        ])
    elif iso_status == "network_manual_review":
        isolation_note = "\n".join([
            "【検知のみ・自動削除をスキップしました】",
            "  リソースが使用中(アタッチ/関連付けあり)のため、即時削除を行いませんでした。",
            "",
            "【⚠️ 人間による対応が必要です】",
            "  1. 必要なリソースの場合は必須タグを付与してください。",
            "  2. 不要な場合は手動で確認のうえ削除してください。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
            "  承認すると、使用中でもデタッチ/関連付け解除のうえ削除されます。",
        ])
    elif iso_status == "network_isolated":
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・ネットワークを隔離しました(通信遮断)",
            "",
            "【対応方法】",
            "  上記の必須タグをリソースに付与してください。",
            "  タグ付与後、自動的に隔離が解除されます。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    else:
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・リソースを隔離しました",
            "",
            "【対応方法】",
            "  上記の必須タグをリソースに付与してください。",
            "  タグ付与後、自動的に隔離が解除されます。",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])

    message = "\n".join([
        "=" * 60,
        "  TagWatchman — リソース検知・隔離通知",
        "=" * 60,
        "",
        "タグが不足しているリソースを検知しました。",
        "",
        "【リソース情報】",
        f"  ARN       : {arn}",
        f"  リージョン: {region}",
        f"  操作      : {event_name}",
        f"  実行者    : {principal}",
        "",
        "【タグ情報】",
        f"  不足タグ  : {', '.join(missing_tags)}",
        f"  必須タグ  : {', '.join(required_tags)}",
        "",
        isolation_note,
        lost_note,
        "=" * 60,
    ])

    _publish(subject, message)
    logger.info("Detection mail sent for ARN: %s", arn)


# ─────────────────────────────────────────────────────────────
# メール② 削除承認依頼
# ─────────────────────────────────────────────────────────────

def _send_approval_mail(event: dict):
    arn            = event["arn"]
    missing_tags   = event["missingTags"]
    required_tags  = event["requiredTags"]
    principal      = event.get("principal", "unknown")
    region         = event.get("region", "unknown")
    execution_id   = event.get("executionId", "")
    is_iam         = re.search(r"arn:aws:iam:.+:(role|user)/", arn) is not None

    approval_url = f"{APPROVAL_BASE_URL}/approve?token={execution_id}&arn={arn}"

    iam_note = "\n".join([
        "【⚠️ IAMリソースの削除前に確認してください】",
        "  このリソースに依存しているシステムがないか確認してください。",
        "  削除後の復旧はできません。",
        "",
    ]) if is_iam else ""

    subject = f"[TagWatchman] Deletion approval required: {arn.split('/')[-1]}"
    message = "\n".join(filter(None, [
        "=" * 60,
        "  TagWatchman — 削除承認依頼",
        "=" * 60,
        "",
        "以下のリソースはタグが付与されないまま猶予期間を過ぎました。",
        "削除してよい場合は、下記の承認URLをクリックしてください。",
        "",
        "【リソース情報】",
        f"  ARN       : {arn}",
        f"  リージョン: {region}",
        f"  実行者    : {principal}",
        "",
        "【タグ情報】",
        f"  不足タグ  : {', '.join(missing_tags)}",
        f"  必須タグ  : {', '.join(required_tags)}",
        "",
        iam_note,
        "【承認URL】",
        f"  {approval_url}",
        "",
        "  ※ このURLは監視フローが終了するまで（最大30日間）有効です。",
        "     複数回クリックしても、削除は一度しか実行されません。",
        "  ※ 削除後の復旧はできません。",
        "  ※ 削除の完了/失敗は結果メールでお知らせします。",
        "     あわせてAWSコンソールでもご確認ください。",
        "  ※ 心当たりのあるリソースの場合は、タグを付与してください。",
        "     タグ付与後、隔離は自動的に解除されます。",
        "=" * 60,
    ]))

    _publish(subject, message)
    logger.info("Approval mail sent for ARN: %s", arn)


# ─────────────────────────────────────────────────────────────
# SNS 送信
# ─────────────────────────────────────────────────────────────

def _publish(subject: str, message: str):
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set — skipping")
        return
    # SNS Subject 制約: ASCII・改行/制御文字なし・100字未満
    subject = subject.encode("ascii", "replace").decode("ascii")
    subject = subject.replace("\n", " ").replace("\r", " ")[:99]
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except ClientError as e:
        logger.error("SNS publish failed: %s", e)
        raise
