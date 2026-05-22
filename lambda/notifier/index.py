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

    subject = f"[TagWatchman] リソース検知・隔離: {arn.split('/')[-1]}"

    # IAMは隔離方法と復旧方法が異なるため専用メッセージを用意
    if is_iam:
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・アタッチ済みポリシーをすべて剥奪しました",
            "  ・アクセスキーをすべて無効化しました（IAM Userの場合）",
            "",
            "【⚠️ 人間による対応が必要です】",
            "  IAMリソースの復旧は自動化できません。",
            "  心当たりのあるリソースの場合は以下を手動で対応してください：",
            "  1. 必須タグを付与する",
            "  2. 必要なポリシーを再アタッチする",
            "  3. 必要なアクセスキーを再作成・有効化する",
            "",
            f"  タグが付与されない場合、{delay_days}日後に削除承認メールが送信されます。",
        ])
    else:
        isolation_note = "\n".join([
            "【自動対応済み】",
            "  ・ネットワークを隔離しました（通信遮断）",
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

    subject = f"[TagWatchman] 削除承認依頼: {arn.split('/')[-1]}"
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
        "  ※ このURLは1回限り有効です。",
        "  ※ 削除後の復旧はできません。",
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
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except ClientError as e:
        logger.error("SNS publish failed: %s", e)
        raise
