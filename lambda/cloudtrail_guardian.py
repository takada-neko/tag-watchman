"""
cloudtrail_guardian/index.py
─────────────────────────────
CloudTrail の無効化・削除を検知する専用Lambda。
タグ関係なく即時発動する TagWatchman の生命線保護フロー。

検知対象イベント:
  - StopLogging    → 即時再有効化 + 最強警告
  - DeleteTrail    → 再作成は困難なため最強警告のみ
  - UpdateTrail    → 設定改ざんの可能性があるため警告
  - PutEventSelectors → イベント取得範囲の改ざん可能性があるため警告

対応フロー:
  StopLogging  → 自動で StartLogging → SNS最強警告
  DeleteTrail  → SNS最強警告（再作成は人間が対応）
  UpdateTrail  → SNS警告
  PutEventSelectors → SNS警告
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

cloudtrail = boto3.client("cloudtrail")
sns        = boto3.client("sns")

# 重大度レベル
SEVERITY_CRITICAL = "🚨🚨🚨 CRITICAL"
SEVERITY_WARNING  = "⚠️ WARNING"


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    logger.info("CloudTrail Guardian triggered: %s", json.dumps(event))

    detail      = event.get("detail", {})
    event_name  = detail.get("eventName", "")
    principal   = detail.get("userIdentity", {}).get("arn", "unknown")
    region      = detail.get("awsRegion", "unknown")
    event_time  = detail.get("eventTime", "unknown")

    # Trail名を取得
    trail_name = _extract_trail_name(event_name, detail)

    handlers = {
        "StopLogging":       _handle_stop_logging,
        "DeleteTrail":       _handle_delete_trail,
        "UpdateTrail":       _handle_update_trail,
        "PutEventSelectors": _handle_put_event_selectors,
    }

    handler = handlers.get(event_name)
    if handler is None:
        logger.info("Unhandled event: %s", event_name)
        return {"status": "skipped"}

    return handler(trail_name, principal, region, event_time, detail)


# ─────────────────────────────────────────────────────────────
# StopLogging → 自動再有効化 + CRITICAL警告
# ─────────────────────────────────────────────────────────────

def _handle_stop_logging(trail_name, principal, region, event_time, detail):
    logger.critical("CloudTrail StopLogging detected! Trail: %s by %s", trail_name, principal)

    # 自動で再有効化
    re_enabled = False
    error_msg  = ""
    if trail_name:
        try:
            cloudtrail.start_logging(Name=trail_name)
            re_enabled = True
            logger.info("CloudTrail re-enabled: %s", trail_name)
        except ClientError as e:
            error_msg = str(e)
            logger.error("Failed to re-enable CloudTrail: %s", e)

    subject = f"{SEVERITY_CRITICAL} CloudTrail が無効化されました"
    message = "\n".join([
        "=" * 60,
        "  TagWatchman — CloudTrail 無効化検知",
        "=" * 60,
        "",
        "  ⚠️  CloudTrail のログ記録が停止されました。",
        "  攻撃者が証跡を隠蔽しようとしている可能性があります。",
        "  直ちに調査してください。",
        "",
        "【検知情報】",
        f"  Trail名    : {trail_name or '不明'}",
        f"  実行者     : {principal}",
        f"  リージョン : {region}",
        f"  発生時刻   : {event_time}",
        "",
        "【自動対応】",
        f"  再有効化   : {'✅ 成功' if re_enabled else f'❌ 失敗 — {error_msg}'}",
        "",
        "【推奨アクション】",
        "  1. 実行者のIAM権限を即時確認・停止",
        "  2. 同時期に作成された不審なリソースを確認",
        "  3. CloudTrailが再有効化されているか確認",
        "  4. 必要に応じてAWS Supportに連絡",
        "=" * 60,
    ])

    _publish(subject, message)
    return {"status": "handled", "event": "StopLogging", "re_enabled": re_enabled}


# ─────────────────────────────────────────────────────────────
# DeleteTrail → CRITICAL警告（再作成は人間が対応）
# ─────────────────────────────────────────────────────────────

def _handle_delete_trail(trail_name, principal, region, event_time, detail):
    logger.critical("CloudTrail DeleteTrail detected! Trail: %s by %s", trail_name, principal)

    subject = f"{SEVERITY_CRITICAL} CloudTrail が削除されました"
    message = "\n".join([
        "=" * 60,
        "  TagWatchman — CloudTrail 削除検知",
        "=" * 60,
        "",
        "  🚨 CloudTrail の証跡が削除されました。",
        "  AWS上の全操作ログが記録されない状態です。",
        "  直ちに対応してください。",
        "",
        "【検知情報】",
        f"  Trail名    : {trail_name or '不明'}",
        f"  実行者     : {principal}",
        f"  リージョン : {region}",
        f"  発生時刻   : {event_time}",
        "",
        "【自動対応】",
        "  再作成     : ❌ 手動対応が必要です",
        "",
        "【推奨アクション】",
        "  1. 実行者のIAM権限を即時停止",
        "  2. CloudTrailを直ちに再作成",
        "  3. 削除前のログをS3から確認",
        "  4. 同時期に作成された不審なリソースを確認",
        "  5. 必要に応じてAWS Supportに連絡",
        "=" * 60,
    ])

    _publish(subject, message)
    return {"status": "handled", "event": "DeleteTrail"}


# ─────────────────────────────────────────────────────────────
# UpdateTrail → WARNING警告
# ─────────────────────────────────────────────────────────────

def _handle_update_trail(trail_name, principal, region, event_time, detail):
    logger.warning("CloudTrail UpdateTrail detected! Trail: %s by %s", trail_name, principal)

    # 変更内容を取得
    params = detail.get("requestParameters", {})

    subject = f"{SEVERITY_WARNING} CloudTrail の設定が変更されました"
    message = "\n".join([
        "=" * 60,
        "  TagWatchman — CloudTrail 設定変更検知",
        "=" * 60,
        "",
        "  CloudTrail の設定が変更されました。",
        "  意図した変更か確認してください。",
        "",
        "【検知情報】",
        f"  Trail名    : {trail_name or '不明'}",
        f"  実行者     : {principal}",
        f"  リージョン : {region}",
        f"  発生時刻   : {event_time}",
        f"  変更内容   : {json.dumps(params, ensure_ascii=False, indent=2)}",
        "",
        "【推奨アクション】",
        "  1. 変更内容が意図したものか確認",
        "  2. 心当たりがない場合は実行者のIAM権限を確認",
        "=" * 60,
    ])

    _publish(subject, message)
    return {"status": "handled", "event": "UpdateTrail"}


# ─────────────────────────────────────────────────────────────
# PutEventSelectors → WARNING警告
# ─────────────────────────────────────────────────────────────

def _handle_put_event_selectors(trail_name, principal, region, event_time, detail):
    logger.warning("CloudTrail PutEventSelectors detected! Trail: %s by %s", trail_name, principal)

    params = detail.get("requestParameters", {})

    subject = f"{SEVERITY_WARNING} CloudTrail のイベント取得範囲が変更されました"
    message = "\n".join([
        "=" * 60,
        "  TagWatchman — CloudTrail イベントセレクター変更検知",
        "=" * 60,
        "",
        "  CloudTrail のイベント取得範囲が変更されました。",
        "  特定のイベントが記録されなくなった可能性があります。",
        "",
        "【検知情報】",
        f"  Trail名    : {trail_name or '不明'}",
        f"  実行者     : {principal}",
        f"  リージョン : {region}",
        f"  発生時刻   : {event_time}",
        f"  変更内容   : {json.dumps(params, ensure_ascii=False, indent=2)}",
        "",
        "【推奨アクション】",
        "  1. イベントセレクターの設定を確認",
        "  2. 必要なイベントが記録対象になっているか確認",
        "  3. 心当たりがない場合は実行者のIAM権限を確認",
        "=" * 60,
    ])

    _publish(subject, message)
    return {"status": "handled", "event": "PutEventSelectors"}


# ─────────────────────────────────────────────────────────────
# ユーティリティ
# ─────────────────────────────────────────────────────────────

def _extract_trail_name(event_name: str, detail: dict) -> str:
    try:
        params = detail.get("requestParameters", {})
        return params.get("name") or params.get("trailName", "")
    except Exception:
        return ""


def _publish(subject: str, message: str):
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set — skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        logger.info("SNS published: %s", subject)
    except ClientError as e:
        logger.error("SNS publish failed: %s", e)
        raise
