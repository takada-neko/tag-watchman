"""
approver/index.py
─────────────────
承認URLクリック → API Gateway → このLambda

役割:
  1. クエリパラメータからトークン（Step Functions実行ID）とARNを取得
  2. Step Functions の実行が有効か検証
  3. Deleter Lambda を呼び出して削除実行
  4. ブラウザに完了ページを返す
"""

import json
import logging
import os
import urllib.parse
import html as htmllib

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DELETER_FUNCTION_ARN = os.environ.get("DELETER_FUNCTION_ARN", "")
STATE_MACHINE_ARN    = os.environ.get("STATE_MACHINE_ARN", "")

sfn    = boto3.client("stepfunctions")
_lambda = boto3.client("lambda")


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    logger.info("Approval request: %s", json.dumps(event))

    method = (event.get("httpMethod") or "").upper()
    params = event.get("queryStringParameters") or {}
    token  = params.get("token", "")
    arn    = urllib.parse.unquote(params.get("arn", ""))

    # バリデーション
    if not token or not arn:
        return _response(400, "不正なリクエストです。URLを確認してください。")

    # hard invariant: deleter invoke は POST 経路のみ。
    # GET は確認ページを返すだけで副作用ゼロ（メールのリンクスキャナ/プリフェッチ対策）。
    if method == "GET":
        return _confirmation_page(token, arn)
    if method == "POST":
        return _execute_approval(token, arn)
    return _response(405, "許可されていないメソッドです。")


def _confirmation_page(token: str, arn: str) -> dict:
    """GET: 副作用ゼロ。対象を表示して POST 承認フォームを返すだけ。
    describe-execution は読み取りのみで状態を変えない。"""
    valid, execution_input = _validate_token(token)
    if not valid:
        return _response(410, "このURLはすでに使用済みか、有効期限が切れています。")
    if execution_input.get("arn") != arn:
        return _response(400, "不正なリクエストです。")

    service = arn.split(":")[2] if len(arn.split(":")) > 2 else "?"
    region  = execution_input.get("region", "?")
    return _html_response(200, _confirm_html(token, arn, service, region))


def _execute_approval(token: str, arn: str) -> dict:
    """POST: 副作用あり。検証段 → invoke 段。
    v1.5 の署名トークン検証は、この検証段の先頭に差し込む（口を空けてある）。"""
    # --- 検証段（v1.5: ここに署名トークン検証を追加する）---
    valid, execution_input = _validate_token(token)
    if not valid:
        return _response(410, "このURLはすでに使用済みか、有効期限が切れています。")
    if execution_input.get("arn") != arn:
        return _response(400, "不正なリクエストです。")

    # --- invoke 段 ---
    try:
        _invoke_deleter(execution_input)
        logger.info("Deletion approved for ARN: %s", arn)
        return _response(200, f"削除を承認しました。\n\nARN: {arn}\n\nリソースの削除を開始しました。")
    except Exception as e:
        logger.error("Deletion failed for %s: %s", arn, e)
        return _response(500, "削除処理中にエラーが発生しました。AWSコンソールを確認してください。")


def _esc(s) -> str:
    return htmllib.escape(str(s), quote=True)


def _confirm_html(token: str, arn: str, service: str, region: str) -> str:
    """確認ページ。フォームは action 省略で同一 URL（token/arn をクエリ保持）に POST する。"""
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>削除承認の確認</title>
</head>
<body style="font-family:sans-serif;max-width:620px;margin:40px auto;padding:0 16px;color:#222;">
<h2>削除の承認</h2>
<p>以下のリソースの<strong>削除</strong>を承認しようとしています。内容を確認してください。</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0;">
<tr><td style="padding:8px;color:#666;width:120px;">ARN</td><td style="padding:8px;font-family:monospace;word-break:break-all;">{_esc(arn)}</td></tr>
<tr><td style="padding:8px;color:#666;">サービス</td><td style="padding:8px;">{_esc(service)}</td></tr>
<tr><td style="padding:8px;color:#666;">リージョン</td><td style="padding:8px;">{_esc(region)}</td></tr>
</table>
<p style="color:#b00020;"><strong>この操作は取り消せません。</strong>リソースは削除されます。</p>
<form method="POST">
<button type="submit" style="background:#b00020;color:#fff;border:0;padding:12px 28px;font-size:16px;border-radius:4px;cursor:pointer;">削除を承認する</button>
</form>
<p style="color:#888;font-size:13px;margin-top:28px;">承認しない場合はこのページを閉じてください。リソースは削除されません。ただし、この段階では隔離（アクセス拒否）は自動的には解除されず、解除には運用者の手動対応が必要です。</p>
</body>
</html>"""


def _html_response(status_code: int, body: str) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": body,
    }


# ─────────────────────────────────────────────────────────────
# トークン検証
# Step Functions の実行IDを使い、実行が存在し有効かを確認
# ─────────────────────────────────────────────────────────────

def _validate_token(execution_id: str) -> tuple[bool, dict]:
    """
    Returns:
        (is_valid, execution_input)
    """
    # execution_id からARNを構築
    execution_arn = f"{STATE_MACHINE_ARN.replace(':stateMachine:', ':execution:')}:{execution_id}"

    try:
        resp = sfn.describe_execution(executionArn=execution_arn)
        status = resp.get("status", "")

        # RUNNING 以外（すでに完了・失敗・タイムアウト）は無効
        if status != "RUNNING":
            logger.warning("Execution %s is not RUNNING: %s", execution_id, status)
            return False, {}

        execution_input = json.loads(resp.get("input", "{}"))
        return True, execution_input

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ExecutionDoesNotExist":
            logger.warning("Execution not found: %s", execution_id)
        else:
            logger.error("SFN describe error: %s", e)
        return False, {}


# ─────────────────────────────────────────────────────────────
# Deleter Lambda を呼び出す
# ─────────────────────────────────────────────────────────────

def _invoke_deleter(execution_input: dict):
    if not DELETER_FUNCTION_ARN:
        raise ValueError("DELETER_FUNCTION_ARN not set")

    _lambda.invoke(
        FunctionName=DELETER_FUNCTION_ARN,
        InvocationType="Event",  # 非同期
        Payload=json.dumps(execution_input).encode(),
    )
    logger.info("Deleter invoked for ARN: %s", execution_input.get("arn"))


# ─────────────────────────────────────────────────────────────
# HTTPレスポンス（プレーンテキスト）
# ─────────────────────────────────────────────────────────────

def _response(status_code: int, message: str) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/plain; charset=utf-8"},
        "body": message,
    }
