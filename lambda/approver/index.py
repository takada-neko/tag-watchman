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

    params = event.get("queryStringParameters") or {}
    token  = params.get("token", "")
    arn    = urllib.parse.unquote(params.get("arn", ""))

    # バリデーション
    if not token or not arn:
        return _response(400, "不正なリクエストです。URLを確認してください。")

    # トークン検証（Step Functions実行IDの有効性確認）
    valid, execution_input = _validate_token(token)
    if not valid:
        return _response(410, "このURLはすでに使用済みか、有効期限が切れています。")

    # ARNの一致確認
    if execution_input.get("arn") != arn:
        return _response(400, "不正なリクエストです。")

    # 削除実行
    try:
        _invoke_deleter(execution_input)
        logger.info("Deletion approved for ARN: %s", arn)
        return _response(200, f"削除を承認しました。\n\nARN: {arn}\n\nリソースの削除を開始しました。")
    except Exception as e:
        logger.error("Deletion failed for %s: %s", arn, e)
        return _response(500, "削除処理中にエラーが発生しました。AWSコンソールを確認してください。")


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
