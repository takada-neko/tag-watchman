"""
recheck/index.py
────────────────
Step Functions の Wait 後に再度タグをチェックする。
tag_validator を使い detector と同じバリデーションロジックで判定。
 
タグが付与されていた場合 → Restorer Lambda を呼んで隔離解除
タグがまだ不足している場合 → 削除フローへ進む
"""
 
import json
import logging
import os
 
import boto3
 
from tag_validator import fetch_and_validate
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
RESTORER_ARN = os.environ.get("RESTORER_FUNCTION_ARN", "")
_lambda      = boto3.client("lambda")
 
 
def lambda_handler(event, context):
    arn = event["arn"]
    logger.info("Rechecking tags for ARN: %s", arn)
 
    missing       = fetch_and_validate(arn)
    still_missing = len(missing) > 0
 
    if not still_missing:
        logger.info("Tags now valid for %s — restoring", arn)
        _invoke_restorer(event)
    else:
        logger.warning("Still violating tags %s for %s — proceeding to approval", missing, arn)
 
    return {
        **event,
        "missingTags":      missing,
        "stillMissingTags": still_missing,
    }
 
 
def _invoke_restorer(event: dict):
    if not RESTORER_ARN:
        logger.warning("RESTORER_FUNCTION_ARN not set — skipping restore")
        return
    _lambda.invoke(
        FunctionName=RESTORER_ARN,
        InvocationType="Event",
        Payload=json.dumps(event).encode(),
    )
    logger.info("Restorer invoked for ARN: %s", event["arn"])
 