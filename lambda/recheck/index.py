"""
recheck/index.py
────────────────
Step Functions の Wait 後に再度タグをチェックする。
 
タグが付与されていた場合 → Restorer Lambda を呼んで隔離解除
タグがまだ不足している場合 → 削除フローへ進む
"""
 
import logging
import os
 
import boto3
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
REQUIRED_TAGS    = [t.strip() for t in os.environ.get("REQUIRED_TAGS", "Env,Owner,Project").split(",")]
RESTORER_ARN     = os.environ.get("RESTORER_FUNCTION_ARN", "")
 
tagging  = boto3.client("resourcegroupstaggingapi")
_lambda  = boto3.client("lambda")
 
 
def lambda_handler(event, context):
    arn = event["arn"]
    logger.info("Rechecking tags for ARN: %s", arn)
 
    missing = _check_tags(arn)
    still_missing = len(missing) > 0
 
    if not still_missing:
        # タグが付与された → 隔離解除
        logger.info("Tags now complete for %s — restoring", arn)
        _invoke_restorer(event)
    else:
        logger.warning("Still missing tags %s for %s — proceeding to approval", missing, arn)
 
    return {
        **event,
        "missingTags":      missing,
        "stillMissingTags": still_missing,
    }
 
 
def _check_tags(arn: str) -> list[str]:
    try:
        resp = tagging.get_resources(ResourceARNList=[arn])
        resources = resp.get("ResourceTagMappingList", [])
        if not resources:
            return REQUIRED_TAGS
        existing_keys = {t["Key"] for t in resources[0].get("Tags", [])}
        # tagwatchman:* タグは判定から除外
        existing_keys = {k for k in existing_keys if not k.startswith("tagwatchman:")}
        return [tag for tag in REQUIRED_TAGS if tag not in existing_keys]
    except Exception as e:
        logger.error("Recheck tag error for %s: %s", arn, e)
        return REQUIRED_TAGS
 
 
def _invoke_restorer(event: dict):
    if not RESTORER_ARN:
        logger.warning("RESTORER_FUNCTION_ARN not set — skipping restore")
        return
    import json
    _lambda.invoke(
        FunctionName=RESTORER_ARN,
        InvocationType="Event",  # 非同期
        Payload=json.dumps(event).encode(),
    )
    logger.info("Restorer invoked for ARN: %s", event["arn"])
 