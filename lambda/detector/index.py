"""
detector/index.py
─────────────────
EventBridge (CloudTrail) → このLambda → Step Functions へ渡す
 
役割:
  1. CloudTrail イベントから作成されたリソースの ARN を抽出
  2. Resource Groups Tagging API で必須タグをチェック
  3. タグ不足なら Step Functions (notifier+deleter) を起動
 
新しいAWSサービスに対応するには RESOURCE_EXTRACTORS に追記するだけ。
"""
 
import json
import logging
import os
import re
import time
from typing import Optional
 
import boto3
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
REQUIRED_TAGS       = [t.strip() for t in os.environ.get("REQUIRED_TAGS", "Env,Owner,Project").split(",")]
STATE_MACHINE_ARN   = os.environ.get("STATE_MACHINE_ARN", "")
ACCOUNT_ID          = boto3.client("sts").get_caller_identity()["Account"]
DEFAULT_REGION      = os.environ.get("AWS_REGION", "ap-northeast-1")
 
tagging = boto3.client("resourcegroupstaggingapi")
sfn     = boto3.client("stepfunctions")
 
 
# ─────────────────────────────────────────────────────────────
# ARN 抽出ルール
# キー   : CloudTrail の eventSource (例: "ec2.amazonaws.com")
# 値     : (eventName パターン, ARN構築関数)
#
# ここに追記するだけで新サービスに対応できます。
# ─────────────────────────────────────────────────────────────
 
def _ec2_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        iid = detail["responseElements"]["instancesSet"]["items"][0]["instanceId"]
        return f"arn:aws:ec2:{region}:{account}:instance/{iid}"
    except (KeyError, IndexError):
        return None
 
def _rds_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        db_id = detail["requestParameters"]["dBInstanceIdentifier"]
        return f"arn:aws:rds:{region}:{account}:db:{db_id}"
    except KeyError:
        return None
 
def _s3_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        bucket = detail["requestParameters"]["bucketName"]
        return f"arn:aws:s3:::{bucket}"
    except KeyError:
        return None
 
def _lambda_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["functionName"]
        return f"arn:aws:lambda:{region}:{account}:function:{name}"
    except KeyError:
        return None
 
def _dynamodb_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["tableName"]
        return f"arn:aws:dynamodb:{region}:{account}:table/{name}"
    except KeyError:
        return None
 
def _ecs_cluster_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["cluster"]["clusterArn"]
    except KeyError:
        return None
 
def _ecs_service_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["service"]["serviceArn"]
    except KeyError:
        return None
 
def _sqs_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        url = detail["responseElements"]["queueUrl"]
        # URL形式: https://sqs.<region>.amazonaws.com/<account>/<name>
        name = url.rstrip("/").split("/")[-1]
        return f"arn:aws:sqs:{region}:{account}:{name}"
    except KeyError:
        return None
 
def _sns_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["topicArn"]
    except KeyError:
        return None
 
def _eks_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["cluster"]["arn"]
    except KeyError:
        return None
 
def _kinesis_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["streamName"]
        return f"arn:aws:kinesis:{region}:{account}:stream/{name}"
    except KeyError:
        return None
 
def _elasticache_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        cid = detail["requestParameters"]["replicationGroupId"]
        return f"arn:aws:elasticache:{region}:{account}:replicationgroup:{cid}"
    except KeyError:
        return None
 
def _opensearch_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["domainName"]
        return f"arn:aws:es:{region}:{account}:domain/{name}"
    except KeyError:
        return None
 
def _glue_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["name"]
        return f"arn:aws:glue:{region}:{account}:database/{name}"
    except KeyError:
        return None
 
 
# eventSource → {対象 eventName → ARN抽出関数}
RESOURCE_EXTRACTORS: dict[str, dict[str, callable]] = {
    "ec2.amazonaws.com": {
        "RunInstances": _ec2_arn,
    },
    "rds.amazonaws.com": {
        "CreateDBInstance":                  _rds_arn,
        "RestoreDBInstanceFromDBSnapshot":   _rds_arn,
        "RestoreDBInstanceToPointInTime":    _rds_arn,
    },
    "s3.amazonaws.com": {
        "CreateBucket": _s3_arn,
    },
    "lambda.amazonaws.com": {
        "CreateFunction20150331": _lambda_arn,
        "CreateFunction":         _lambda_arn,
    },
    "dynamodb.amazonaws.com": {
        "CreateTable":           _dynamodb_arn,
        "RestoreTableFromBackup": _dynamodb_arn,
    },
    "ecs.amazonaws.com": {
        "CreateCluster": _ecs_cluster_arn,
        "CreateService": _ecs_service_arn,
    },
    "sqs.amazonaws.com": {
        "CreateQueue": _sqs_arn,
    },
    "sns.amazonaws.com": {
        "CreateTopic": _sns_arn,
    },
    "eks.amazonaws.com": {
        "CreateCluster": _eks_arn,
    },
    "kinesis.amazonaws.com": {
        "CreateStream": _kinesis_arn,
    },
    "elasticache.amazonaws.com": {
        "CreateReplicationGroup": _elasticache_arn,
    },
    "es.amazonaws.com": {
        "CreateDomain":        _opensearch_arn,
        "CreateElasticsearchDomain": _opensearch_arn,
    },
    "glue.amazonaws.com": {
        "CreateDatabase": _glue_arn,
    },
}
 
 
# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────
 
def lambda_handler(event, context):
    logger.info("Event: %s", json.dumps(event))
 
    detail      = event.get("detail", {})
    event_source = detail.get("eventSource", "")
    event_name   = detail.get("eventName", "")
    region       = detail.get("awsRegion", DEFAULT_REGION)
 
    # 対応サービス・イベントか確認
    extractors_for_source = RESOURCE_EXTRACTORS.get(event_source, {})
    extractor = extractors_for_source.get(event_name)
 
    if extractor is None:
        logger.info("No extractor for %s / %s — skipping", event_source, event_name)
        return {"status": "skipped"}
 
    # ARN 抽出
    arn = extractor(detail, region, ACCOUNT_ID)
    if not arn:
        logger.warning("ARN extraction failed for %s / %s", event_source, event_name)
        return {"status": "error", "reason": "arn_extraction_failed"}
 
    logger.info("Extracted ARN: %s", arn)
 
    # 少し待機（リソースがタグAPIに反映されるまでのラグ対策）
    time.sleep(5)
 
    # タグチェック（Resource Groups Tagging API で統一）
    missing_tags = _check_tags(arn)
 
    if not missing_tags:
        logger.info("All required tags present for %s", arn)
        return {"status": "ok", "arn": arn}
 
    logger.warning("Missing tags %s for %s", missing_tags, arn)
 
    # Step Functions を起動（通知→待機→削除）
    _start_state_machine(arn, missing_tags, event_name, detail)
 
    return {"status": "triggered", "arn": arn, "missing_tags": missing_tags}
 
 
# ─────────────────────────────────────────────────────────────
# タグチェック（Resource Groups Tagging API）
# ─────────────────────────────────────────────────────────────
 
def _check_tags(arn: str) -> list[str]:
    """
    Resource Groups Tagging API を使い、ARN のタグを取得する。
    S3 は ARN にリージョン/アカウントが含まれないため個別対応。
    """
    try:
        resp = tagging.get_resources(ResourceARNList=[arn])
        resources = resp.get("ResourceTagMappingList", [])
 
        if not resources:
            logger.warning("No tag data returned for ARN: %s (treating as untagged)", arn)
            return REQUIRED_TAGS
 
        existing_keys = {t["Key"] for t in resources[0].get("Tags", [])}
        return [tag for tag in REQUIRED_TAGS if tag not in existing_keys]
 
    except Exception as e:
        logger.error("Tag check error for %s: %s", arn, e)
        return REQUIRED_TAGS  # 安全側に倒す
 
 
# ─────────────────────────────────────────────────────────────
# Step Functions 起動
# ─────────────────────────────────────────────────────────────
 
def _start_state_machine(arn: str, missing_tags: list[str], event_name: str, detail: dict):
    if not STATE_MACHINE_ARN:
        logger.error("STATE_MACHINE_ARN not set")
        return
 
    payload = {
        "arn":          arn,
        "missingTags":  missing_tags,
        "requiredTags": REQUIRED_TAGS,
        "eventName":    event_name,
        "principal":    detail.get("userIdentity", {}).get("arn", "unknown"),
        "region":       detail.get("awsRegion", DEFAULT_REGION),
    }
 
    sfn.start_execution(
        stateMachineArn=STATE_MACHINE_ARN,
        input=json.dumps(payload),
    )
    logger.info("Started Step Functions for ARN: %s", arn)