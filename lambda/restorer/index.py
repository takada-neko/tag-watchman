"""
restorer/index.py
─────────────────
Recheck Lambda がタグ付与を検知したときに呼ばれる復旧Lambda。

役割:
  1. 隔離時にタグに保存した元の状態を読み取る
  2. SGを元に戻す / ポリシーを削除 / 同時実行数を戻す
  3. tagwatchman:* タグを削除してクリーンアップ
"""

import json
import logging
import os
import re
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"

ec2 = boto3.client("ec2")
rds = boto3.client("rds")
s3  = boto3.client("s3")

TAG_QUARANTINED          = "tagwatchman:quarantined"
TAG_ORIGINAL_SGS         = "tagwatchman:original-sgs"
TAG_ORIGINAL_POLICY      = "tagwatchman:had-bucket-policy"
TAG_ORIGINAL_CONCURRENCY = "tagwatchman:original-concurrency"


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    arn    = event["arn"]
    region = event.get("region", os.environ.get("AWS_REGION", "ap-northeast-1"))

    logger.info("Restoring ARN: %s DRY_RUN=%s", arn, DRY_RUN)

    restorer = _find_restorer(arn)
    if restorer is None:
        logger.warning("No restorer for ARN: %s — skipping", arn)
        return {**event, "restoreStatus": "skipped"}

    if DRY_RUN:
        logger.info("[DRY RUN] Would restore: %s", arn)
        return {**event, "restoreStatus": "dry_run"}

    try:
        restorer(arn, region)
        return {**event, "restoreStatus": "restored"}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidInstanceID.NotFound", "DBInstanceNotFound",
                    "NoSuchBucket", "ResourceNotFoundException"):
            logger.warning("Resource not found: %s (%s)", arn, code)
            return {**event, "restoreStatus": "not_found"}
        logger.error("Restore failed for %s: %s", arn, e)
        raise
    except Exception as e:
        logger.error("Unexpected error restoring %s: %s", arn, e)
        raise


# ─────────────────────────────────────────────────────────────
# EC2 復旧
# ─────────────────────────────────────────────────────────────

def _restore_ec2(arn: str, region: str):
    instance_id = arn.split("/")[-1]
    _ec2 = boto3.client("ec2", region_name=region)

    # タグから元のSGを取得
    resp = _ec2.describe_tags(
        Filters=[
            {"Name": "resource-id",  "Values": [instance_id]},
            {"Name": "key",          "Values": [TAG_ORIGINAL_SGS]},
        ]
    )
    tags = resp.get("Tags", [])
    if not tags:
        logger.warning("No original SG tag found for EC2 %s", instance_id)
        return

    original_sgs = json.loads(tags[0]["Value"])

    # 元のSGに戻す
    _ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=original_sgs,
    )

    # tagwatchman タグを削除
    _ec2.delete_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": TAG_QUARANTINED},
            {"Key": TAG_ORIGINAL_SGS},
        ],
    )

    logger.info("EC2 %s restored. SGS: %s", instance_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# RDS 復旧
# ─────────────────────────────────────────────────────────────

def _restore_rds(arn: str, region: str):
    db_id = arn.split(":")[-1]
    _rds = boto3.client("rds", region_name=region)

    # DBのARNを取得
    resp = _rds.describe_db_instances(DBInstanceIdentifier=db_id)
    db = resp["DBInstances"][0]
    db_arn = db["DBInstanceArn"]

    # タグから元のSGを取得
    tag_resp = _rds.list_tags_for_resource(ResourceName=db_arn)
    tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagList", [])}

    if TAG_ORIGINAL_SGS not in tags:
        logger.warning("No original SG tag found for RDS %s", db_id)
        return

    original_sgs = json.loads(tags[TAG_ORIGINAL_SGS])

    # 元のSGに戻す
    _rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        VpcSecurityGroupIds=original_sgs,
        ApplyImmediately=True,
    )

    # tagwatchman タグを削除
    _rds.remove_tags_from_resource(
        ResourceName=db_arn,
        TagKeys=[TAG_QUARANTINED, TAG_ORIGINAL_SGS],
    )

    logger.info("RDS %s restored. SGS: %s", db_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# S3 復旧
# ─────────────────────────────────────────────────────────────

def _restore_s3(arn: str, region: str):
    bucket = arn.split(":::")[-1]
    _s3 = boto3.client("s3", region_name=region)

    # タグから元のポリシー有無を確認
    try:
        tag_resp = _s3.get_bucket_tagging(Bucket=bucket)
        tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
    except ClientError:
        tags = {}

    # 全拒否ポリシーを削除
    # 元々ポリシーがなかった場合は削除、あった場合も今は削除（元のポリシーは保存していないため）
    try:
        _s3.delete_bucket_policy(Bucket=bucket)
        logger.info("S3 bucket %s deny policy removed", bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise

    # tagwatchman タグを削除
    try:
        existing_tags = tag_resp.get("TagSet", [])
        new_tags = [t for t in existing_tags
                    if t["Key"] not in (TAG_QUARANTINED, TAG_ORIGINAL_POLICY)]
        if new_tags:
            _s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": new_tags})
        else:
            _s3.delete_bucket_tagging(Bucket=bucket)
    except ClientError:
        pass

    logger.info("S3 bucket %s restored", bucket)


# ─────────────────────────────────────────────────────────────
# Lambda 復旧
# ─────────────────────────────────────────────────────────────

def _restore_lambda(arn: str, region: str):
    func_name = arn.split(":")[-1]
    _lambda = boto3.client("lambda", region_name=region)

    # タグから元の同時実行数を取得
    tag_resp = _lambda.list_tags(Resource=arn)
    tags = tag_resp.get("Tags", {})
    original = int(tags.get(TAG_ORIGINAL_CONCURRENCY, "-1"))

    if original == -1:
        # 元々未設定だったので制限を削除
        _lambda.delete_function_concurrency(FunctionName=func_name)
    else:
        _lambda.put_function_concurrency(
            FunctionName=func_name,
            ReservedConcurrentExecutions=original,
        )

    # tagwatchman タグを削除
    _lambda.untag_resource(
        Resource=arn,
        TagKeys=[TAG_QUARANTINED, TAG_ORIGINAL_CONCURRENCY],
    )

    logger.info("Lambda %s restored. Concurrency: %s", func_name, original)


# ─────────────────────────────────────────────────────────────
# DynamoDB 復旧
# ─────────────────────────────────────────────────────────────

def _restore_dynamodb(arn: str, region: str):
    _dynamodb = boto3.client("dynamodb", region_name=region)

    try:
        _dynamodb.delete_resource_policy(ResourceArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PolicyNotFoundException":
            raise

    _dynamodb.untag_resource(
        ResourceArn=arn,
        TagKeys=[TAG_QUARANTINED],
    )

    logger.info("DynamoDB %s restored", arn.split("/")[-1])


# ─────────────────────────────────────────────────────────────
# SQS 復旧
# ─────────────────────────────────────────────────────────────

def _restore_sqs(arn: str, region: str):
    _sqs = boto3.client("sqs", region_name=region)
    account = arn.split(":")[4]
    queue_name = arn.split(":")[-1]
    url = _sqs.get_queue_url(
        QueueName=queue_name,
        QueueOwnerAWSAccountId=account,
    )["QueueUrl"]

    # ポリシーを空に（削除）
    _sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})
    _sqs.untag_queue(QueueUrl=url, TagKeys=[TAG_QUARANTINED])

    logger.info("SQS queue %s restored", queue_name)


# ─────────────────────────────────────────────────────────────
# ARN → 復旧関数のマッピング
# ─────────────────────────────────────────────────────────────

RESTORERS: list[tuple[str, callable]] = [
    (r"arn:aws:ec2:.+:instance/",   _restore_ec2),
    (r"arn:aws:rds:.+:db:",         _restore_rds),
    (r"arn:aws:s3:::",              _restore_s3),
    (r"arn:aws:lambda:",            _restore_lambda),
    (r"arn:aws:dynamodb:",          _restore_dynamodb),
    (r"arn:aws:sqs:",               _restore_sqs),
]


def _find_restorer(arn: str) -> Optional[callable]:
    for pattern, fn in RESTORERS:
        if re.search(pattern, arn):
            return fn
    return None
