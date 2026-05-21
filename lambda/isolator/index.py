"""
isolator/index.py
─────────────────
Step Functions から呼ばれる隔離Lambda。

役割:
  1. ARN のサービスを判定
  2. 通信遮断（SGの差し替え / バケットポリシー封鎖 / 同時実行数0）
  3. 元の状態をタグに保存（復旧時に使用）

復旧は Recheck Lambda がタグ付与を検知したときに行う。
削除はしない。
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

DRY_RUN        = os.environ.get("DRY_RUN", "true").lower() == "true"
QUARANTINE_SG  = os.environ.get("QUARANTINE_SG_ID", "")  # 全拒否SGのID（デプロイ時に作成）

ec2 = boto3.client("ec2")
rds = boto3.client("rds")
s3  = boto3.client("s3")

# 隔離状態を記録するタグキー
TAG_QUARANTINED        = "tagwatchman:quarantined"
TAG_ORIGINAL_SGS       = "tagwatchman:original-sgs"
TAG_ORIGINAL_POLICY    = "tagwatchman:had-bucket-policy"
TAG_ORIGINAL_CONCURRENCY = "tagwatchman:original-concurrency"


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    arn    = event["arn"]
    region = event.get("region", os.environ.get("AWS_REGION", "ap-northeast-1"))

    logger.info("Isolating ARN: %s DRY_RUN=%s", arn, DRY_RUN)

    isolator = _find_isolator(arn)
    if isolator is None:
        logger.warning("No isolator for ARN: %s — skipping isolation", arn)
        return {**event, "isolationStatus": "skipped"}

    if DRY_RUN:
        logger.info("[DRY RUN] Would isolate: %s", arn)
        return {**event, "isolationStatus": "dry_run"}

    try:
        isolator(arn, region)
        return {**event, "isolationStatus": "isolated"}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # すでに隔離済み or リソースが存在しない場合はスキップ
        if code in ("InvalidInstanceID.NotFound", "DBInstanceNotFound",
                    "NoSuchBucket", "ResourceNotFoundException"):
            logger.warning("Resource not found or already isolated: %s (%s)", arn, code)
            return {**event, "isolationStatus": "skipped"}
        logger.error("Isolation failed for %s: %s", arn, e)
        raise
    except Exception as e:
        logger.error("Unexpected error isolating %s: %s", arn, e)
        raise


# ─────────────────────────────────────────────────────────────
# EC2 隔離
# ─────────────────────────────────────────────────────────────

def _isolate_ec2(arn: str, region: str):
    instance_id = arn.split("/")[-1]

    # 現在のSGを取得
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp["Reservations"][0]["Instances"][0]
    original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # 元のSGをタグに保存
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": TAG_QUARANTINED,  "Value": "true"},
            {"Key": TAG_ORIGINAL_SGS, "Value": json.dumps(original_sgs)},
        ],
    )

    # 全拒否SGに差し替え
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG],
    )

    logger.info("EC2 %s isolated. Original SGS: %s", instance_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# RDS 隔離
# ─────────────────────────────────────────────────────────────

def _isolate_rds(arn: str, region: str):
    db_id = arn.split(":")[-1]
    _rds = boto3.client("rds", region_name=region)

    # 現在のSGを取得
    resp = _rds.describe_db_instances(DBInstanceIdentifier=db_id)
    db = resp["DBInstances"][0]
    original_sgs = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
    db_arn = db["DBInstanceArn"]

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # 元のSGをタグに保存
    _rds.add_tags_to_resource(
        ResourceName=db_arn,
        Tags=[
            {"Key": TAG_QUARANTINED,  "Value": "true"},
            {"Key": TAG_ORIGINAL_SGS, "Value": json.dumps(original_sgs)},
        ],
    )

    # 全拒否SGに差し替え
    _rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        VpcSecurityGroupIds=[QUARANTINE_SG],
        ApplyImmediately=True,
    )

    logger.info("RDS %s isolated. Original SGS: %s", db_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# S3 隔離
# ─────────────────────────────────────────────────────────────

def _isolate_s3(arn: str, region: str):
    bucket = arn.split(":::")[-1]

    # 既存のバケットポリシーがあるか確認
    had_policy = False
    try:
        s3.get_bucket_policy(Bucket=bucket)
        had_policy = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise

    # 全拒否ポリシーを適用
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
            }
        ],
    })

    # 元のポリシー有無をタグに保存
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": TAG_QUARANTINED,     "Value": "true"},
                {"Key": TAG_ORIGINAL_POLICY, "Value": str(had_policy)},
            ]
        },
    )

    s3.put_bucket_policy(Bucket=bucket, Policy=deny_policy)
    logger.info("S3 bucket %s isolated. Had existing policy: %s", bucket, had_policy)


# ─────────────────────────────────────────────────────────────
# Lambda 隔離（同時実行数を0に）
# ─────────────────────────────────────────────────────────────

def _isolate_lambda(arn: str, region: str):
    func_name = arn.split(":")[-1]
    _lambda = boto3.client("lambda", region_name=region)

    # 現在の同時実行数を取得
    try:
        resp = _lambda.get_function_concurrency(FunctionName=func_name)
        original = resp.get("ReservedConcurrentExecutions", -1)  # -1 = 未設定
    except ClientError:
        original = -1

    # タグに保存
    _lambda.tag_resource(
        Resource=arn,
        Tags={
            TAG_QUARANTINED:          "true",
            TAG_ORIGINAL_CONCURRENCY: str(original),
        },
    )

    # 同時実行数を0に設定（新規リクエストをすべて拒否）
    _lambda.put_function_concurrency(
        FunctionName=func_name,
        ReservedConcurrentExecutions=0,
    )

    logger.info("Lambda %s isolated. Original concurrency: %s", func_name, original)


# ─────────────────────────────────────────────────────────────
# DynamoDB 隔離（リソースポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_dynamodb(arn: str, region: str):
    _dynamodb = boto3.client("dynamodb", region_name=region)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "dynamodb:*",
                "Resource": arn,
            }
        ],
    })

    _dynamodb.put_resource_policy(ResourceArn=arn, Policy=deny_policy)

    # タグに記録
    table_name = arn.split("/")[-1]
    _dynamodb.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("DynamoDB table %s isolated", table_name)


# ─────────────────────────────────────────────────────────────
# SQS 隔離（キューポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_sqs(arn: str, region: str):
    _sqs = boto3.client("sqs", region_name=region)
    account = arn.split(":")[4]
    queue_name = arn.split(":")[-1]
    url = _sqs.get_queue_url(
        QueueName=queue_name,
        QueueOwnerAWSAccountId=account,
    )["QueueUrl"]

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sqs:*",
                "Resource": arn,
            }
        ],
    })

    _sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={"Policy": deny_policy},
    )

    _sqs.tag_queue(QueueUrl=url, Tags={TAG_QUARANTINED: "true"})
    logger.info("SQS queue %s isolated", queue_name)


# ─────────────────────────────────────────────────────────────
# ARN → 隔離関数のマッピング
# ─────────────────────────────────────────────────────────────

ISOLATORS: list[tuple[str, callable]] = [
    (r"arn:aws:ec2:.+:instance/",   _isolate_ec2),
    (r"arn:aws:rds:.+:db:",         _isolate_rds),
    (r"arn:aws:s3:::",              _isolate_s3),
    (r"arn:aws:lambda:",            _isolate_lambda),
    (r"arn:aws:dynamodb:",          _isolate_dynamodb),
    (r"arn:aws:sqs:",               _isolate_sqs),
]


def _find_isolator(arn: str) -> Optional[callable]:
    for pattern, fn in ISOLATORS:
        if re.search(pattern, arn):
            return fn
    return None
