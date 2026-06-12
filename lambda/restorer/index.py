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
import base64
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
TAG_ORIGINAL_CONCURRENCY = "tagwatchman:original-concurrency"
TAG_APIGW_STAGES         = "tagwatchman:original-stages"

def _decode_sgs(value):
    value = (value or "").strip()
    if not value:
        return []
    if value.startswith("["):     # 旧 json.dumps 形式の後方互換（保険）
        return json.loads(value)
    return value.split("/")


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

    original_sgs = _decode_sgs(tags[0]["Value"])

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

    original_sgs = _decode_sgs(tags[TAG_ORIGINAL_SGS])

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

    # 既存タグを取得（tagwatchman: プレフィックスの掃除に使用）
    tag_resp = {}
    try:
        tag_resp = _s3.get_bucket_tagging(Bucket=bucket)
    except ClientError:
        pass

    # 全拒否ポリシーを削除
    # lossy リストア設計: 元ポリシーは復元しない（全文はメール通知済み・b64 サマリーはタグ退避）
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
                    if not t["Key"].startswith("tagwatchman:")]
        logger.info("S3 restore tag filter: existing=%s new=%s",
                    [t["Key"] for t in existing_tags], [t["Key"] for t in new_tags])
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
# ECS 復旧
# ─────────────────────────────────────────────────────────────

def _restore_ecs(arn: str, region: str):
    _ecs = boto3.client("ecs", region_name=region)
    parts   = arn.split("/")
    cluster = parts[-2]
    service = parts[-1]

    # タグから元のSGを取得
    tag_resp = _ecs.list_tags_for_resource(resourceArn=arn)
    tags = {t["key"]: t["value"] for t in tag_resp.get("tags", [])}

    if TAG_ORIGINAL_SGS not in tags:
        logger.warning("No original SG tag for ECS %s", service)
        return

    original_sgs = _decode_sgs(tags[TAG_ORIGINAL_SGS])

    # 現在のネットワーク設定を取得して差し替え
    resp = _ecs.describe_services(cluster=cluster, services=[service])
    nc   = resp["services"][0].get("networkConfiguration", {}).get("awsvpcConfiguration", {})

    _ecs.update_service(
        cluster=cluster,
        service=service,
        networkConfiguration={"awsvpcConfiguration": {**nc, "securityGroups": original_sgs}},
    )

    # tagwatchman タグを削除
    _ecs.untag_resource(
        resourceArn=arn,
        tagKeys=[TAG_QUARANTINED, TAG_ORIGINAL_SGS],
    )

    logger.info("ECS service %s restored. SGS: %s", service, original_sgs)


# ─────────────────────────────────────────────────────────────
# EKS 復旧
# ─────────────────────────────────────────────────────────────

def _restore_eks(arn: str, region: str):
    _eks = boto3.client("eks", region_name=region)
    cluster_name = arn.split("/")[-1]

    tag_resp = _eks.list_tags_for_resource(resourceArn=arn)
    tags = tag_resp.get("tags", {})

    if TAG_ORIGINAL_SGS not in tags:
        logger.warning("No original SG tag for EKS %s", cluster_name)
        return

    original_sgs = _decode_sgs(tags[TAG_ORIGINAL_SGS])

    _eks.update_cluster_config(
        name=cluster_name,
        resourcesVpcConfig={"securityGroupIds": original_sgs},
    )

    _eks.untag_resource(
        resourceArn=arn,
        tagKeys=[TAG_QUARANTINED, TAG_ORIGINAL_SGS],
    )

    logger.info("EKS cluster %s restored. SGS: %s", cluster_name, original_sgs)


# ─────────────────────────────────────────────────────────────
# SNS 復旧（ポリシーを削除）
# ─────────────────────────────────────────────────────────────

def _restore_sns(arn: str, region: str):
    _sns = boto3.client("sns", region_name=region)
    # 【SNS固有】SNS の Policy 属性は空文字で上書きできない
    # （InvalidParameter: "Policy is empty"・実機確定）。トピックは必ず
    # ポリシーを持つ仕様のため「削除」は構造的に不可能。代わりに
    # デフォルトポリシー（__default_policy_ID・作成直後の状態）を再構築して
    # 置く。account ID と topic ARN から決定論的に再構築できるので、
    # デフォルトのままだったトピックには実質 lossless。カスタムポリシーは
    # 戻らない（lossy）が、検知メールの元ポリシー全文が復旧の痕跡となる。
    account = arn.split(":")[4]
    default_policy = json.dumps({
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [{
            "Sid": "__default_statement_ID",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "SNS:GetTopicAttributes",
                "SNS:SetTopicAttributes",
                "SNS:AddPermission",
                "SNS:RemovePermission",
                "SNS:DeleteTopic",
                "SNS:Subscribe",
                "SNS:ListSubscriptionsByTopic",
                "SNS:Publish",
            ],
            "Resource": arn,
            "Condition": {"StringEquals": {"AWS:SourceOwner": account}},
        }],
    })
    _sns.set_topic_attributes(
        TopicArn=arn,
        AttributeName="Policy",
        AttributeValue=default_policy,
    )
    _sns.untag_resource(
        ResourceArn=arn,
        TagKeys=[TAG_QUARANTINED],
    )
    logger.info("SNS topic %s restored (default policy reconstructed)", arn.split(":")[-1])


# ─────────────────────────────────────────────────────────────
# OpenSearch 復旧（アクセスポリシーを削除）
# ─────────────────────────────────────────────────────────────

def _restore_opensearch(arn: str, region: str):
    _es = boto3.client("es", region_name=region)
    domain_name = arn.split("/")[-1]

    _es.update_elasticsearch_domain_config(
        DomainName=domain_name,
        AccessPolicies="",
    )

    _es.remove_tags(
        ARN=arn,
        TagKeys=[TAG_QUARANTINED],
    )

    logger.info("OpenSearch domain %s restored", domain_name)


# ─────────────────────────────────────────────────────────────
# ECR 復旧（リポジトリポリシーを削除）
# ─────────────────────────────────────────────────────────────

def _restore_ecr(arn: str, region: str):
    _ecr = boto3.client("ecr", region_name=region)
    repo_name = arn.split("/")[-1]

    try:
        _ecr.delete_repository_policy(repositoryName=repo_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryPolicyNotFoundException":
            raise

    _ecr.untag_resource(
        resourceArn=arn,
        tagKeys=[TAG_QUARANTINED],
    )

    logger.info("ECR repository %s restored", repo_name)


# ─────────────────────────────────────────────────────────────
# Redshift 復旧
# ─────────────────────────────────────────────────────────────

def _restore_redshift(arn: str, region: str):
    _rs = boto3.client("redshift", region_name=region)
    cluster_id = arn.split(":")[-1]

    tag_resp = _rs.describe_tags(ResourceName=arn)
    tags = {t["Tag"]["Key"]: t["Tag"]["Value"] for t in tag_resp.get("TaggedResources", [])}

    if TAG_ORIGINAL_SGS not in tags:
        logger.warning("No original SG tag for Redshift %s", cluster_id)
        return

    original_sgs = _decode_sgs(tags[TAG_ORIGINAL_SGS])

    _rs.modify_cluster(
        ClusterIdentifier=cluster_id,
        VpcSecurityGroupIds=original_sgs,
    )

    _rs.delete_tags(
        ResourceName=arn,
        TagKeys=[TAG_QUARANTINED, TAG_ORIGINAL_SGS],
    )

    logger.info("Redshift cluster %s restored. SGS: %s", cluster_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# IAM Role 復旧
# 注意: 剥奪したポリシーの情報はタグに保存していないため
#       復旧は「隔離タグの削除」のみ。ポリシーは人間が再付与。
# ─────────────────────────────────────────────────────────────

def _restore_iam_role(arn: str, region: str):
    _iam = boto3.client("iam")
    role_name = arn.split("/")[-1]

    _iam.untag_role(
        RoleName=role_name,
        TagKeys=[TAG_QUARANTINED],
    )

    logger.warning(
        "IAM Role %s quarantine tag removed. "
        "Detached policies must be re-attached manually.",
        role_name,
    )


# ─────────────────────────────────────────────────────────────
# IAM User 復旧
# 注意: 同上。ポリシーとアクセスキーは人間が対応。
# ─────────────────────────────────────────────────────────────

def _restore_iam_user(arn: str, region: str):
    _iam = boto3.client("iam")
    user_name = arn.split("/")[-1]

    _iam.untag_user(
        UserName=user_name,
        TagKeys=[TAG_QUARANTINED],
    )

    logger.warning(
        "IAM User %s quarantine tag removed. "
        "Detached policies and deactivated keys must be restored manually.",
        user_name,
    )


# ─────────────────────────────────────────────────────────────
# API Gateway 復旧（削除したステージを再作成）
# ─────────────────────────────────────────────────────────────

def _restore_apigateway(arn: str, region: str):
    _apigw = boto3.client("apigateway", region_name=region)
    api_id = arn.split("/restapis/")[-1].split("/")[0]

    # タグからステージ情報を取得
    tag_resp = _apigw.get_tags(resourceArn=arn)
    tags     = tag_resp.get("tags", {})

    stage_tag = tags.get(TAG_APIGW_STAGES)
    if stage_tag is None:
        logger.warning("No stage info tag found for API Gateway %s", api_id)
        return
    stages = json.loads(base64.b64decode(stage_tag, validate=True))

    if not stages:
        logger.info("API Gateway %s had no stages — nothing to restore", api_id)
    else:
        for s in stages:
            stage_name    = s["stageName"]
            deployment_id = s.get("deploymentId", "")
            variables     = s.get("variables", {})
            description   = s.get("description", "")

            if not deployment_id:
                logger.warning(
                    "API Gateway %s stage '%s' has no deploymentId — skipping",
                    api_id, stage_name,
                )
                continue

            kwargs = dict(
                restApiId    = api_id,
                stageName    = stage_name,
                deploymentId = deployment_id,
            )
            if variables:
                kwargs["variables"] = variables
            if description:
                kwargs["description"] = description

            try:
                _apigw.create_stage(**kwargs)
                logger.info(
                    "API Gateway %s stage '%s' recreated (deploymentId=%s)",
                    api_id, stage_name, deployment_id,
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "ConflictException":
                    # すでに同名ステージが存在する場合はスキップ
                    logger.info(
                        "API Gateway %s stage '%s' already exists — skipping",
                        api_id, stage_name,
                    )
                else:
                    raise

    # tagwatchman タグを削除
    _apigw.untag_resource(
        resourceArn=arn,
        tagKeys=[TAG_QUARANTINED, TAG_APIGW_STAGES],
    )

    logger.info("API Gateway %s restored", api_id)


# ─────────────────────────────────────────────────────────────
# ARN → 復旧関数のマッピング
# ─────────────────────────────────────────────────────────────

RESTORERS: list[tuple[str, callable]] = [
    # パターンA
    (r"arn:aws:ec2:.+:instance/",        _restore_ec2),
    (r"arn:aws:rds:.+:db:",              _restore_rds),
    (r"arn:aws:s3:::",                   _restore_s3),
    (r"arn:aws:lambda:",                 _restore_lambda),
    (r"arn:aws:dynamodb:",               _restore_dynamodb),
    (r"arn:aws:sqs:",                    _restore_sqs),
    (r"arn:aws:ecs:.+:service/",         _restore_ecs),
    (r"arn:aws:eks:.+:cluster/",         _restore_eks),
    (r"arn:aws:sns:",                    _restore_sns),
    (r"arn:aws:es:",                     _restore_opensearch),
    (r"arn:aws:ecr:",                    _restore_ecr),
    (r"arn:aws:redshift:",               _restore_redshift),
    (r"arn:aws:apigateway:.+::/restapis/", _restore_apigateway),
    # パターンC
    (r"arn:aws:iam:.+:role/",            _restore_iam_role),
    (r"arn:aws:iam:.+:user/",            _restore_iam_user),
    # パターンB（即時削除系は復旧なし）
    # パターンE（通知のみ・8サービス: elasticache / kinesis / stepfunctions / vpc /
    #           glue / workspaces / secretsmanager / cloudfront は隔離しないため復旧なし）
]


def _find_restorer(arn: str) -> Optional[callable]:
    for pattern, fn in RESTORERS:
        if re.search(pattern, arn):
            return fn
    return None
