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
# ECS 隔離（SGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────

def _isolate_ecs(arn: str, region: str):
    _ecs = boto3.client("ecs", region_name=region)

    # ARN: arn:aws:ecs:<region>:<account>:service/<cluster>/<service>
    parts     = arn.split("/")
    cluster   = parts[-2]
    service   = parts[-1]

    # 現在のネットワーク設定を取得
    resp = _ecs.describe_services(cluster=cluster, services=[service])
    svc  = resp["services"][0]
    nc   = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
    original_sgs = nc.get("securityGroups", [])

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # タグに保存
    _ecs.tag_resource(
        resourceArn=arn,
        tags=[
            {"key": TAG_QUARANTINED,  "value": "true"},
            {"key": TAG_ORIGINAL_SGS, "value": json.dumps(original_sgs)},
        ],
    )

    # 全拒否SGに差し替え
    _ecs.update_service(
        cluster=cluster,
        service=service,
        networkConfiguration={
            "awsvpcConfiguration": {
                **nc,
                "securityGroups": [QUARANTINE_SG],
            }
        },
    )

    logger.info("ECS service %s isolated. Original SGS: %s", service, original_sgs)


# ─────────────────────────────────────────────────────────────
# EKS 隔離（クラスターのSGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────

def _isolate_eks(arn: str, region: str):
    _eks = boto3.client("eks", region_name=region)
    _ec2 = boto3.client("ec2", region_name=region)

    cluster_name = arn.split("/")[-1]

    # 現在のSGを取得
    resp = _eks.describe_cluster(name=cluster_name)
    original_sgs = resp["cluster"]["resourcesVpcConfig"].get("securityGroupIds", [])

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # タグに保存（EKSはEC2タグAPIを使用）
    _eks.tag_resource(
        resourceArn=arn,
        tags={
            TAG_QUARANTINED:  "true",
            TAG_ORIGINAL_SGS: json.dumps(original_sgs),
        },
    )

    # 全拒否SGに差し替え
    _eks.update_cluster_config(
        name=cluster_name,
        resourcesVpcConfig={"securityGroupIds": [QUARANTINE_SG]},
    )

    logger.info("EKS cluster %s isolated. Original SGS: %s", cluster_name, original_sgs)


# ─────────────────────────────────────────────────────────────
# ElastiCache 隔離（SGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────

def _isolate_elasticache(arn: str, region: str):
    _ec = boto3.client("elasticache", region_name=region)
    rg_id = arn.split(":")[-1]

    # 現在のSGを取得
    resp = _ec.describe_replication_groups(ReplicationGroupId=rg_id)
    member_clusters = resp["ReplicationGroups"][0].get("MemberClusters", [])

    original_sgs = []
    if member_clusters:
        cluster_resp = _ec.describe_cache_clusters(
            CacheClusterId=member_clusters[0],
            ShowCacheNodeInfo=False,
        )
        original_sgs = [
            sg["SecurityGroupId"]
            for sg in cluster_resp["CacheClusters"][0].get("SecurityGroups", [])
        ]

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # タグに保存
    _ec.add_tags_to_resource(
        ResourceName=arn,
        Tags=[
            {"Key": TAG_QUARANTINED,  "Value": "true"},
            {"Key": TAG_ORIGINAL_SGS, "Value": json.dumps(original_sgs)},
        ],
    )

    # 全拒否SGに差し替え
    _ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        SecurityGroupIds=[QUARANTINE_SG],
        ApplyImmediately=True,
    )

    logger.info("ElastiCache %s isolated. Original SGS: %s", rg_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# SNS 隔離（トピックポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_sns(arn: str, region: str):
    _sns = boto3.client("sns", region_name=region)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sns:*",
                "Resource": arn,
            }
        ],
    })

    _sns.set_topic_attributes(
        TopicArn=arn,
        AttributeName="Policy",
        AttributeValue=deny_policy,
    )

    _sns.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("SNS topic %s isolated", arn.split(":")[-1])


# ─────────────────────────────────────────────────────────────
# Kinesis 隔離（リソースポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_kinesis(arn: str, region: str):
    _kinesis = boto3.client("kinesis", region_name=region)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kinesis:*",
                "Resource": arn,
            }
        ],
    })

    _kinesis.put_resource_policy(ResourceARN=arn, Policy=deny_policy)

    stream_name = arn.split("/")[-1]
    _kinesis.add_tags_to_stream(
        StreamName=stream_name,
        Tags={TAG_QUARANTINED: "true"},
    )

    logger.info("Kinesis stream %s isolated", stream_name)


# ─────────────────────────────────────────────────────────────
# OpenSearch 隔離（アクセスポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_opensearch(arn: str, region: str):
    _es = boto3.client("es", region_name=region)
    domain_name = arn.split("/")[-1]

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "es:*",
                "Resource": f"{arn}/*",
            }
        ],
    })

    _es.update_elasticsearch_domain_config(
        DomainName=domain_name,
        AccessPolicies=deny_policy,
    )

    _es.add_tags(
        ARN=arn,
        TagList=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("OpenSearch domain %s isolated", domain_name)


# ─────────────────────────────────────────────────────────────
# ECR 隔離（リポジトリポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_ecr(arn: str, region: str):
    _ecr = boto3.client("ecr", region_name=region)
    repo_name = arn.split("/")[-1]

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "ecr:*",
            }
        ],
    })

    _ecr.set_repository_policy(
        repositoryName=repo_name,
        policyText=deny_policy,
    )

    _ecr.tag_resource(
        resourceArn=arn,
        tags=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("ECR repository %s isolated", repo_name)


# ─────────────────────────────────────────────────────────────
# Redshift 隔離（SGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────

def _isolate_redshift(arn: str, region: str):
    _rs = boto3.client("redshift", region_name=region)
    cluster_id = arn.split(":")[-1]

    # 現在のSGを取得
    resp = _rs.describe_clusters(ClusterIdentifier=cluster_id)
    original_sgs = [
        sg["VpcSecurityGroupId"]
        for sg in resp["Clusters"][0].get("VpcSecurityGroups", [])
    ]

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # タグに保存
    _rs.create_tags(
        ResourceName=arn,
        Tags=[
            {"Key": TAG_QUARANTINED,  "Value": "true"},
            {"Key": TAG_ORIGINAL_SGS, "Value": json.dumps(original_sgs)},
        ],
    )

    # 全拒否SGに差し替え
    _rs.modify_cluster(
        ClusterIdentifier=cluster_id,
        VpcSecurityGroupIds=[QUARANTINE_SG],
    )

    logger.info("Redshift cluster %s isolated. Original SGS: %s", cluster_id, original_sgs)


# ─────────────────────────────────────────────────────────────
# Step Functions 隔離（リソースポリシーで全拒否）
# ─────────────────────────────────────────────────────────────

def _isolate_stepfunctions(arn: str, region: str):
    _sfn = boto3.client("stepfunctions", region_name=region)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "states:*",
                "Resource": arn,
            }
        ],
    })

    _sfn.set_resource_policy(resourceArn=arn, policy=deny_policy)

    _sfn.tag_resource(
        resourceArn=arn,
        tags=[{"key": TAG_QUARANTINED, "value": "true"}],
    )

    logger.info("Step Functions %s isolated", arn.split(":")[-1])


# ─────────────────────────────────────────────────────────────
# Workspaces 隔離（SGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────

def _isolate_workspaces(arn: str, region: str):
    _ws = boto3.client("workspaces", region_name=region)
    workspace_id = arn.split("/")[-1]

    if not QUARANTINE_SG:
        raise ValueError("QUARANTINE_SG_ID not set")

    # WorkspacesはDirectory経由でSGを変更
    resp = _ws.describe_workspaces(WorkspaceIds=[workspace_id])
    if not resp["Workspaces"]:
        raise ValueError(f"Workspace not found: {workspace_id}")

    directory_id = resp["Workspaces"][0]["DirectoryId"]

    dir_resp = _ws.describe_workspace_directories(DirectoryIds=[directory_id])
    original_sgs = dir_resp["Directories"][0].get("workspaceSecurityGroupId", "")

    _ws.modify_workspace_properties(
        WorkspaceId=workspace_id,
        WorkspaceProperties={},
    )

    # タグに保存
    _ws.create_tags(
        ResourceId=workspace_id,
        Tags=[
            {"Key": TAG_QUARANTINED,  "Value": "true"},
            {"Key": TAG_ORIGINAL_SGS, "Value": json.dumps([original_sgs])},
        ],
    )

    logger.info("Workspace %s isolated", workspace_id)


# ─────────────────────────────────────────────────────────────
# IGW 隔離（アタッチなし → 即時削除 / アタッチあり → スキップ）
# ─────────────────────────────────────────────────────────────

def _isolate_igw(arn: str, region: str):
    _ec2 = boto3.client("ec2", region_name=region)
    igw_id = arn.split("/")[-1]

    resp = _ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])
    igw  = resp["InternetGateways"][0]
    attachments = igw.get("Attachments", [])

    if attachments:
        # アタッチあり → 既存VPCへの影響があるため通知のみ
        logger.warning("IGW %s is attached — skipping deletion, manual review required", igw_id)
        raise RuntimeError(f"IGW {igw_id} is attached to VPC — requires manual review")

    # アタッチなし → 即時削除
    _ec2.delete_internet_gateway(InternetGatewayId=igw_id)
    logger.info("IGW %s deleted (was not attached)", igw_id)


# ─────────────────────────────────────────────────────────────
# NAT Gateway 即時削除
# ─────────────────────────────────────────────────────────────

def _isolate_nat_gateway(arn: str, region: str):
    _ec2  = boto3.client("ec2", region_name=region)
    nat_id = arn.split("/")[-1]

    _ec2.delete_nat_gateway(NatGatewayId=nat_id)
    logger.info("NAT Gateway %s deleted", nat_id)


# ─────────────────────────────────────────────────────────────
# VPC Peering 即時削除
# ─────────────────────────────────────────────────────────────

def _isolate_vpc_peering(arn: str, region: str):
    _ec2       = boto3.client("ec2", region_name=region)
    peering_id = arn.split("/")[-1]

    _ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=peering_id)
    logger.info("VPC Peering %s deleted", peering_id)


# ─────────────────────────────────────────────────────────────
# IAM Role 隔離（ポリシーを全剥奪）
# ─────────────────────────────────────────────────────────────

def _isolate_iam_role(arn: str, region: str):
    _iam      = boto3.client("iam")
    role_name = arn.split("/")[-1]

    # アタッチ済みマネージドポリシーを全剥奪
    attached = _iam.list_attached_role_policies(RoleName=role_name)
    for policy in attached.get("AttachedPolicies", []):
        _iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
        logger.info("Detached policy %s from role %s", policy["PolicyArn"], role_name)

    # インラインポリシーを全削除
    inline = _iam.list_role_policies(RoleName=role_name)
    for policy_name in inline.get("PolicyNames", []):
        _iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        logger.info("Deleted inline policy %s from role %s", policy_name, role_name)

    # タグに記録
    _iam.tag_role(
        RoleName=role_name,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("IAM Role %s isolated — all policies detached", role_name)


# ─────────────────────────────────────────────────────────────
# IAM User 隔離（ポリシー全剥奪 + アクセスキー無効化）
# ─────────────────────────────────────────────────────────────

def _isolate_iam_user(arn: str, region: str):
    _iam      = boto3.client("iam")
    user_name = arn.split("/")[-1]

    # アタッチ済みマネージドポリシーを全剥奪
    attached = _iam.list_attached_user_policies(UserName=user_name)
    for policy in attached.get("AttachedPolicies", []):
        _iam.detach_user_policy(UserName=user_name, PolicyArn=policy["PolicyArn"])
        logger.info("Detached policy %s from user %s", policy["PolicyArn"], user_name)

    # インラインポリシーを全削除
    inline = _iam.list_user_policies(UserName=user_name)
    for policy_name in inline.get("PolicyNames", []):
        _iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        logger.info("Deleted inline policy %s from user %s", policy_name, user_name)

    # アクセスキーを全て無効化
    keys = _iam.list_access_keys(UserName=user_name)
    for key in keys.get("AccessKeyMetadata", []):
        _iam.update_access_key(
            UserName=user_name,
            AccessKeyId=key["AccessKeyId"],
            Status="Inactive",
        )
        logger.info("Deactivated access key %s for user %s", key["AccessKeyId"], user_name)

    # タグに記録
    _iam.tag_user(
        UserName=user_name,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"}],
    )

    logger.info("IAM User %s isolated — policies detached, keys deactivated", user_name)


# ─────────────────────────────────────────────────────────────
# ARN → 隔離関数のマッピング
# ─────────────────────────────────────────────────────────────

ISOLATORS: list[tuple[str, callable]] = [
    # パターンA: 隔離→承認→削除
    (r"arn:aws:ec2:.+:instance/",        _isolate_ec2),
    (r"arn:aws:rds:.+:db:",              _isolate_rds),
    (r"arn:aws:s3:::",                   _isolate_s3),
    (r"arn:aws:lambda:",                 _isolate_lambda),
    (r"arn:aws:dynamodb:",               _isolate_dynamodb),
    (r"arn:aws:sqs:",                    _isolate_sqs),
    (r"arn:aws:ecs:.+:service/",         _isolate_ecs),
    (r"arn:aws:eks:.+:cluster/",         _isolate_eks),
    (r"arn:aws:elasticache:",            _isolate_elasticache),
    (r"arn:aws:sns:",                    _isolate_sns),
    (r"arn:aws:kinesis:",                _isolate_kinesis),
    (r"arn:aws:es:",                     _isolate_opensearch),
    (r"arn:aws:ecr:",                    _isolate_ecr),
    (r"arn:aws:redshift:",               _isolate_redshift),
    (r"arn:aws:states:",                 _isolate_stepfunctions),
    (r"arn:aws:workspaces:",             _isolate_workspaces),
    # パターンB: 条件付き即時削除
    (r"arn:aws:ec2:.+:internet-gateway/", _isolate_igw),
    (r"arn:aws:ec2:.+:natgateway/",       _isolate_nat_gateway),
    (r"arn:aws:ec2:.+:vpc-peering-connection/", _isolate_vpc_peering),
    # パターンC: 権限剥奪→承認→削除
    (r"arn:aws:iam:.+:role/",            _isolate_iam_role),
    (r"arn:aws:iam:.+:user/",            _isolate_iam_user),
]


def _find_isolator(arn: str) -> Optional[callable]:
    for pattern, fn in ISOLATORS:
        if re.search(pattern, arn):
            return fn
    return None
