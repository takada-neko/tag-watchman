"""
deleter/index.py
────────────────
Step Functions から呼ばれる削除Lambda。
ARN のプレフィックスでサービスを判定し、対応する削除処理を実行する。

新サービスへの対応は DELETERS dict に追記するだけ。
"""

import logging
import os
import re
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"

# Boto3 クライアントを遅延初期化（リージョン対応）
_clients: dict[str, boto3.client] = {}

def _client(service: str, region: Optional[str] = None) -> boto3.client:
    key = f"{service}:{region or 'default'}"
    if key not in _clients:
        kwargs = {}
        if region:
            kwargs["region_name"] = region
        _clients[key] = boto3.client(service, **kwargs)
    return _clients[key]


# ─────────────────────────────────────────────────────────────
# 削除ハンドラ
# ARN プレフィックス → 削除関数
# ─────────────────────────────────────────────────────────────

def _delete_ec2_instance(arn: str, region: str):
    instance_id = arn.split("/")[-1]
    _client("ec2", region).terminate_instances(InstanceIds=[instance_id])
    logger.info("Terminated EC2 instance: %s", instance_id)

def _delete_rds_instance(arn: str, region: str):
    db_id = arn.split(":")[-1]
    _client("rds", region).delete_db_instance(
        DBInstanceIdentifier=db_id,
        SkipFinalSnapshot=True,
        DeleteAutomatedBackups=True,
    )
    logger.info("Deleted RDS instance: %s", db_id)

def _delete_s3_bucket(arn: str, region: str):
    bucket = arn.split(":::")[-1]
    s3 = _client("s3", region)
    s3r = boto3.resource("s3")
    bucket_obj = s3r.Bucket(bucket)
    # バージョニング対応で全オブジェクト削除してからバケット削除
    bucket_obj.object_versions.delete()
    bucket_obj.objects.delete()
    s3.delete_bucket(Bucket=bucket)
    logger.info("Deleted S3 bucket: %s", bucket)

def _delete_lambda_function(arn: str, region: str):
    func_name = arn.split(":")[-1]
    _client("lambda", region).delete_function(FunctionName=func_name)
    logger.info("Deleted Lambda function: %s", func_name)

def _delete_dynamodb_table(arn: str, region: str):
    table_name = arn.split("/")[-1]
    _client("dynamodb", region).delete_table(TableName=table_name)
    logger.info("Deleted DynamoDB table: %s", table_name)

def _delete_ecs_cluster(arn: str, region: str):
    _client("ecs", region).delete_cluster(cluster=arn)
    logger.info("Deleted ECS cluster: %s", arn)

def _delete_ecs_service(arn: str, region: str):
    # ARN: arn:aws:ecs:<region>:<account>:service/<cluster>/<service>
    parts = arn.split("/")
    cluster = parts[-2]
    service = parts[-1]
    ecs = _client("ecs", region)
    # まず desired count を 0 にしてから削除
    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    ecs.delete_service(cluster=cluster, service=service)
    logger.info("Deleted ECS service: %s in cluster %s", service, cluster)

def _delete_sqs_queue(arn: str, region: str):
    account = arn.split(":")[4]
    queue_name = arn.split(":")[-1]
    sqs = _client("sqs", region)
    url = sqs.get_queue_url(QueueName=queue_name, QueueOwnerAWSAccountId=account)["QueueUrl"]
    sqs.delete_queue(QueueUrl=url)
    logger.info("Deleted SQS queue: %s", queue_name)

def _delete_sns_topic(arn: str, region: str):
    _client("sns", region).delete_topic(TopicArn=arn)
    logger.info("Deleted SNS topic: %s", arn)

def _delete_eks_cluster(arn: str, region: str):
    cluster_name = arn.split("/")[-1]
    _client("eks", region).delete_cluster(name=cluster_name)
    logger.info("Deleted EKS cluster: %s", cluster_name)

def _delete_kinesis_stream(arn: str, region: str):
    stream_name = arn.split("/")[-1]
    _client("kinesis", region).delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    logger.info("Deleted Kinesis stream: %s", stream_name)

def _delete_elasticache(arn: str, region: str):
    rg_id = arn.split(":")[-1]
    _client("elasticache", region).delete_replication_group(
        ReplicationGroupId=rg_id,
        RetainPrimaryCluster=False,
    )
    logger.info("Deleted ElastiCache replication group: %s", rg_id)

def _delete_opensearch(arn: str, region: str):
    domain_name = arn.split("/")[-1]
    _client("es", region).delete_elasticsearch_domain(DomainName=domain_name)
    logger.info("Deleted OpenSearch domain: %s", domain_name)

def _delete_glue_database(arn: str, region: str):
    db_name = arn.split("/")[-1]
    _client("glue", region).delete_database(Name=db_name)
    logger.info("Deleted Glue database: %s", db_name)

def _delete_ecr_repository(arn: str, region: str):
    repo_name = arn.split("/")[-1]
    _client("ecr", region).delete_repository(
        repositoryName=repo_name,
        force=True,  # 中身があっても削除
    )
    logger.info("Deleted ECR repository: %s", repo_name)

def _delete_redshift_cluster(arn: str, region: str):
    cluster_id = arn.split(":")[-1]
    _client("redshift", region).delete_cluster(
        ClusterIdentifier=cluster_id,
        SkipFinalClusterSnapshot=True,
    )
    logger.info("Deleted Redshift cluster: %s", cluster_id)

def _delete_stepfunctions(arn: str, region: str):
    _client("stepfunctions", region).delete_state_machine(stateMachineArn=arn)
    logger.info("Deleted Step Functions state machine: %s", arn.split(":")[-1])

def _delete_workspaces(arn: str, region: str):
    workspace_id = arn.split("/")[-1]
    _client("workspaces", region).terminate_workspaces(
        Workspaces=[{"WorkspaceId": workspace_id}]
    )
    logger.info("Deleted Workspace: %s", workspace_id)

def _delete_igw(arn: str, region: str):
    igw_id = arn.split("/")[-1]
    ec2 = _client("ec2", region)
    # アタッチされている場合はデタッチしてから削除
    resp = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])
    for attachment in resp["InternetGateways"][0].get("Attachments", []):
        ec2.detach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=attachment["VpcId"],
        )
        logger.info("Detached IGW %s from VPC %s", igw_id, attachment["VpcId"])
    ec2.delete_internet_gateway(InternetGatewayId=igw_id)
    logger.info("Deleted IGW: %s", igw_id)

def _delete_nat_gateway(arn: str, region: str):
    nat_id = arn.split("/")[-1]
    _client("ec2", region).delete_nat_gateway(NatGatewayId=nat_id)
    logger.info("Deleted NAT Gateway: %s", nat_id)

def _delete_vpc_peering(arn: str, region: str):
    peering_id = arn.split("/")[-1]
    _client("ec2", region).delete_vpc_peering_connection(
        VpcPeeringConnectionId=peering_id
    )
    logger.info("Deleted VPC Peering: %s", peering_id)

def _delete_iam_role(arn: str, region: str):
    iam = _client("iam", region)
    role_name = arn.split("/")[-1]
    # アタッチ済みポリシーを全剥奪
    for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
    # インラインポリシーを全削除
    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    # インスタンスプロファイルからの削除
    for profile in iam.list_instance_profiles_for_role(RoleName=role_name).get("InstanceProfiles", []):
        iam.remove_role_from_instance_profile(
            InstanceProfileName=profile["InstanceProfileName"],
            RoleName=role_name,
        )
    iam.delete_role(RoleName=role_name)
    logger.info("Deleted IAM Role: %s", role_name)

def _delete_iam_user(arn: str, region: str):
    iam = _client("iam", region)
    user_name = arn.split("/")[-1]
    # アクセスキーを全削除
    for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
        iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    # アタッチ済みポリシーを全剥奪
    for policy in iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []):
        iam.detach_user_policy(UserName=user_name, PolicyArn=policy["PolicyArn"])
    # インラインポリシーを全削除
    for policy_name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    # MFAデバイスを削除
    for mfa in iam.list_mfa_devices(UserName=user_name).get("MFADevices", []):
        iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa["SerialNumber"])
        iam.delete_virtual_mfa_device(SerialNumber=mfa["SerialNumber"])
    # グループから削除
    for group in iam.list_groups_for_user(UserName=user_name).get("Groups", []):
        iam.remove_user_from_group(GroupName=group["GroupName"], UserName=user_name)
    iam.delete_user(UserName=user_name)
    logger.info("Deleted IAM User: %s", user_name)


# ARN 内のサービス識別子 → 削除関数のマッピング
DELETERS: list[tuple[str, callable]] = [
    # パターンA: 隔離→承認→削除
    (r"arn:aws:ec2:.+:instance/",              _delete_ec2_instance),
    (r"arn:aws:rds:.+:db:",                    _delete_rds_instance),
    (r"arn:aws:s3:::",                         _delete_s3_bucket),
    (r"arn:aws:lambda:",                       _delete_lambda_function),
    (r"arn:aws:dynamodb:",                     _delete_dynamodb_table),
    (r"arn:aws:ecs:.+:service/",               _delete_ecs_service),  # serviceを先に
    (r"arn:aws:ecs:.+:cluster/",               _delete_ecs_cluster),
    (r"arn:aws:sqs:",                          _delete_sqs_queue),
    (r"arn:aws:sns:",                          _delete_sns_topic),
    (r"arn:aws:eks:",                          _delete_eks_cluster),
    (r"arn:aws:kinesis:",                      _delete_kinesis_stream),
    (r"arn:aws:elasticache:",                  _delete_elasticache),
    (r"arn:aws:es:",                           _delete_opensearch),
    (r"arn:aws:glue:",                         _delete_glue_database),
    (r"arn:aws:ecr:",                          _delete_ecr_repository),
    (r"arn:aws:redshift:.+:cluster:",          _delete_redshift_cluster),
    (r"arn:aws:states:",                       _delete_stepfunctions),
    (r"arn:aws:workspaces:",                   _delete_workspaces),
    # パターンB: 条件付き即時削除
    (r"arn:aws:ec2:.+:internet-gateway/",      _delete_igw),
    (r"arn:aws:ec2:.+:natgateway/",            _delete_nat_gateway),
    (r"arn:aws:ec2:.+:vpc-peering-connection/", _delete_vpc_peering),
    # パターンC: 権限剥奪→承認→削除
    (r"arn:aws:iam:.+:role/",                  _delete_iam_role),
    (r"arn:aws:iam:.+:user/",                  _delete_iam_user),
]


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    arn    = event["arn"]
    region = event.get("region", os.environ.get("AWS_REGION", "ap-northeast-1"))

    logger.info("Delete request: ARN=%s DRY_RUN=%s", arn, DRY_RUN)

    deleter = _find_deleter(arn)
    if deleter is None:
        msg = f"No deleter registered for ARN: {arn}"
        logger.error(msg)
        return {**event, "deleteStatus": "error", "deleteReason": msg}

    if DRY_RUN:
        logger.info("[DRY RUN] Would delete: %s", arn)
        return {**event, "deleteStatus": "dry_run"}

    try:
        deleter(arn, region)
        return {**event, "deleteStatus": "deleted"}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # 既に削除済みの場合は正常扱い
        if code in ("InvalidInstanceID.NotFound", "DBInstanceNotFound",
                    "NoSuchBucket", "ResourceNotFoundException",
                    "ClusterNotFoundException"):
            logger.warning("Resource already gone: %s (%s)", arn, code)
            return {**event, "deleteStatus": "already_deleted"}
        logger.error("Delete failed for %s: %s", arn, e)
        raise
    except Exception as e:
        logger.error("Unexpected error deleting %s: %s", arn, e)
        raise


def _find_deleter(arn: str) -> Optional[callable]:
    for pattern, fn in DELETERS:
        if re.search(pattern, arn):
            return fn
    return None
