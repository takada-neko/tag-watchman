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


SELF_PROTECT_PREFIX = os.environ.get("SELF_PROTECT_PREFIX", "")
OPERATOR_ROLE_ARN   = os.environ.get("OPERATOR_ROLE_ARN", "")
LAMBDA_ROLE_ARN     = os.environ.get("LAMBDA_ROLE_ARN", "")
SNS_TOPIC_ARN       = os.environ.get("SNS_TOPIC_ARN", "")


def _notify_result(arn: str, success: bool, reason: str = ""):
    """
    承認削除の結果メール（成功/失敗）をSNSで送信する。
    deleter は approver からのみ呼ばれる（ASLにDeleteステートは無い）ため、
    このメールは「承認された削除の完了/失敗通知」として意味が一意に決まる。
    ベストエフォート: 送信失敗しても削除結果（return値）は変えない。
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set — skipping result mail")
        return

    name = arn.split("/")[-1]
    if success:
        subject = f"[TagWatchman] Deletion completed: {name}"
        message = "\n".join([
            "=" * 60,
            "  TagWatchman — 削除完了",
            "=" * 60,
            "",
            "承認いただいた以下のリソースの削除が完了しました。",
            "",
            "【リソース情報】",
            f"  ARN: {arn}",
            "",
            "=" * 60,
        ])
    else:
        subject = f"[TagWatchman] Deletion FAILED: {name}"
        message = "\n".join([
            "=" * 60,
            "  TagWatchman — 削除失敗",
            "=" * 60,
            "",
            "承認いただいた以下のリソースの削除に失敗しました。",
            "",
            "【リソース情報】",
            f"  ARN: {arn}",
            "",
            "【エラー内容】",
            f"  {reason}",
            "",
            "【対処】",
            "  ・AWSコンソールでリソースの状態をご確認ください。",
            "  ・一時的なエラーの場合は、承認メールのURLを再度クリックすると",
            "    削除を再試行できます。",
            "",
            "=" * 60,
        ])

    # SNS Subject 制約: ASCII・改行/制御文字なし・100字未満（notifier と同一ガード）
    subject = subject.encode("ascii", "replace").decode("ascii")
    subject = subject.replace("\n", " ").replace("\r", " ")[:99]
    try:
        _client("sns").publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        logger.info("Result mail sent for ARN: %s (success=%s)", arn, success)
    except Exception as e:
        logger.error("Result mail publish failed for %s: %s", arn, e)


def _is_self_protected_iam(arn: str) -> bool:
    """
    自スタックの IAM プリンシパルを削除対象から除外する自己保全ガード。
    E パターン skip（RuntimeError raise）と違い、保護は正常系なので return で成功扱い。
    """
    if ":role/" not in arn and ":user/" not in arn:
        return False
    name = arn.rsplit("/", 1)[-1]
    if SELF_PROTECT_PREFIX and name.startswith(SELF_PROTECT_PREFIX):
        return True
    return arn in {a for a in (LAMBDA_ROLE_ARN, OPERATOR_ROLE_ARN) if a}


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

def _skip_kinesis(arn: str, region: str):
    stream_name = arn.split("/")[-1]
    raise RuntimeError(f"Kinesis stream {stream_name} is notification-only and not auto-deleted")

def _skip_elasticache(arn: str, region: str):
    rg_id = arn.split(":")[-1]
    logger.warning("ElastiCache %s skipped — notification only, no auto-deletion", rg_id)
    raise RuntimeError(f"ElastiCache {rg_id} is notification-only and not auto-deleted")

def _delete_opensearch(arn: str, region: str):
    domain_name = arn.split("/")[-1]
    _client("es", region).delete_elasticsearch_domain(DomainName=domain_name)
    logger.info("Deleted OpenSearch domain: %s", domain_name)

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

def _skip_stepfunctions(arn: str, region: str):
    sm_name = arn.split(":")[-1]
    raise RuntimeError(f"Step Functions {sm_name} is notification-only and not auto-deleted")

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

def _delete_eip(arn: str, region: str):
    alloc_id = arn.split("/")[-1]
    _client("ec2", region).release_address(AllocationId=alloc_id)
    logger.info("Released EIP: %s", alloc_id)

def _delete_apigateway(arn: str, region: str):
    # ARN: arn:aws:apigateway:ap-northeast-1::/restapis/abc123def
    api_id = arn.split("/restapis/")[-1].split("/")[0]
    _client("apigateway", region).delete_rest_api(restApiId=api_id)
    logger.info("Deleted API Gateway REST API: %s", api_id)

def _skip_vpc(arn: str, region: str):
    vpc_id = arn.split("/")[-1]
    logger.warning("VPC %s skipped — deletion requires manual operation", vpc_id)
    raise RuntimeError(f"VPC {vpc_id} requires manual deletion")

def _skip_glue(arn: str, region: str):
    db_name = arn.split("/")[-1]
    logger.warning("Glue database %s skipped — notification only, no auto-deletion", db_name)
    raise RuntimeError(f"Glue database {db_name} is notification-only and not auto-deleted")

def _skip_workspaces(arn: str, region: str):
    workspace_id = arn.split("/")[-1]
    logger.warning("Workspace %s skipped — notification only, no auto-deletion", workspace_id)
    raise RuntimeError(f"Workspace {workspace_id} is notification-only and not auto-deleted")

def _skip_secretsmanager(arn: str, region: str):
    secret_name = arn.split(":")[-1]
    logger.warning("Secrets Manager secret %s skipped — notification only, no auto-deletion", secret_name)
    raise RuntimeError(f"Secrets Manager secret {secret_name} is notification-only and not auto-deleted")

def _skip_cloudfront(arn: str, region: str):
    dist_id = arn.split("/")[-1]
    logger.warning("CloudFront distribution %s skipped — notification only, no auto-deletion", dist_id)
    raise RuntimeError(f"CloudFront distribution {dist_id} is notification-only and not auto-deleted")

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
    (r"arn:aws:es:",                           _delete_opensearch),
    (r"arn:aws:ecr:",                          _delete_ecr_repository),
    (r"arn:aws:redshift:.+:cluster:",          _delete_redshift_cluster),
    (r"arn:aws:apigateway:.+::/restapis/",     _delete_apigateway),
    # パターンB: 条件付き即時削除
    (r"arn:aws:ec2:.+:internet-gateway/",      _delete_igw),
    (r"arn:aws:ec2:.+:natgateway/",            _delete_nat_gateway),
    (r"arn:aws:ec2:.+:vpc-peering-connection/", _delete_vpc_peering),
    (r"arn:aws:ec2:.+:elastic-ip/",            _delete_eip),
    # パターンC: 権限剥奪→承認→削除
    (r"arn:aws:iam:.+:role/",                  _delete_iam_role),
    (r"arn:aws:iam:.+:user/",                  _delete_iam_user),
    # パターンE: 通知のみ（削除しない）
    (r"arn:aws:ec2:.+:vpc/",                   _skip_vpc),
    (r"arn:aws:glue:",                         _skip_glue),
    (r"arn:aws:kinesis:",                      _skip_kinesis),
    (r"arn:aws:workspaces:",                   _skip_workspaces),
    (r"arn:aws:elasticache:",                  _skip_elasticache),
    (r"arn:aws:states:",                       _skip_stepfunctions),
    (r"arn:aws:secretsmanager:",               _skip_secretsmanager),
    (r"arn:aws:cloudfront:",                   _skip_cloudfront),
    
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

    if _is_self_protected_iam(arn):
        logger.warning("Self-protected IAM principal, skipping deletion: %s", arn)
        return {**event, "deleteStatus": "self_protected"}

    if DRY_RUN:
        logger.info("[DRY RUN] Would delete: %s", arn)
        return {**event, "deleteStatus": "dry_run"}

    try:
        deleter(arn, region)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # 既に削除済み（リソース不存在）は正常扱い。
        # deleter の意味論では「対象が無い＝削除目的は達成済み」のため、
        # サービス別コードの列挙ではなく AWS 慣用の不存在系キーワードで包括判定する。
        # 列挙方式は SQS のプロトコル世代差（query: AWS.SimpleQueueService.NonExistentQueue /
        # json: QueueDoesNotExist）のようにランタイム更新で静かに破られる（2026-06-12 実機＋doc調査）。
        # この包括判定は deleter 限定。isolator / restorer には適用しない
        # （あちらでは「無い」が異常になり得るため）。
        if any(k in code for k in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist")):
            logger.warning("Resource already gone: %s (%s)", arn, code)
            return {**event, "deleteStatus": "already_deleted"}
        logger.error("Delete failed for %s: %s", arn, e)
        _notify_result(arn, success=False, reason=str(e))
        return {**event, "deleteStatus": "delete_failed", "deleteReason": str(e)}
    except Exception as e:
        # approver からの非同期 invoke のため、raise しても Lambda の自動リトライ2回が
        # サイレントに走るだけで利用者には届かない（DLQ 未設定）。
        # 失敗メール1通＋return に倒し、再試行は承認URLの再クリック
        # （execution が RUNNING の間は有効＝意図的仕様）に委ねる。
        logger.error("Unexpected error deleting %s: %s", arn, e)
        _notify_result(arn, success=False, reason=str(e))
        return {**event, "deleteStatus": "delete_failed", "deleteReason": str(e)}

    _notify_result(arn, success=True)
    return {**event, "deleteStatus": "deleted"}


def _find_deleter(arn: str) -> Optional[callable]:
    for pattern, fn in DELETERS:
        if re.search(pattern, arn):
            return fn
    return None
