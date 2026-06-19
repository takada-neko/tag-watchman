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
import base64
import hashlib
from datetime import datetime, timezone
import logging
import os
import re
from typing import Optional
 
import boto3
from botocore.exceptions import ClientError
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
DRY_RUN        = os.environ.get("DRY_RUN", "true").lower() == "true"
 
# 動的作成する隔離SGの名前（VPCごとに1つ作成・再利用）
QUARANTINE_SG_NAME = "tagwatchman-quarantine"
 
 
def _get_or_create_quarantine_sg(vpc_id: str, region: str) -> str:
    """
    対象VPC内の隔離SG（全拒否）を取得する。なければ作成する。
    全拒否 = インバウンドルールなし + アウトバウンドのデフォルト許可も削除。
    SGは同一VPC内のリソースにしか付与できないため、VPCごとに用意する。
    """
    _ec2 = boto3.client("ec2", region_name=region)
 
    # 既存の隔離SGを探す
    resp = _ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
            {"Name": "vpc-id",     "Values": [vpc_id]},
        ]
    )
    groups = resp.get("SecurityGroups", [])
    if groups:
        return groups[0]["GroupId"]
 
    # なければ作成
    create_resp = _ec2.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description="TagWatchman quarantine SG - deny all traffic",
        VpcId=vpc_id,
    )
    sg_id = create_resp["GroupId"]
 
    # アウトバウンドのデフォルト全許可ルールを削除して完全な全拒否にする
    try:
        _ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    except ClientError as e:
        # すでにルールがない場合などは無視
        logger.warning("Could not revoke default egress on %s: %s", sg_id, e)
 
    logger.info("Created quarantine SG %s in VPC %s", sg_id, vpc_id)
    return sg_id
 
# タグ付与を許可するロールのARN（これら以外はタグ付与もDenyする）
OPERATOR_ROLE_ARN = os.environ.get("OPERATOR_ROLE_ARN", "")
LAMBDA_ROLE_ARN   = os.environ.get("LAMBDA_ROLE_ARN", "")

SELF_PROTECT_PREFIX = os.environ.get("SELF_PROTECT_PREFIX", "")


def _is_self_protected_iam(arn: str) -> bool:
    """
    自スタックの IAM プリンシパル（lambda-role / operator / sfn-role 等、
    ${StackName}- 始まり）を剥奪対象から除外する自己保全ガード。
    IAM 以外の ARN は常に False（全 ARN に安全に呼べる）。
    """
    if ":role/" not in arn and ":user/" not in arn:
        return False
    name = arn.rsplit("/", 1)[-1]
    if SELF_PROTECT_PREFIX and name.startswith(SELF_PROTECT_PREFIX):
        return True
    return arn in {a for a in (LAMBDA_ROLE_ARN, OPERATOR_ROLE_ARN) if a}


def _vpc_id_from_subnet(subnet_id: str, region: str) -> str:
    """
    subnet ID から VPC ID を引く共通ヘルパー。
    EKS / ElastiCache / ECS など、describe系レスポンスに vpcId が
    直接含まれない（または moto が返さない）サービスで使う。
    """
    _ec2 = boto3.client("ec2", region_name=region)
    resp = _ec2.describe_subnets(SubnetIds=[subnet_id])
    return resp["Subnets"][0]["VpcId"]

 
def _tagging_allowed_arns() -> list[str]:
    """タグ付与を許可するロールARNのリスト（空のものは除外）"""
    return [a for a in (OPERATOR_ROLE_ARN, LAMBDA_ROLE_ARN) if a]
 
 
def _quarantine_condition() -> Optional[dict]:
    """
    主要操作Denyに付与する条件。
    restorer（lambda-role）が復旧操作（ポリシー削除等）を実行できるよう、
    lambda-role を Deny の対象から除外する。
    LAMBDA_ROLE_ARN が未設定の場合は None（条件なし＝全員Deny）。
    """
    if not LAMBDA_ROLE_ARN:
        return None
    return {
        "StringNotLike": {
            "aws:PrincipalArn": [LAMBDA_ROLE_ARN],
        }
    }
 
 
def _make_quarantine_statement(actions: list[str], resource) -> dict:
    """主要操作を拒否するステートメント（lambda-roleは除外）"""
    stmt = {
        "Sid": "TagWatchmanQuarantine",
        "Effect": "Deny",
        "Principal": "*",
        "Action": actions,
        "Resource": resource,
    }
    cond = _quarantine_condition()
    if cond:
        stmt["Condition"] = cond
    return stmt
 
 
def _make_tagging_deny_statement(actions: list[str], resource) -> Optional[dict]:
    """
    タグ付与アクションを、許可ロール以外には拒否する条件付きDenyステートメントを生成する。
    許可ロールARNが未設定の場合は None を返す（タグ付与は全員可能なまま）。
    """
    allowed = _tagging_allowed_arns()
    if not allowed:
        return None
    return {
        "Sid": "TagWatchmanTaggingRestriction",
        "Effect": "Deny",
        "Principal": "*",
        "Action": actions,
        "Resource": resource,
        "Condition": {
            "StringNotLike": {
                "aws:PrincipalArn": allowed,
            }
        },
    }
 
ec2 = boto3.client("ec2")
rds = boto3.client("rds")
s3  = boto3.client("s3")
 
# 隔離状態を記録するタグキー
TAG_QUARANTINED          = "tagwatchman:quarantined"
TAG_ORIGINAL_SGS         = "tagwatchman:original-sgs"
TAG_ORIGINAL_POLICY      = "tagwatchman:had-bucket-policy"
TAG_HAD_RESOURCE_POLICY  = "tagwatchman:had-resource-policy"  # S3以外の5サービス共通
TAG_ORIGINAL_CONCURRENCY = "tagwatchman:original-concurrency"
TAG_APIGW_STAGES         = "tagwatchman:original-stages"
TAG_POLICY_SHA256        = "tagwatchman:original-policy-sha256"
TAG_POLICY_ISOLATED_AT   = "tagwatchman:original-policy-isolated-at"
TAG_POLICY_SUMMARY_B64   = "tagwatchman:original-policy-summary-b64"


def _encode_sgs(sgs):
    # ElastiCache / Redshift はタグ値に [ ] " を許さないため json を使わず / 区切りで保存
    return "/".join(sgs)

def _original_sgs_to_save(current_sgs, quarantine_sg_id):
    """
    冪等性ガード（案イ）。現在SGから quarantine SG を除外して本物のSGだけ返す。
    - 残りが空（既に隔離済みで現在SG=quarantineのみ 等）なら None。
      呼び出し側は TAG_ORIGINAL_SGS の書き込みを丸ごとスキップ＝既存の正しい
      original タグを上書きしない。
    - 初回隔離時は quarantine が含まれないため本物SGがそのまま返る。
    """
    real = [s for s in current_sgs if s != quarantine_sg_id]
    return real or None
 
 
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

    if _is_self_protected_iam(arn):
        logger.warning("Self-protected IAM principal, skipping isolation: %s", arn)
        return {**event, "isolationStatus": "self_protected"}

    if DRY_RUN:
        logger.info("[DRY RUN] Would isolate: %s", arn)
        return {**event, "isolationStatus": "dry_run"}
 
    try:
        result = isolator(arn, region) or {}
        status = result.pop("isolationStatus", "isolated")
        return {**event, "isolationStatus": status, "lostPolicy": result}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # すでに隔離済み or リソースが存在しない場合はスキップ
        if code in ("InvalidInstanceID.NotFound", "DBInstanceNotFound",
                    "NoSuchBucket", "ResourceNotFoundException",
                    "ClusterNotFoundException"):
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
    _ec2 = boto3.client("ec2", region_name=region)
 
    # 現在のSGとVPCを取得
    resp = _ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp["Reservations"][0]["Instances"][0]
    original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    vpc_id = instance["VpcId"]
 
    # 対象インスタンスのVPC内に隔離SGを用意（なければ作成）
    quarantine_sg = _get_or_create_quarantine_sg(vpc_id, region)
 
    # 元のSGをタグに保存（冪等性ガード: quarantine SG を original として保存しない）
    tags = [{"Key": TAG_QUARANTINED, "Value": "true"}]
    sgs_to_save = _original_sgs_to_save(original_sgs, quarantine_sg)
    if sgs_to_save is not None:
        tags.append({"Key": TAG_ORIGINAL_SGS, "Value": _encode_sgs(sgs_to_save)})
    _ec2.create_tags(Resources=[instance_id], Tags=tags)
 
    # 全拒否SGに差し替え
    _ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg],
    )
 
    logger.info("EC2 %s isolated (SG=%s in VPC %s). Original SGS: %s",
                instance_id, quarantine_sg, vpc_id, original_sgs)
    return {"isolationStatus": "network_isolated"}
 
 
# ─────────────────────────────────────────────────────────────
# RDS 隔離
# ─────────────────────────────────────────────────────────────
 
def _isolate_rds(arn: str, region: str):
    db_id = arn.split(":")[-1]
    _rds = boto3.client("rds", region_name=region)

    # 現在のSGとVPCを取得
    resp = _rds.describe_db_instances(DBInstanceIdentifier=db_id)
    db = resp["DBInstances"][0]
    original_sgs = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
    db_arn = db["DBInstanceArn"]
    vpc_id = db["DBSubnetGroup"]["VpcId"]

    # 対象DBのVPC内に隔離SGを用意（なければ作成）
    quarantine_sg = _get_or_create_quarantine_sg(vpc_id, region)

    # 元のSGをタグに保存（冪等性ガード: quarantine SG を original として保存しない）
    tags = [{"Key": TAG_QUARANTINED, "Value": "true"}]
    sgs_to_save = _original_sgs_to_save(original_sgs, quarantine_sg)
    if sgs_to_save is not None:
        tags.append({"Key": TAG_ORIGINAL_SGS, "Value": _encode_sgs(sgs_to_save)})
    _rds.add_tags_to_resource(ResourceName=db_arn, Tags=tags)

    # 全拒否SGに差し替え
    _rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        VpcSecurityGroupIds=[quarantine_sg],
        ApplyImmediately=True,
    )

    logger.info("RDS %s isolated (SG=%s in VPC %s). Original SGS: %s",
                db_id, quarantine_sg, vpc_id, original_sgs)
    return {"isolationStatus": "network_isolated"}
 
 
# ─────────────────────────────────────────────────────────────
# S3 隔離
# ─────────────────────────────────────────────────────────────

def _policy_summary_b64(policy_json: str) -> str:
    """元ポリシーの概観を b64 で返す（タグ値256字内・本文はメールへ）。"""
    try:
        doc = json.loads(policy_json)
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        allow = sum(1 for s in stmts if s.get("Effect") == "Allow")
        deny  = sum(1 for s in stmts if s.get("Effect") == "Deny")
        def _wild(s):
            p = s.get("Principal")
            return p == "*" or (isinstance(p, dict) and "*" in p.values())
        summary = {"st": len(stmts), "al": allow, "dy": deny,
                   "wild": any(_wild(s) for s in stmts)}
    except Exception:
        summary = {"err": "unparsable"}
    raw = json.dumps(summary, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _policy_trace_pairs(had_policy: bool, original_policy: Optional[str]) -> list:
    """リソースポリシー系（S3以外の5サービス）の痕跡タグを (Key, Value) 列で返す。

    _isolate_s3 と同じ情報を、サービス非依存の中立キーで付与する。
    - 有無フラグ(had-resource-policy)は常に付与。S3専用の had-bucket-policy とは別キー。
    - ポリシーがあった時だけ sha256 / isolated-at / summary を追加（本文の正本はメール）。
    痕跡はどの Lambda も機械的に読まない（フォレンジック専用）。
    """
    pairs = [(TAG_HAD_RESOURCE_POLICY, str(bool(had_policy)))]
    if had_policy and original_policy:
        sha = hashlib.sha256(original_policy.encode("utf-8")).hexdigest()
        isolated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        pairs += [
            (TAG_POLICY_SHA256,      sha),
            (TAG_POLICY_ISOLATED_AT, isolated_at),
            (TAG_POLICY_SUMMARY_B64, _policy_summary_b64(original_policy)),
        ]
    return pairs


def _isolate_s3(arn: str, region: str):
    bucket = arn.split(":::")[-1]

    # 既存バケットポリシー本文を取得（痕跡化のため本文ごと退避）
    had_policy = False
    original_policy = None
    try:
        resp = s3.get_bucket_policy(Bucket=bucket)
        original_policy = resp["Policy"]
        had_policy = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
 
    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # s3:PutBucketTagging / s3:GetBucketTagging は除外
    # lambda-role（restorer）は復旧のため主要操作Denyからも除外
    statements = [
        _make_quarantine_statement(
            [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:ListBucket",
                "s3:ListBucketVersions",
                "s3:GetBucketAcl",
                "s3:PutBucketAcl",
                "s3:DeleteBucket",
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
                "s3:DeleteBucketPolicy",
                "s3:GetBucketCORS",
                "s3:PutBucketCORS",
                "s3:GetBucketWebsite",
                "s3:PutBucketWebsite",
                "s3:GetBucketVersioning",
                "s3:PutBucketVersioning",
                "s3:GetLifecycleConfiguration",
                "s3:PutLifecycleConfiguration",
            ],
            [
                f"arn:aws:s3:::{bucket}",
                f"arn:aws:s3:::{bucket}/*",
            ],
        )
    ]
    # 許可ロール以外のタグ付与を拒否
    tagging_deny = _make_tagging_deny_statement(
        ["s3:PutBucketTagging"], f"arn:aws:s3:::{bucket}"
    )
    if tagging_deny:
        statements.append(tagging_deny)
 
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })
 
    # 元のポリシー有無＋痕跡をタグに保存（既存タグを保持＝put_bucket_tagging は全置換のため）
    try:
        existing = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchTagSet", "NoSuchTagSetError"):
            existing = []
        else:
            raise
    # 自前の tagwatchman: 系は付け直すので一旦除外（必須タグ等の非接頭は保持）
    tag_set = [t for t in existing if not t["Key"].startswith("tagwatchman:")]
    tag_set += [
        {"Key": TAG_QUARANTINED,     "Value": "true"},
        {"Key": TAG_ORIGINAL_POLICY, "Value": str(had_policy)},
    ]
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        sha = hashlib.sha256(original_policy.encode("utf-8")).hexdigest()
        isolated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tag_set += [
            {"Key": TAG_POLICY_SHA256,      "Value": sha},
            {"Key": TAG_POLICY_ISOLATED_AT, "Value": isolated_at},
            {"Key": TAG_POLICY_SUMMARY_B64, "Value": _policy_summary_b64(original_policy)},
        ]
        trace = {"had": True, "body": original_policy}

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})

    s3.put_bucket_policy(Bucket=bucket, Policy=deny_policy)
    logger.info("S3 bucket %s isolated. Had existing policy: %s", bucket, had_policy)
    return {"isolationStatus": "policy_denied", **trace}
 
 
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
    return {"isolationStatus": "concurrency_zero"}
 
 
# ─────────────────────────────────────────────────────────────
# DynamoDB 隔離（リソースポリシーで全拒否）
# ─────────────────────────────────────────────────────────────
 
def _isolate_dynamodb(arn: str, region: str):
    _dynamodb = boto3.client("dynamodb", region_name=region)

    # 既存リソースポリシー本文を取得（痕跡化のため本文ごと退避・S3と同型）
    # 未設定時は PolicyNotFoundException
    had_policy = False
    original_policy = None
    try:
        resp = _dynamodb.get_resource_policy(ResourceArn=arn)
        original_policy = resp.get("Policy")
        had_policy = bool(original_policy)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PolicyNotFoundException":
            raise

    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # dynamodb:TagResource / dynamodb:UntagResource / dynamodb:ListTagsOfResource は除外
    # lambda-role（restorer）は復旧のため主要操作Denyからも除外
    #
    # 【DynamoDB固有】table の resource-based policy は table リソースに対する
    # アクションのみ有効。dynamodb:CreateTable（アカウントレベル）、
    # dynamodb:RestoreTableFromBackup / dynamodb:DeleteBackup（backup リソース対象）は
    # 載せると PutResourcePolicy が ValidationException("action names are invalid")
    # で全体失敗する（実機確定）ため除外。
    statements = [
        _make_quarantine_statement(
            [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:BatchGetItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:DeleteTable",
                "dynamodb:UpdateTable",
                "dynamodb:DescribeTable",
                "dynamodb:CreateBackup",
                "dynamodb:ExportTableToPointInTime",
            ],
            arn,
        )
    ]
    tagging_deny = _make_tagging_deny_statement(["dynamodb:TagResource"], arn)
    if tagging_deny:
        statements.append(tagging_deny)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })

    _dynamodb.put_resource_policy(ResourceArn=arn, Policy=deny_policy)

    # タグに記録
    table_name = arn.split("/")[-1]
    _dynamodb.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"},
              *({"Key": k, "Value": v}
                for k, v in _policy_trace_pairs(had_policy, original_policy))],
    )

    logger.info("DynamoDB table %s isolated. Had existing policy: %s", table_name, had_policy)
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        trace = {"had": True, "body": original_policy}
    return {"isolationStatus": "policy_denied", **trace}
 
 
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

    # 既存キューポリシー本文を取得（痕跡化のため本文ごと退避・S3と同型）
    # SQSは未設定時に例外でなく Attributes に Policy キーが無いだけ
    attrs = _sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["Policy"],
    ).get("Attributes", {})
    original_policy = attrs.get("Policy")
    had_policy = bool(original_policy)

    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # sqs:TagQueue / sqs:UntagQueue / sqs:ListQueueTags は除外
    # lambda-role（restorer）は復旧のため主要操作Denyからも除外
    #
    # 【SQS固有】SQSポリシーは「1ステートメントあたり action 上限7」（SQSポリシークォータ）。
    # 共通ヘルパ _make_quarantine_statement は1ステートメントに全actionを入れるため、
    # SQSに10action渡すと OverLimit("max allowed is 7") で失敗する。
    # 他サービス(SNS/DynamoDB/ECR/S3)はこの上限が無いので
    # 共通ヘルパは変更せず、SQSだけ7個ずつ分割した複数Denyステートメントを組む。
    deny_actions = [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:ChangeMessageVisibility",
        "sqs:GetQueueAttributes",
        "sqs:SetQueueAttributes",
        "sqs:PurgeQueue",
        "sqs:DeleteQueue",
        "sqs:GetQueueUrl",
        "sqs:ListDeadLetterSourceQueues",
    ]
    SQS_MAX_ACTIONS_PER_STATEMENT = 7
    cond = _quarantine_condition()  # 共通の carve-out（lambda-role除外）を再利用

    statements = []
    for idx in range(0, len(deny_actions), SQS_MAX_ACTIONS_PER_STATEMENT):
        chunk = deny_actions[idx:idx + SQS_MAX_ACTIONS_PER_STATEMENT]
        stmt = {
            "Sid": f"TagWatchmanQuarantine{idx // SQS_MAX_ACTIONS_PER_STATEMENT + 1}",
            "Effect": "Deny",
            "Principal": "*",
            "Action": chunk,
            "Resource": arn,
        }
        if cond:
            stmt["Condition"] = cond
        statements.append(stmt)

    tagging_deny = _make_tagging_deny_statement(["sqs:TagQueue"], arn)
    if tagging_deny:
        statements.append(tagging_deny)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })

    _sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={"Policy": deny_policy},
    )

    _sqs_tags = {TAG_QUARANTINED: "true"}
    _sqs_tags.update(dict(_policy_trace_pairs(had_policy, original_policy)))
    _sqs.tag_queue(QueueUrl=url, Tags=_sqs_tags)
    logger.info("SQS queue %s isolated (%d deny statements). Had existing policy: %s",
                queue_name, len(statements), had_policy)
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        trace = {"had": True, "body": original_policy}
    return {"isolationStatus": "policy_denied", **trace}
 
 
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

    # VPC ID は subnet から引く
    subnet_ids = nc.get("subnets", [])
    if not subnet_ids:
        raise ValueError(f"ECS service {service} has no subnets (not awsvpc mode?)")
    vpc_id = _vpc_id_from_subnet(subnet_ids[0], region)

    # 対象サービスのVPC内に隔離SGを用意（なければ作成）
    quarantine_sg = _get_or_create_quarantine_sg(vpc_id, region)

    # タグに保存（冪等性ガード: quarantine SG を original として保存しない）
    tags = [{"key": TAG_QUARANTINED, "value": "true"}]
    sgs_to_save = _original_sgs_to_save(original_sgs, quarantine_sg)
    if sgs_to_save is not None:
        tags.append({"key": TAG_ORIGINAL_SGS, "value": _encode_sgs(sgs_to_save)})
    _ecs.tag_resource(resourceArn=arn, tags=tags)

    # 全拒否SGに差し替え（subnetは温存し、SGのみ差し替え）
    _ecs.update_service(
        cluster=cluster,
        service=service,
        networkConfiguration={
            "awsvpcConfiguration": {
                **nc,
                "securityGroups": [quarantine_sg],
            }
        },
    )

    logger.info("ECS service %s isolated (SG=%s in VPC %s). Original SGS: %s",
                service, quarantine_sg, vpc_id, original_sgs)
    return {"isolationStatus": "network_isolated"}
 
 
# ─────────────────────────────────────────────────────────────
# EKS 隔離（クラスターのSGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────
 
def _isolate_eks(arn: str, region: str):
    _eks = boto3.client("eks", region_name=region)
    cluster_name = arn.split("/")[-1]

    # 現在のSGとsubnetを取得
    resp = _eks.describe_cluster(name=cluster_name)
    vpc_cfg = resp["cluster"]["resourcesVpcConfig"]
    original_sgs = vpc_cfg.get("securityGroupIds", [])

    # VPC ID は subnet から引く
    # （resourcesVpcConfig.vpcId は実AWSには存在するが moto が返さないため、
    #   実AWS・テスト両対応のため subnet 経由で解決する）
    subnet_ids = vpc_cfg.get("subnetIds", [])
    if not subnet_ids:
        raise ValueError(f"EKS cluster {cluster_name} has no subnets")
    vpc_id = _vpc_id_from_subnet(subnet_ids[0], region)

    # 対象クラスタのVPC内に隔離SGを用意（なければ作成）
    quarantine_sg = _get_or_create_quarantine_sg(vpc_id, region)

    # タグに保存（冪等性ガード: quarantine SG を original として保存しない）
    tags = {TAG_QUARANTINED: "true"}
    sgs_to_save = _original_sgs_to_save(original_sgs, quarantine_sg)
    if sgs_to_save is not None:
        tags[TAG_ORIGINAL_SGS] = _encode_sgs(sgs_to_save)
    _eks.tag_resource(resourceArn=arn, tags=tags)

    # 全拒否SGに差し替え
    _eks.update_cluster_config(
        name=cluster_name,
        resourcesVpcConfig={"securityGroupIds": [quarantine_sg]},
    )

    logger.info("EKS cluster %s isolated (SG=%s in VPC %s). Original SGS: %s",
                cluster_name, quarantine_sg, vpc_id, original_sgs)
    return {"isolationStatus": "network_isolated"}
 
 
# ─────────────────────────────────────────────────────────────
# ElastiCache 通知のみ（隔離・削除はしない）— v2でA系から降格
# describe ステータスが内部実態から大きく遅延し、available 表示後も
# add_tags / modify が40分超弾かれ続ける（v2実測）。線形2分・最大60分の
# リトライでもSG差し替え完了に収束せず、「素早く無害化」という隔離本来の
# 目的を満たさないため通知のみとする。_encode_sgs は Redshift が使うため残置。
# ─────────────────────────────────────────────────────────────
def _isolate_elasticache(arn: str, region: str):
    rg_id = arn.split(":")[-1]
    logger.warning(
        "ElastiCache %s detected without tags — notification only. "
        "SG-swap isolation was demoted because describe status lags real "
        "state so severely that tagging/modify stay rejected well beyond the "
        "60-minute retry window.",
        rg_id,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}
 
 
# ─────────────────────────────────────────────────────────────
# SNS 隔離（トピックポリシーで全拒否）
# ─────────────────────────────────────────────────────────────
 
def _isolate_sns(arn: str, region: str):
    _sns = boto3.client("sns", region_name=region)

    # 既存トピックポリシー本文を取得（痕跡化のため本文ごと退避・S3と同型）
    # SNSトピックは作成時に必ずデフォルトポリシー(__default_policy_ID)を持つため
    # had は実質常に True になる（デフォルト文面も deny 上書きで失われるため正確に捕捉する）
    attrs = _sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
    original_policy = attrs.get("Policy")
    had_policy = bool(original_policy)

    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # sns:TagResource / sns:UntagResource / sns:ListTagsForResource は除外
    # lambda-role（restorer）は復旧のため主要操作Denyからも除外
    #
    # 【SNS固有】topic の resource policy に載せられる action はトピック操作のみ。
    # sns:Unsubscribe / sns:ConfirmSubscription（subscription 対象の操作）を含めると
    # SetTopicAttributes が InvalidParameter("Policy statement action out of
    # service scope!") で全体失敗する（実機確定）ため除外。有効 action 集合は
    # デフォルトポリシー(__default_policy_ID)が列挙する8つと一致する。
    statements = [
        _make_quarantine_statement(
            [
                "sns:Publish",
                "sns:Subscribe",
                "sns:SetTopicAttributes",
                "sns:GetTopicAttributes",
                "sns:DeleteTopic",
                "sns:ListSubscriptionsByTopic",
                "sns:AddPermission",
                "sns:RemovePermission",
            ],
            arn,
        )
    ]
    tagging_deny = _make_tagging_deny_statement(["sns:TagResource"], arn)
    if tagging_deny:
        statements.append(tagging_deny)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })

    _sns.set_topic_attributes(
        TopicArn=arn,
        AttributeName="Policy",
        AttributeValue=deny_policy,
    )

    _sns.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": TAG_QUARANTINED, "Value": "true"},
              *({"Key": k, "Value": v}
                for k, v in _policy_trace_pairs(had_policy, original_policy))],
    )

    logger.info("SNS topic %s isolated. Had existing policy: %s",
                arn.split(":")[-1], had_policy)
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        trace = {"had": True, "body": original_policy}
    return {"isolationStatus": "policy_denied", **trace}
 
 
# ─────────────────────────────────────────────────────────────
# Kinesis 通知のみ（隔離・削除はしない）— v17で A系(リソースポリシー全拒否)から降格
# Kinesis の resource-based policy はワイルドカード Principal を許可せず
# (実機: "The resource policy cannot contain the wildcard principal")、
# 全プリンシパル一括拒否が原理的に表現不可。さらに DeleteStream/UpdateShardCount/
# SplitShard/MergeShards/SubscribeToShard は resource policy 非対応アクションで
# InvalidArgumentException となる。「素早く無害化」という隔離本来の目的を
# resource policy では満たせないため通知のみとする。
# ─────────────────────────────────────────────────────────────
def _isolate_kinesis(arn: str, region: str):
    stream_name = arn.split("/")[-1]
    logger.warning(
        "Kinesis stream '%s' detected without tags — notification only. "
        "Resource-based policy cannot use a wildcard principal, so an "
        "all-principals deny (full isolation) is impossible; management "
        "actions are also unsupported in resource policy.",
        stream_name,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}
 
 
# ─────────────────────────────────────────────────────────────
# OpenSearch 隔離（アクセスポリシーで全拒否）
# ─────────────────────────────────────────────────────────────
class OpenSearchChangeInProgressError(Exception):
    """OpenSearch ドメインが変更処理中で update を受け付けない状態（実機確定）。
    ES は状態ロックを汎用 ValidationException で返すため、永続エラーと
    区別できる固有例外に変換し ASL Retry（ErrorEquals）で吸収する。"""

 
def _isolate_opensearch(arn: str, region: str):
    _es = boto3.client("es", region_name=region)
    domain_name = arn.split("/")[-1]

    # 既存アクセスポリシー本文を取得（痕跡化のため本文ごと退避・S3と同型）
    # 未設定時は例外でなく空文字列が返る
    config = _es.describe_elasticsearch_domain_config(
        DomainName=domain_name,
    ).get("DomainConfig", {})
    original_policy = config.get("AccessPolicies", {}).get("Options", "")
    had_policy = bool(original_policy)

    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # es:AddTags / es:RemoveTags / es:ListTags は除外
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": [
                    "es:ESHttpGet",
                    "es:ESHttpPut",
                    "es:ESHttpPost",
                    "es:ESHttpDelete",
                    "es:ESHttpHead",
                    "es:ESHttpPatch",
                    "es:DescribeElasticsearchDomain",
                    "es:UpdateElasticsearchDomainConfig",
                    "es:DeleteElasticsearchDomain",
                    "es:CreateElasticsearchDomain",
                ],
                "Resource": f"{arn}/*",
            }
        ],
    })

    try:
        _es.update_elasticsearch_domain_config(
            DomainName=domain_name,
            AccessPolicies=deny_policy,
        )
    except ClientError as e:
        if (e.response["Error"]["Code"] == "ValidationException"
                and "in progress" in str(e)):
            raise OpenSearchChangeInProgressError(str(e)) from e
        raise

    _es.add_tags(
        ARN=arn,
        TagList=[{"Key": TAG_QUARANTINED, "Value": "true"},
                 *({"Key": k, "Value": v}
                   for k, v in _policy_trace_pairs(had_policy, original_policy))],
    )

    logger.info("OpenSearch domain %s isolated. Had existing policy: %s",
                domain_name, had_policy)
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        trace = {"had": True, "body": original_policy}
    return {"isolationStatus": "policy_denied", **trace}
 
 
# ─────────────────────────────────────────────────────────────
# ECR 隔離（リポジトリポリシーで全拒否）
# ─────────────────────────────────────────────────────────────
 
def _isolate_ecr(arn: str, region: str):
    _ecr = boto3.client("ecr", region_name=region)
    repo_name = arn.split("/")[-1]

    # 既存リポジトリポリシー本文を取得（痕跡化のため本文ごと退避・S3と同型）
    # 未設定時は RepositoryPolicyNotFoundException
    had_policy = False
    original_policy = None
    try:
        resp = _ecr.get_repository_policy(repositoryName=repo_name)
        original_policy = resp.get("policyText")
        had_policy = bool(original_policy)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryPolicyNotFoundException":
            raise

    # 主要操作を拒否（タグ付与は許可して復旧の道を残す）
    # ecr:TagResource / ecr:UntagResource / ecr:ListTagsForResource は除外
    # lambda-role（restorer）は復旧のため主要操作Denyからも除外
    statements = [
        _make_quarantine_statement(
            [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DeleteRepository",
                "ecr:DeleteRepositoryPolicy",
                "ecr:SetRepositoryPolicy",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:BatchDeleteImage",
                "ecr:DescribeImages",
            ],
            arn,
        )
    ]
    tagging_deny = _make_tagging_deny_statement(["ecr:TagResource"], arn)
    if tagging_deny:
        statements.append(tagging_deny)

    # ECR の repository policy は Resource 要素を受け付けない（実機確定）。
    # ポリシーがリポジトリ自体に暗黙紐付けされるため、statement から除去する。
    # shared helper は変更せず ECR ローカルで pop する（SQS 7分割と同方針）。
    for _stmt in statements:
        _stmt.pop("Resource", None)

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })

    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    })

    _ecr.set_repository_policy(
        repositoryName=repo_name,
        policyText=deny_policy,
    )

    _ecr.tag_resource(
        resourceArn=arn,
        tags=[{"Key": TAG_QUARANTINED, "Value": "true"},
              *({"Key": k, "Value": v}
                for k, v in _policy_trace_pairs(had_policy, original_policy))],
    )

    logger.info("ECR repository %s isolated. Had existing policy: %s",
                repo_name, had_policy)
    trace = {"had": False, "body": ""}
    if had_policy and original_policy:
        trace = {"had": True, "body": original_policy}
    return {"isolationStatus": "policy_denied", **trace}
 
 
# ─────────────────────────────────────────────────────────────
# Redshift 隔離（SGを全拒否に差し替え）
# ─────────────────────────────────────────────────────────────
 
def _isolate_redshift(arn: str, region: str):
    _rs = boto3.client("redshift", region_name=region)
    cluster_id = arn.split(":")[-1]

    # 現在のSGとsubnet group名を取得
    resp = _rs.describe_clusters(ClusterIdentifier=cluster_id)
    cl = resp["Clusters"][0]
    original_sgs = [
        sg["VpcSecurityGroupId"]
        for sg in cl.get("VpcSecurityGroups", [])
    ]

    # ClusterSubnetGroupName → VpcId を解決
    # （describe_clusters.VpcId は実AWSには存在するが moto が返さないため、
    #   subnet group 経由で解決する）
    subnet_group_name = cl["ClusterSubnetGroupName"]
    sg_resp = _rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=subnet_group_name)
    vpc_id = sg_resp["ClusterSubnetGroups"][0]["VpcId"]

    # 対象クラスタのVPC内に隔離SGを用意（なければ作成）
    quarantine_sg = _get_or_create_quarantine_sg(vpc_id, region)

    # 元のSGをタグに保存（冪等性ガード: quarantine SG を original として保存しない）
    tags = [{"Key": TAG_QUARANTINED, "Value": "true"}]
    sgs_to_save = _original_sgs_to_save(original_sgs, quarantine_sg)
    if sgs_to_save is not None:
        tags.append({"Key": TAG_ORIGINAL_SGS, "Value": _encode_sgs(sgs_to_save)})
    _rs.create_tags(ResourceName=arn, Tags=tags)

    # 全拒否SGに差し替え
    _rs.modify_cluster(
        ClusterIdentifier=cluster_id,
        VpcSecurityGroupIds=[quarantine_sg],
    )

    logger.info("Redshift cluster %s isolated (SG=%s in VPC %s). Original SGS: %s",
                cluster_id, quarantine_sg, vpc_id, original_sgs)
    return {"isolationStatus": "network_isolated"}


# ─────────────────────────────────────────────────────────────
# Step Functions 通知のみ（隔離・削除はしない）— v22でA系(リソースポリシー全拒否)から降格
# Step Functions の state machine は resource-based policy 非対応で、
# boto3 stepfunctions クライアントに set_resource_policy 操作が存在しない
# （旧実装はデッドコード＝実行されれば deny 構築以前に AttributeError で即死）。
# resource policy による全プリンシパル拒否が原理的に表現不可のため通知のみとする。
# ─────────────────────────────────────────────────────────────
def _isolate_stepfunctions(arn: str, region: str):
    logger.warning(
        "Step Functions has no resource-based policy support; notify only: %s", arn
    )
    return {"isolationStatus": "notify_only"}
 
 
# ─────────────────────────────────────────────────────────────
# Workspaces 通知のみ（隔離・削除はしない）
# 個別Workspaceの通信遮断は不可能。SGは workspaceSecurityGroupId として
# Directory単位で共有されるため、差し替えると同一Directory内の無関係な
# Workspaceまで巻き込む。よって通知のみとする。
# ─────────────────────────────────────────────────────────────

def _isolate_workspaces(arn: str, region: str):
    workspace_id = arn.split("/")[-1]
    logger.warning(
        "Workspace %s detected without tags — notification only. "
        "Per-workspace isolation is not feasible because the security group "
        "is shared at the directory level.",
        workspace_id,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}
 
 
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
        logger.warning(
            "IGW %s is attached — skipping deletion, manual review required", igw_id
        )
        # status を返して正常終了 → Step Functionsフローが継続して通知メールが飛ぶ
        return {"isolationStatus": "network_manual_review"}
 
    # アタッチなし → 即時削除
    _ec2.delete_internet_gateway(InternetGatewayId=igw_id)
    logger.info("IGW %s deleted (was not attached)", igw_id)
    return {"isolationStatus": "network_immediate_delete"}
 
 
# ─────────────────────────────────────────────────────────────
# NAT Gateway 即時削除
# ─────────────────────────────────────────────────────────────
 
def _isolate_nat_gateway(arn: str, region: str):
    _ec2  = boto3.client("ec2", region_name=region)
    nat_id = arn.split("/")[-1]
 
    _ec2.delete_nat_gateway(NatGatewayId=nat_id)
    logger.info("NAT Gateway %s deleted", nat_id)
    return {"isolationStatus": "network_immediate_delete"}
 
 
# ─────────────────────────────────────────────────────────────
# VPC Peering 即時削除
# ─────────────────────────────────────────────────────────────
 
def _isolate_vpc_peering(arn: str, region: str):
    _ec2       = boto3.client("ec2", region_name=region)
    peering_id = arn.split("/")[-1]
 
    _ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=peering_id)
    logger.info("VPC Peering %s deleted", peering_id)
    return {"isolationStatus": "network_immediate_delete"}
 
 
# ─────────────────────────────────────────────────────────────
# IAM 隔離 共通ヘルパー
# ─────────────────────────────────────────────────────────────

def _capture_iam_policies(iam, *, role_name=None, user_name=None):
    """剥奪前に managed ARN 一覧・インライン本文・(User のみ)アクセスキーを退避し、
    復旧用の人間可読テキストを body として返す。自動復旧はしない（材料の提供のみ）。"""
    lines = []
    captured = False

    if role_name:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    else:
        attached = iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        inline_names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])

    if attached:
        captured = True
        lines.append("[マネージドポリシー（再アタッチで復元可）]")
        for p in attached:
            lines.append(f"  - {p['PolicyArn']}")

    if inline_names:
        captured = True
        lines.append("[インラインポリシー（削除されます・本文から再作成してください）]")
        for name in inline_names:
            if role_name:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            else:
                doc = iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
            body = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
            lines.append(f"  - {name}:")
            lines.append(f"    {body}")

    if user_name:
        keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        if keys:
            captured = True
            lines.append("[無効化したアクセスキー（必要なら再有効化してください）]")
            for k in keys:
                lines.append(f"  - {k['AccessKeyId']}")

    return captured, "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# IAM Role 隔離（ポリシーを全剥奪）
# ─────────────────────────────────────────────────────────────
 
def _isolate_iam_role(arn: str, region: str):
    if _is_self_protected_iam(arn):
        logger.warning("Self-protected IAM role, skipping isolation: %s", arn)
        return
    _iam      = boto3.client("iam")
    role_name = arn.split("/")[-1]

    # 剥奪前にオリジナルを退避（復旧材料の提供のみ・自動復旧はしない）
    had, body = _capture_iam_policies(_iam, role_name=role_name)

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
    return {"isolationStatus": "permissions_revoked", "had": had, "body": body}
 
 
# ─────────────────────────────────────────────────────────────
# IAM User 隔離（ポリシー全剥奪 + アクセスキー無効化）
# ─────────────────────────────────────────────────────────────
 
def _isolate_iam_user(arn: str, region: str):
    if _is_self_protected_iam(arn):
        logger.warning("Self-protected IAM user, skipping isolation: %s", arn)
        return
    _iam      = boto3.client("iam")
    user_name = arn.split("/")[-1]

    # 剥奪前にオリジナルを退避（復旧材料の提供のみ・自動復旧はしない）
    had, body = _capture_iam_policies(_iam, user_name=user_name)

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
    return {"isolationStatus": "permissions_revoked", "had": had, "body": body}
 
 
# ─────────────────────────────────────────────────────────────
# VPC 通知のみ（隔離・削除はしない）
# ─────────────────────────────────────────────────────────────
 
def _isolate_vpc(arn: str, region: str):
    vpc_id = arn.split("/")[-1]
    logger.warning(
        "VPC %s detected without tags — notification only. "
        "VPC deletion is too risky to automate.",
        vpc_id,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}
 
 
# ─────────────────────────────────────────────────────────────
# EIP 隔離（アタッチなし → 即時解放 / アタッチあり → 通知のみ）
# ─────────────────────────────────────────────────────────────
 
def _isolate_eip(arn: str, region: str):
    _ec2 = boto3.client("ec2", region_name=region)
    alloc_id = arn.split("/")[-1]
 
    resp = _ec2.describe_addresses(AllocationIds=[alloc_id])
    address = resp["Addresses"][0]
 
    # アタッチされているか確認
    instance_id      = address.get("InstanceId")
    network_interface = address.get("NetworkInterfaceId")
 
    if instance_id or network_interface:
        # アタッチあり → 通知のみ
        logger.warning(
            "EIP %s is associated with %s — skipping release, manual review required",
            alloc_id,
            instance_id or network_interface,
        )
        # status を返して正常終了 → Step Functionsフローが継続して通知メールが飛ぶ
        return {"isolationStatus": "network_manual_review"}
 
    # アタッチなし → 即時解放
    _ec2.release_address(AllocationId=alloc_id)
    logger.info("EIP %s released (was not associated)", alloc_id)
    return {"isolationStatus": "network_immediate_delete"}
 
 
# ─────────────────────────────────────────────────────────────
# API Gateway 隔離（ステージを全削除してエンドポイント無効化）
# ─────────────────────────────────────────────────────────────
 
def _isolate_apigateway(arn: str, region: str):
    # ARN: arn:aws:apigateway:ap-northeast-1::/restapis/abc123def
    _apigw = boto3.client("apigateway", region_name=region)
    api_id = arn.split("/restapis/")[-1].split("/")[0]
 
    # 全ステージを取得
    resp   = _apigw.get_stages(restApiId=api_id)
    stages = resp.get("item", [])
 
    if not stages:
        logger.info("API Gateway %s has no stages — nothing to isolate", api_id)
        _apigw.tag_resource(
            resourceArn=arn,
            tags={
                TAG_QUARANTINED:  "true",
                TAG_APIGW_STAGES: base64.b64encode(b"[]").decode("ascii"),
            },
        )
        return {"isolationStatus": "stages_deleted"}
 
    # 復旧に必要な情報をタグに保存（stageName, deploymentId, variables, description）
    stage_info = [
        {
            "stageName":    s["stageName"],
            "deploymentId": s.get("deploymentId", ""),
            "variables":    s.get("variables", {}),
            "description":  s.get("description", ""),
        }
        for s in stages
    ]
    stage_json = json.dumps(stage_info, ensure_ascii=False)
    stage_tag  = base64.b64encode(stage_json.encode("utf-8")).decode("ascii")
 
    # タグ値256文字超過対策: 判定は base64後の長さで行う
    # （base64は約33%膨張するため、生JSON長で判定すると実機で256超過し得る）。
    # 超えた場合はステージ名とdeploymentIdのみに切り詰めて再度base64化。
    if len(stage_tag) > 256:
        logger.warning(
            "API Gateway %s stage info exceeds 256 chars after base64 (%d). "
            "Saving stage names only — manual variable restoration required.",
            api_id, len(stage_tag),
        )
        stage_json = json.dumps(
            [{"stageName": s["stageName"], "deploymentId": s.get("deploymentId", "")}
             for s in stages],
            ensure_ascii=False,
        )
        stage_tag = base64.b64encode(stage_json.encode("utf-8")).decode("ascii")
 
    _apigw.tag_resource(
        resourceArn=arn,
        tags={
            TAG_QUARANTINED:  "true",
            TAG_APIGW_STAGES: stage_tag,
        },
    )
 
    # 全ステージを削除
    for s in stages:
        _apigw.delete_stage(restApiId=api_id, stageName=s["stageName"])
        logger.info("API Gateway %s stage '%s' deleted", api_id, s["stageName"])
 
    logger.info("API Gateway %s isolated. Deleted %d stage(s)", api_id, len(stages))
    return {"isolationStatus": "stages_deleted"}
 
 
# ─────────────────────────────────────────────────────────────
# Glue 通知のみ
# リソースポリシーがデータカタログ全体に適用されるため
# database単位での隔離が不可能。通知のみとする。
# ─────────────────────────────────────────────────────────────
 
def _isolate_glue(arn: str, region: str):
    db_name = arn.split("/")[-1]
    logger.warning(
        "Glue database '%s' detected without tags — notification only. "
        "Glue resource policy applies account-wide and cannot isolate per database.",
        db_name,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}


# ─────────────────────────────────────────────────────────────
# secretsmanager 通知のみ
# ─────────────────────────────────────────────────────────────
def _isolate_secretsmanager(arn: str, region: str):
    secret_name = arn.split(":")[-1]
    logger.warning(
        "Secrets Manager secret %s detected without tags — notification only. "
        "Secret isolation/deletion is too risky to automate.",
        secret_name,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}


# ─────────────────────────────────────────────────────────────
# cloudfront 通知のみ
# ─────────────────────────────────────────────────────────────
def _isolate_cloudfront(arn: str, region: str):
    dist_id = arn.split("/")[-1]
    logger.warning(
        "CloudFront distribution %s detected without tags — notification only. "
        "Distribution disable/deletion is too risky to automate.",
        dist_id,
    )
    # 隔離せず通知のみ。notifier に notify_only を伝える
    return {"isolationStatus": "notify_only"}
 

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
    (r"arn:aws:sns:",                    _isolate_sns),
    (r"arn:aws:es:",                     _isolate_opensearch),
    (r"arn:aws:ecr:",                    _isolate_ecr),
    (r"arn:aws:redshift:",               _isolate_redshift),
    (r"arn:aws:apigateway:.+::/restapis/", _isolate_apigateway),
    # パターンB: 条件付き即時削除
    (r"arn:aws:ec2:.+:internet-gateway/",       _isolate_igw),
    (r"arn:aws:ec2:.+:natgateway/",             _isolate_nat_gateway),
    (r"arn:aws:ec2:.+:vpc-peering-connection/", _isolate_vpc_peering),
    (r"arn:aws:ec2:.+:elastic-ip/",             _isolate_eip),
    # パターンC: 権限剥奪→承認→削除
    (r"arn:aws:iam:.+:role/",            _isolate_iam_role),
    (r"arn:aws:iam:.+:user/",            _isolate_iam_user),
    # パターンE: 通知のみ
    (r"arn:aws:elasticache:",            _isolate_elasticache),
    (r"arn:aws:states:",                 _isolate_stepfunctions),
    (r"arn:aws:ec2:.+:vpc/",             _isolate_vpc),
    (r"arn:aws:glue:",                   _isolate_glue),
    (r"arn:aws:kinesis:",                _isolate_kinesis),    
    (r"arn:aws:workspaces:",             _isolate_workspaces),
    (r"arn:aws:secretsmanager:",         _isolate_secretsmanager), 
    (r"arn:aws:cloudfront:",             _isolate_cloudfront),
]
 
 
def _find_isolator(arn: str) -> Optional[callable]:
    for pattern, fn in ISOLATORS:
        if re.search(pattern, arn):
            return fn
    return None
