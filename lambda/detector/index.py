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
import time
from typing import Optional

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

STATE_MACHINE_ARN   = os.environ.get("STATE_MACHINE_ARN", "")
ACCOUNT_ID          = boto3.client("sts").get_caller_identity()["Account"]
DEFAULT_REGION      = os.environ.get("AWS_REGION", "ap-northeast-1")

sfn     = boto3.client("stepfunctions")

from tag_validator import fetch_and_validate, get_required_tags


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

def _ecr_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        name = detail["requestParameters"]["repositoryName"]
        return f"arn:aws:ecr:{region}:{account}:repository/{name}"
    except KeyError:
        return None

def _redshift_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        cid = detail["requestParameters"]["clusterIdentifier"]
        return f"arn:aws:redshift:{region}:{account}:cluster:{cid}"
    except KeyError:
        return None

def _stepfunctions_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["stateMachineArn"]
    except KeyError:
        return None

def _workspaces_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        wid = detail["responseElements"]["pendingRequests"][0]["workspaceId"]
        return f"arn:aws:workspaces:{region}:{account}:workspace/{wid}"
    except (KeyError, IndexError):
        return None

def _igw_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        igw_id = detail["responseElements"]["internetGateway"]["internetGatewayId"]
        return f"arn:aws:ec2:{region}:{account}:internet-gateway/{igw_id}"
    except KeyError:
        return None

def _nat_gateway_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        nat_id = detail["responseElements"]["CreateNatGatewayResponse"]["natGateway"]["natGatewayId"]
        return f"arn:aws:ec2:{region}:{account}:natgateway/{nat_id}"
    except KeyError:
        return None

def _vpc_peering_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        pcx_id = detail["responseElements"]["vpcPeeringConnection"]["vpcPeeringConnectionId"]
        return f"arn:aws:ec2:{region}:{account}:vpc-peering-connection/{pcx_id}"
    except KeyError:
        return None

def _iam_role_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["role"]["arn"]
    except KeyError:
        return None

def _iam_user_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        return detail["responseElements"]["user"]["arn"]
    except KeyError:
        return None

def _apigateway_rest_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        api_id = detail["responseElements"]["id"]
        return f"arn:aws:apigateway:{region}::/restapis/{api_id}"
    except KeyError:
        return None


# HTTP API (CreateApi / API Gateway v2) の ARN 抽出は未実装
# isolator/restorer が apigatewayv2 クライアントに対応次第追加予定
# ロードマップ: HTTP API（API Gateway v2）対応


def _vpc_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        vpc_id = detail["responseElements"]["vpc"]["vpcId"]
        return f"arn:aws:ec2:{region}:{account}:vpc/{vpc_id}"
    except KeyError:
        return None

def _eip_arn(detail: dict, region: str, account: str) -> Optional[str]:
    try:
        alloc_id = detail["responseElements"]["allocationId"]
        return f"arn:aws:ec2:{region}:{account}:elastic-ip/{alloc_id}"
    except KeyError:
        return None


def _secretsmanager_arn(detail: dict, region: str, account: str) -> Optional[str]:
    # SM の ARN は名前から組み立て不可（末尾ランダム6文字サフィックス）のため
    # responseElements の ARN を直読み。フィールド名の大小は実機未確定のため両対応。
    resp = detail.get("responseElements") or {}
    return resp.get("arn") or resp.get("ARN")


def _cloudfront_arn(detail: dict, region: str, account: str) -> Optional[str]:
    # CloudFront はグローバルサービス（us-east-1 転送経由・ARN はリージョンレス）。
    # responseElements の構造は実機未確定のため二段構え:
    # ① distribution 配下の ARN 直読み ② id から組み立て。
    resp = detail.get("responseElements") or {}
    dist = resp.get("distribution") or {}
    arn = dist.get("arn") or dist.get("ARN")
    if arn:
        return arn
    dist_id = dist.get("id") or dist.get("Id")
    if dist_id:
        return f"arn:aws:cloudfront::{account}:distribution/{dist_id}"
    return None


# eventSource → {対象 eventName → ARN抽出関数}
RESOURCE_EXTRACTORS: dict[str, dict[str, callable]] = {
    "ec2.amazonaws.com": {
        "RunInstances":              _ec2_arn,
        "CreateInternetGateway":     _igw_arn,
        "CreateNatGateway":          _nat_gateway_arn,
        "CreateVpcPeeringConnection": _vpc_peering_arn,
        "CreateVpc":                 _vpc_arn,
        "AllocateAddress":           _eip_arn,
    },
    "rds.amazonaws.com": {
        "CreateDBInstance":                _rds_arn,
        "RestoreDBInstanceFromDBSnapshot": _rds_arn,
        "RestoreDBInstanceToPointInTime":  _rds_arn,
    },
    "s3.amazonaws.com": {
        "CreateBucket": _s3_arn,
    },
    "lambda.amazonaws.com": {
        "CreateFunction20150331": _lambda_arn,
        "CreateFunction":         _lambda_arn,
    },
    "dynamodb.amazonaws.com": {
        "CreateTable":            _dynamodb_arn,
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
        "CreateDomain":              _opensearch_arn,
        "CreateElasticsearchDomain": _opensearch_arn,
    },
    "glue.amazonaws.com": {
        "CreateDatabase": _glue_arn,
    },
    "ecr.amazonaws.com": {
        "CreateRepository": _ecr_arn,
    },
    "redshift.amazonaws.com": {
        "CreateCluster":              _redshift_arn,
        "RestoreFromClusterSnapshot": _redshift_arn,
    },
    "states.amazonaws.com": {
        "CreateStateMachine": _stepfunctions_arn,
    },
    "workspaces.amazonaws.com": {
        "CreateWorkspaces": _workspaces_arn,
    },
    "iam.amazonaws.com": {
        "CreateRole": _iam_role_arn,
        "CreateUser": _iam_user_arn,
    },
    "secretsmanager.amazonaws.com": {
        "CreateSecret": _secretsmanager_arn,
    },
    "cloudfront.amazonaws.com": {
        "CreateDistribution": _cloudfront_arn,
        "CreateDistributionWithTags": _cloudfront_arn,
    },
    "apigateway.amazonaws.com": {
        "CreateRestApi": _apigateway_rest_arn,
        # 注: CreateStage/CreateDeployment は意図的に未登録（案②）。
        # detector は CreateRestApi 発火時点＝ステージ常にゼロで隔離し、
        # 7日後 delete_rest_api で無タグ撲滅。検知ギャップは許容仕様。
        # CreateApi (HTTP API / API Gateway v2) は現在未対応
        # isolator/restorer が apigatewayv2 クライアントに対応次第追加予定
        # ロードマップ: HTTP API（API Gateway v2）対応
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

    # タグチェック（共通バリデーションユーティリティ）
    missing_tags = fetch_and_validate(arn)

    if not missing_tags:
        logger.info("All required tags valid for %s", arn)
        return {"status": "ok", "arn": arn}

    logger.warning("Tag violation %s for %s", missing_tags, arn)

    # Step Functions を起動
    _start_state_machine(arn, missing_tags, get_required_tags(), event_name, detail)

    return {"status": "triggered", "arn": arn, "missing_tags": missing_tags}


# ─────────────────────────────────────────────────────────────
# Step Functions 起動
# ─────────────────────────────────────────────────────────────

def _start_state_machine(arn: str, missing_tags: list[str], required_tags: list[str], event_name: str, detail: dict):
    if not STATE_MACHINE_ARN:
        logger.error("STATE_MACHINE_ARN not set")
        return

    payload = {
        "arn":          arn,
        "missingTags":  missing_tags,
        "requiredTags": required_tags,
        "waitSeconds":  int(os.environ.get("DELETE_DELAY_SECONDS", "604800")),
        "eventName":    event_name,
        "principal":    detail.get("userIdentity", {}).get("arn", "unknown"),
        "region":       detail.get("awsRegion", DEFAULT_REGION),
    }

    sfn.start_execution(
        stateMachineArn=STATE_MACHINE_ARN,
        input=json.dumps(payload),
    )
    logger.info("Started Step Functions for ARN: %s", arn)
