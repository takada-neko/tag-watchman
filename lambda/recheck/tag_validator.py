"""
tag_validator.py
────────────────
detector / recheck から共通で使うタグバリデーションユーティリティ。
 
バリデーションルール:
  Env     → 完全一致（許可値リストと照合）
  Project → 前方一致（許可値のいずれかで始まればOK）
  Owned   → 空文字のみNG（値は自由）
 
設定はSSM Parameter Storeから取得:
  /tagwatchman/required-tags      = Env,Project,Owned
  /tagwatchman/tag-allowed-values = Env:prod|stg|test,Project:my-project
  /tagwatchman/tag-match-mode     = Env:exact,Project:prefix
"""
 
import logging
import os
from functools import lru_cache
 
import boto3
from botocore.exceptions import ClientError
 
logger = logging.getLogger()
 
ssm = boto3.client("ssm")
 
SSM_PREFIX = os.environ.get("SSM_PREFIX", "/tagwatchman")
 
 
# ─────────────────────────────────────────────────────────────
# SSMからの設定取得（キャッシュあり）
# ─────────────────────────────────────────────────────────────
 
# maxsize は同時にキャッシュする SSM キー数に合わせる。
# _get_ssm_value は required-tags / tag-allowed-values / tag-match-mode の
# 3キーで呼ばれるため、maxsize=1 だと validate_tags 内で互いに追い出し合い
# キャッシュが効かない。3キー + 余裕で 8 とする。
@lru_cache(maxsize=8)
def _get_ssm_value(name: str) -> str:
    try:
        resp = ssm.get_parameter(Name=f"{SSM_PREFIX}/{name}")
        return resp["Parameter"]["Value"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ParameterNotFound":
            return ""
        raise
 
 
def get_required_tags() -> list[str]:
    """必須タグキーのリスト"""
    val = _get_ssm_value("required-tags") or os.environ.get("REQUIRED_TAGS", "Env,Project,Owned")
    return [t.strip() for t in val.split(",") if t.strip()]
 
 
def get_allowed_values() -> dict[str, list[str]]:
    """
    タグキー → 許可値リスト
    例: "Env:prod|stg|test,Project:my-project"
        → {"Env": ["prod", "stg", "test"], "Project": ["my-project"]}
    """
    val = _get_ssm_value("tag-allowed-values")
    if not val:
        return {}
 
    result = {}
    for item in val.split(","):
        if ":" not in item:
            continue
        key, values = item.split(":", 1)
        result[key.strip()] = [v.strip() for v in values.split("|") if v.strip()]
    return result
 
 
def get_match_modes() -> dict[str, str]:
    """
    タグキー → マッチモード（exact / prefix）
    例: "Env:exact,Project:prefix"
        → {"Env": "exact", "Project": "prefix"}
    デフォルト: exact
    """
    val = _get_ssm_value("tag-match-mode")
    if not val:
        return {}
 
    result = {}
    for item in val.split(","):
        if ":" not in item:
            continue
        key, mode = item.split(":", 1)
        result[key.strip()] = mode.strip()
    return result
 
 
# ─────────────────────────────────────────────────────────────
# タグバリデーション
# ─────────────────────────────────────────────────────────────
 
def validate_tags(resource_tags: dict[str, str]) -> list[str]:
    """
    リソースのタグを検証し、違反しているタグキーのリストを返す。
    全て正常なら空リストを返す。
 
    Args:
        resource_tags: リソースに付与されているタグ {key: value}
 
    Returns:
        違反タグキーのリスト（空なら問題なし）
    """
    required_tags  = get_required_tags()
    allowed_values = get_allowed_values()
    match_modes    = get_match_modes()
 
    violations = []
 
    for tag_key in required_tags:
        # tagwatchman:* タグは判定から除外
        if tag_key.startswith("tagwatchman:"):
            continue
 
        value = resource_tags.get(tag_key, "")
 
        # ① キーが存在しない or 空文字
        if not value:
            logger.warning("Tag '%s' is missing or empty", tag_key)
            violations.append(tag_key)
            continue
 
        # ② 許可値が定義されていない場合は空文字チェックのみ（Ownedなど）
        if tag_key not in allowed_values:
            continue
 
        # ③ 許可値チェック
        allowed = allowed_values[tag_key]
        mode    = match_modes.get(tag_key, "exact")
 
        if mode == "prefix":
            # 前方一致: 許可値のいずれかで始まればOK
            if not any(value.startswith(a) for a in allowed):
                logger.warning(
                    "Tag '%s' value '%s' does not start with any of %s",
                    tag_key, value, allowed,
                )
                violations.append(tag_key)
        else:
            # 完全一致（デフォルト）
            if value not in allowed:
                logger.warning(
                    "Tag '%s' value '%s' not in allowed values %s",
                    tag_key, value, allowed,
                )
                violations.append(tag_key)
 
    return violations
 

def _fetch_iam_tags(arn: str) -> dict[str, str]:
    """
    IAM Role/User のタグをネイティブ API で取得する。
    Resource Groups Tagging API は IAM を非サポートのため
    （どのリージョンでも常に空応答）、RGT 経由では読めない。
    IAM はグローバルサービスなのでリージョン指定は不要。
    """
    iam = boto3.client("iam")
    name = arn.rsplit("/", 1)[-1]  # path 付き（role/service-role/xxx 等）でも名前部のみ
    if ":role/" in arn:
        resp = iam.list_role_tags(RoleName=name)
    else:
        resp = iam.list_user_tags(UserName=name)
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}


def _fetch_cloudfront_tags(arn: str) -> dict[str, str]:
    """
    CloudFront distribution のタグをネイティブ API で取得する。
    CloudFront はグローバルサービスで、RGT の ap-northeast-1
    クライアントでは読めない（IAM と同型のカバレッジ穴対策）。
    list_tags_for_resource の応答は Tags.Items 配下（IAM と構造が異なる）。
    """
    cf = boto3.client("cloudfront")
    resp = cf.list_tags_for_resource(Resource=arn)
    items = (resp.get("Tags") or {}).get("Items") or []
    return {t["Key"]: t["Value"] for t in items}


def fetch_and_validate(arn: str) -> list[str]:
    """
    ARNのタグを取得し、バリデーションする。
    IAM Role/User は RGT 非サポートのためネイティブ API、
    それ以外は Resource Groups Tagging API で読む。

    Returns:
        違反タグキーのリスト（空なら問題なし）
    """
    # IAM は RGT 非対応 → ネイティブ API 分岐（false positive 恒久対策）
    if ":iam:" in arn and (":role/" in arn or ":user/" in arn):
        try:
            return validate_tags(_fetch_iam_tags(arn))
        except Exception as e:
            logger.error("IAM tag fetch error for %s: %s", arn, e)
            return get_required_tags()  # 読めない場合は従来どおり欠落扱い

    # CloudFront はグローバルサービス → ネイティブ API 分岐（IAM と同型の対策）
    if ":cloudfront:" in arn and ":distribution/" in arn:
        try:
            return validate_tags(_fetch_cloudfront_tags(arn))
        except Exception as e:
            logger.error("CloudFront tag fetch error for %s: %s", arn, e)
            return get_required_tags()  # 読めない場合は欠落扱い（E のため実害は誤メールまで）
    tagging = boto3.client("resourcegroupstaggingapi")

    try:
        resp      = tagging.get_resources(ResourceARNList=[arn])
        resources = resp.get("ResourceTagMappingList", [])

        if not resources:
            logger.warning("No tag data for ARN: %s — treating as untagged", arn)
            return get_required_tags()

        resource_tags = {t["Key"]: t["Value"] for t in resources[0].get("Tags", [])}
        return validate_tags(resource_tags)

    except Exception as e:
        logger.error("Tag fetch error for %s: %s", arn, e)
        return get_required_tags()  # 安全側に倒す
