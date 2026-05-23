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

@lru_cache(maxsize=1)
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


def fetch_and_validate(arn: str) -> list[str]:
    """
    Resource Groups Tagging API でARNのタグを取得し、バリデーションする。

    Returns:
        違反タグキーのリスト（空なら問題なし）
    """
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
