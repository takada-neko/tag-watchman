"""
conftest.py
───────────
全テスト共通のフィクスチャ
"""

import os
import sys

import boto3
import pytest
from moto import mock_aws

# Lambda のパスを通す
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))
# tag_validator のフラット import 対応（Lambda 実行時は index.py と同階層に配置されるため、
# detector 側を正として通す。recheck 側は two-location 同一内容のため共有で問題なし）
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda/detector"))

# AWS 認証情報のダミー設定（moto用）
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

# TagWatchman 環境変数
os.environ.setdefault("REQUIRED_TAGS", "Env,Project,Owned")
os.environ.setdefault("SSM_PREFIX", "/tagwatchman")
os.environ.setdefault("DRY_RUN", "false")
os.environ.setdefault("DELETE_DELAY_SECONDS", "604800")


@pytest.fixture
def aws_region():
    return "ap-northeast-1"


@pytest.fixture
def account_id():
    return "123456789012"


@pytest.fixture
def sns_topic_arn(aws_region, account_id):
    return f"arn:aws:sns:{aws_region}:{account_id}:tagwatchman-alert"


@pytest.fixture
def quarantine_sg_id():
    return "sg-quarantine123"


# ─────────────────────────────────────────────────────────────
# SSM パラメータのセットアップ
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def setup_ssm(aws_region):
    """SSM Parameter Store にテスト用パラメータを設定"""
    with mock_aws():
        ssm = boto3.client("ssm", region_name=aws_region)
        ssm.put_parameter(
            Name="/tagwatchman/required-tags",
            Value="Env,Project,Owned",
            Type="String",
            Overwrite=True,
        )
        ssm.put_parameter(
            Name="/tagwatchman/tag-allowed-values",
            Value="Env:prod|stg|test,Project:my-project",
            Type="String",
            Overwrite=True,
        )
        ssm.put_parameter(
            Name="/tagwatchman/tag-match-mode",
            Value="Env:exact,Project:prefix",
            Type="String",
            Overwrite=True,
        )
        yield ssm


# ─────────────────────────────────────────────────────────────
# CloudTrail イベントのファクトリ
# ─────────────────────────────────────────────────────────────

def make_cloudtrail_event(event_source: str, event_name: str, request_params: dict = None, response_elements: dict = None, region: str = "ap-northeast-1") -> dict:
    return {
        "detail": {
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": region,
            "eventTime": "2025-01-01T00:00:00Z",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "type": "IAMUser",
            },
            "requestParameters": request_params or {},
            "responseElements": response_elements or {},
        }
    }
