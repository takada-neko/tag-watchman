"""
test_detector.py
────────────────
detector Lambda のユニットテスト
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))

from conftest import make_cloudtrail_event


@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:ap-northeast-1:123456789012:stateMachine:tagwatchman-auto-delete")
    monkeypatch.setenv("AWS_REGION", "ap-northeast-1")
    monkeypatch.setenv("DELETE_DELAY_SECONDS", "604800")


class TestDetectorARNExtraction:

    def _get_detector(self):
        """STS をモックしてdetectorをインポート"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)
        return detector

    def test_ec2_run_instances(self):
        """EC2 RunInstances → ARN抽出"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event(
            "ec2.amazonaws.com", "RunInstances",
            response_elements={
                "instancesSet": {
                    "items": [{"instanceId": "i-1234567890abcdef0"}]
                }
            }
        )
        detail = event["detail"]
        arn = detector._ec2_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-1234567890abcdef0"

    def test_rds_create_db_instance(self):
        """RDS CreateDBInstance → ARN抽出"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event(
            "rds.amazonaws.com", "CreateDBInstance",
            request_params={"dBInstanceIdentifier": "my-db"}
        )
        detail = event["detail"]
        arn = detector._rds_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:rds:ap-northeast-1:123456789012:db:my-db"

    def test_s3_create_bucket(self):
        """S3 CreateBucket → ARN抽出"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event(
            "s3.amazonaws.com", "CreateBucket",
            request_params={"bucketName": "my-bucket"}
        )
        detail = event["detail"]
        arn = detector._s3_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:s3:::my-bucket"

    def test_igw_create(self):
        """IGW CreateInternetGateway → ARN抽出"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event(
            "ec2.amazonaws.com", "CreateInternetGateway",
            response_elements={
                "internetGateway": {"internetGatewayId": "igw-12345678"}
            }
        )
        detail = event["detail"]
        arn = detector._igw_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:ec2:ap-northeast-1:123456789012:internet-gateway/igw-12345678"

    def test_iam_role_create(self):
        """IAM CreateRole → ARN抽出"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event(
            "iam.amazonaws.com", "CreateRole",
            response_elements={
                "role": {"arn": "arn:aws:iam::123456789012:role/my-role"}
            }
        )
        detail = event["detail"]
        arn = detector._iam_role_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:iam::123456789012:role/my-role"

    def test_unsupported_event_skipped(self):
        """未対応イベントはスキップ"""
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)

        event = make_cloudtrail_event("unknown.amazonaws.com", "UnknownEvent")
        with patch("detector.index.sfn"), patch("detector.index.tagging"):
            result = detector.lambda_handler(event, {})
        assert result["status"] == "skipped"


class TestDetectorTagCheck:

    @mock_aws
    def test_tags_valid_no_action(self, monkeypatch):
        """タグが揃っている → Step Functions起動なし"""
        import importlib
        import detector.index as detector
        importlib.reload(detector)

        with patch("detector.index.fetch_and_validate", return_value=[]), \
             patch("detector.index.sfn") as mock_sfn, \
             patch("boto3.client") as mock_boto:

            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts

            event = make_cloudtrail_event(
                "s3.amazonaws.com", "CreateBucket",
                request_params={"bucketName": "my-bucket"}
            )
            result = detector.lambda_handler(event, {})
            assert result["status"] == "ok"
            mock_sfn.start_execution.assert_not_called()

    @mock_aws
    def test_tags_missing_triggers_sfn(self, monkeypatch):
        """タグ不足 → Step Functions起動"""
        import importlib
        import detector.index as detector
        importlib.reload(detector)

        with patch("detector.index.fetch_and_validate", return_value=["Env", "Owned"]), \
             patch("detector.index.get_required_tags", return_value=["Env", "Project", "Owned"]), \
             patch("detector.index.sfn") as mock_sfn, \
             patch("detector.index.time") as mock_time:

            mock_sfn.start_execution.return_value = {"executionArn": "arn:test"}

            event = make_cloudtrail_event(
                "s3.amazonaws.com", "CreateBucket",
                request_params={"bucketName": "my-bucket"}
            )
            result = detector.lambda_handler(event, {})
            assert result["status"] == "triggered"
            assert "Env" in result["missing_tags"]
            mock_sfn.start_execution.assert_called_once()
