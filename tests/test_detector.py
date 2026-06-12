"""
test_detector.py
────────────────
detector Lambda のユニットテスト
"""

import os
import sys
from unittest.mock import MagicMock, patch

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
        with patch("detector.index.sfn"):
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
             patch("detector.index.time"):

            mock_sfn.start_execution.return_value = {"executionArn": "arn:test"}

            event = make_cloudtrail_event(
                "s3.amazonaws.com", "CreateBucket",
                request_params={"bucketName": "my-bucket"}
            )
            result = detector.lambda_handler(event, {})
            assert result["status"] == "triggered"
            assert "Env" in result["missing_tags"]
            mock_sfn.start_execution.assert_called_once()


# ─────────────────────────────────────────────────────────────
# Secrets Manager extractor（v26 追加分）
# ─────────────────────────────────────────────────────────────

class TestDetectorSecretsManager:

    def _get_detector(self):
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)
        return detector

    def test_create_secret_lowercase_arn(self):
        """CreateSecret → responseElements の小文字 arn を直読み（実機 CloudTrail の実効経路）"""
        detector = self._get_detector()
        sm_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:tw-probe-AbC123"
        event = make_cloudtrail_event(
            "secretsmanager.amazonaws.com", "CreateSecret",
            response_elements={"arn": sm_arn, "name": "tw-probe"},
        )
        arn = detector._secretsmanager_arn(event["detail"], "ap-northeast-1", "123456789012")
        assert arn == sm_arn

    def test_create_secret_uppercase_arn(self):
        """CreateSecret → 大文字 ARN でも読める（tolerant 二段の保険側）"""
        detector = self._get_detector()
        sm_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:tw-probe-AbC123"
        event = make_cloudtrail_event(
            "secretsmanager.amazonaws.com", "CreateSecret",
            response_elements={"ARN": sm_arn},
        )
        arn = detector._secretsmanager_arn(event["detail"], "ap-northeast-1", "123456789012")
        assert arn == sm_arn

    def test_create_secret_null_response_elements(self):
        """responseElements が null でも安全に None を返す（.get() 連鎖）"""
        detector = self._get_detector()
        detail = {"responseElements": None}
        assert detector._secretsmanager_arn(detail, "ap-northeast-1", "123456789012") is None

    def test_create_secret_registered_in_extractors(self):
        """RESOURCE_EXTRACTORS に CreateSecret が登録されている（回帰）"""
        detector = self._get_detector()
        ext = detector.RESOURCE_EXTRACTORS["secretsmanager.amazonaws.com"]
        assert ext["CreateSecret"] is detector._secretsmanager_arn


# ─────────────────────────────────────────────────────────────
# CloudFront extractor（v26 追加分）
# ─────────────────────────────────────────────────────────────

class TestDetectorCloudFront:

    def _get_detector(self):
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)
        return detector

    def test_cloudfront_arn_direct_read(self):
        """distribution.arn の直読み（将来の保険段）"""
        detector = self._get_detector()
        cf_arn = "arn:aws:cloudfront::123456789012:distribution/E1TESTDIRECT"
        event = make_cloudtrail_event(
            "cloudfront.amazonaws.com", "CreateDistribution",
            response_elements={"distribution": {"arn": cf_arn, "id": "E1TESTDIRECT"}},
        )
        arn = detector._cloudfront_arn(event["detail"], "us-east-1", "123456789012")
        assert arn == cf_arn

    def test_cloudfront_arn_built_from_id_when_third_form(self):
        """実機 CloudTrail の第3形態 `aRN` では直読み二段（arn/ARN）が不発
        → id からの組み立てフォールバックが実効経路（v26 実機実証の再現）"""
        detector = self._get_detector()
        event = make_cloudtrail_event(
            "cloudfront.amazonaws.com", "CreateDistributionWithTags",
            response_elements={"distribution": {
                "aRN": "arn:aws:cloudfront::123456789012:distribution/E383RYYP0LWN8U",
                "id": "E383RYYP0LWN8U",
            }},
        )
        arn = detector._cloudfront_arn(event["detail"], "us-east-1", "123456789012")
        assert arn == "arn:aws:cloudfront::123456789012:distribution/E383RYYP0LWN8U"

    def test_cloudfront_arn_no_distribution_returns_none(self):
        """distribution 不在（空 responseElements）→ None"""
        detector = self._get_detector()
        detail = {"responseElements": None}
        assert detector._cloudfront_arn(detail, "us-east-1", "123456789012") is None

    def test_cloudfront_both_event_names_registered(self):
        """CreateDistribution / CreateDistributionWithTags の両イベント名が登録されている（回帰）"""
        detector = self._get_detector()
        ext = detector.RESOURCE_EXTRACTORS["cloudfront.amazonaws.com"]
        assert ext["CreateDistribution"] is detector._cloudfront_arn
        assert ext["CreateDistributionWithTags"] is detector._cloudfront_arn
