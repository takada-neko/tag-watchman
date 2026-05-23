"""
test_notifier.py
test_recheck.py
test_restorer.py
test_approver.py
test_deleter.py
test_cloudtrail_guardian.py
を1ファイルにまとめたテスト
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))


# ─────────────────────────────────────────────────────────────
# Notifier テスト
# ─────────────────────────────────────────────────────────────

class TestNotifier:

    BASE_EVENT = {
        "arn": "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-123",
        "missingTags": ["Env"],
        "requiredTags": ["Env", "Project", "Owned"],
        "region": "ap-northeast-1",
        "eventName": "RunInstances",
        "principal": "arn:aws:iam::123456789012:user/test",
    }

    @mock_aws
    def test_detection_mail_sent(self, monkeypatch):
        """検知メール①が送信される"""
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:test-topic")
        monkeypatch.setenv("DELETE_DELAY_SECONDS", "604800")

        import importlib
        import notifier.index as notifier
        importlib.reload(notifier)

        sns = boto3.client("sns", region_name="ap-northeast-1")
        sns.create_topic(Name="test-topic")

        with patch("notifier.index.sns") as mock_sns:
            event = {**self.BASE_EVENT, "mailType": "detection"}
            result = notifier.lambda_handler(event, {})
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            assert "TagWatchman" in call_kwargs["Subject"]
            assert "検知・隔離" in call_kwargs["Subject"]

    @mock_aws
    def test_approval_mail_sent(self, monkeypatch):
        """承認メール②が送信される"""
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:test-topic")
        monkeypatch.setenv("APPROVAL_BASE_URL", "https://example.com")

        import importlib
        import notifier.index as notifier
        importlib.reload(notifier)

        with patch("notifier.index.sns") as mock_sns:
            event = {**self.BASE_EVENT, "mailType": "approval", "executionId": "exec-123"}
            result = notifier.lambda_handler(event, {})
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            assert "削除承認依頼" in call_kwargs["Subject"]
            assert "exec-123" in call_kwargs["Message"]

    def test_iam_detection_mail_has_manual_note(self, monkeypatch):
        """IAMリソースの検知メールに手動対応の案内が含まれる"""
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:test-topic")

        import importlib
        import notifier.index as notifier
        importlib.reload(notifier)

        with patch("notifier.index.sns") as mock_sns:
            event = {
                **self.BASE_EVENT,
                "arn": "arn:aws:iam::123456789012:role/my-role",
                "mailType": "detection",
            }
            notifier.lambda_handler(event, {})
            message = mock_sns.publish.call_args[1]["Message"]
            assert "人間による対応が必要" in message

    def test_no_sns_topic_skips(self, monkeypatch):
        """SNS_TOPIC_ARN未設定の場合はスキップ"""
        monkeypatch.setenv("SNS_TOPIC_ARN", "")

        import importlib
        import notifier.index as notifier
        importlib.reload(notifier)

        with patch("notifier.index.sns") as mock_sns:
            event = {**self.BASE_EVENT, "mailType": "detection"}
            notifier.lambda_handler(event, {})
            mock_sns.publish.assert_not_called()


# ─────────────────────────────────────────────────────────────
# Recheck テスト
# ─────────────────────────────────────────────────────────────

class TestRecheck:

    BASE_EVENT = {
        "arn": "arn:aws:s3:::my-bucket",
        "missingTags": ["Env"],
        "requiredTags": ["Env", "Project", "Owned"],
        "region": "ap-northeast-1",
    }

    def test_tags_still_missing(self, monkeypatch):
        """タグがまだ不足 → stillMissingTags=True"""
        monkeypatch.setenv("RESTORER_FUNCTION_ARN", "")

        import importlib
        import recheck.index as recheck
        importlib.reload(recheck)

        with patch("recheck.index.fetch_and_validate", return_value=["Env"]):
            result = recheck.lambda_handler(self.BASE_EVENT, {})
            assert result["stillMissingTags"] is True
            assert "Env" in result["missingTags"]

    def test_tags_now_valid_invokes_restorer(self, monkeypatch):
        """タグが揃った → Restorer呼び出し"""
        monkeypatch.setenv("RESTORER_FUNCTION_ARN", "arn:aws:lambda:ap-northeast-1:123456789012:function:restorer")

        import importlib
        import recheck.index as recheck
        importlib.reload(recheck)

        with patch("recheck.index.fetch_and_validate", return_value=[]), \
             patch("recheck.index._lambda") as mock_lambda:
            result = recheck.lambda_handler(self.BASE_EVENT, {})
            assert result["stillMissingTags"] is False
            mock_lambda.invoke.assert_called_once()


# ─────────────────────────────────────────────────────────────
# Restorer テスト
# ─────────────────────────────────────────────────────────────

class TestRestorer:

    @mock_aws
    def test_s3_restore(self, monkeypatch):
        """S3 復旧 → バケットポリシーを削除"""
        monkeypatch.setenv("DRY_RUN", "false")

        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)

        s3 = boto3.client("s3", region_name="ap-northeast-1")
        s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"},
        )
        s3.put_bucket_policy(Bucket="test-bucket", Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "TagWatchmanQuarantine",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::test-bucket",
                    "arn:aws:s3:::test-bucket/*",
                ],
            }]
        }))
        s3.put_bucket_tagging(Bucket="test-bucket", Tagging={
            "TagSet": [
                {"Key": "tagwatchman:quarantined", "Value": "true"},
                {"Key": "tagwatchman:had-bucket-policy", "Value": "False"},
            ]
        })

        event = {"arn": "arn:aws:s3:::test-bucket", "region": "ap-northeast-1"}
        result = restorer.lambda_handler(event, {})
        assert result["restoreStatus"] == "restored"

        # ポリシーが削除されているか確認
        with pytest.raises(Exception, match="NoSuchBucketPolicy|AccessDenied"):
            s3.get_bucket_policy(Bucket="test-bucket")

    def test_dry_run_skips_restore(self, monkeypatch):
        """DRY_RUN=true の場合は復旧しない"""
        monkeypatch.setenv("DRY_RUN", "true")

        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)

        event = {
            "arn": "arn:aws:s3:::test-bucket",
            "region": "ap-northeast-1",
        }
        result = restorer.lambda_handler(event, {})
        assert result["restoreStatus"] == "dry_run"


# ─────────────────────────────────────────────────────────────
# Approver テスト
# ─────────────────────────────────────────────────────────────

class TestApprover:

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("DELETER_FUNCTION_ARN", "arn:aws:lambda:ap-northeast-1:123456789012:function:deleter")
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:ap-northeast-1:123456789012:stateMachine:tagwatchman")

    def test_missing_token_returns_400(self):
        """トークンなし → 400"""
        import importlib
        import approver.index as approver
        importlib.reload(approver)

        event = {"queryStringParameters": {}}
        result = approver.lambda_handler(event, {})
        assert result["statusCode"] == 400

    def test_invalid_token_returns_410(self):
        """無効なトークン → 410"""
        import importlib
        import approver.index as approver
        importlib.reload(approver)

        with patch("approver.index._validate_token", return_value=(False, {})):
            event = {"queryStringParameters": {"token": "invalid", "arn": "arn:aws:s3:::test"}}
            result = approver.lambda_handler(event, {})
            assert result["statusCode"] == 410

    def test_valid_token_triggers_deletion(self):
        """有効なトークン → 削除実行・200"""
        import importlib
        import approver.index as approver
        importlib.reload(approver)

        execution_input = {
            "arn": "arn:aws:s3:::test-bucket",
            "missingTags": ["Env"],
        }
        with patch("approver.index._validate_token", return_value=(True, execution_input)), \
             patch("approver.index._invoke_deleter") as mock_deleter:
            event = {
                "queryStringParameters": {
                    "token": "valid-token",
                    "arn": "arn:aws:s3:::test-bucket",
                }
            }
            result = approver.lambda_handler(event, {})
            assert result["statusCode"] == 200
            mock_deleter.assert_called_once()

    def test_arn_mismatch_returns_400(self):
        """ARNが一致しない → 400"""
        import importlib
        import approver.index as approver
        importlib.reload(approver)

        execution_input = {"arn": "arn:aws:s3:::different-bucket"}
        with patch("approver.index._validate_token", return_value=(True, execution_input)):
            event = {
                "queryStringParameters": {
                    "token": "valid-token",
                    "arn": "arn:aws:s3:::test-bucket",  # 異なるARN
                }
            }
            result = approver.lambda_handler(event, {})
            assert result["statusCode"] == 400


# ─────────────────────────────────────────────────────────────
# Deleter テスト
# ─────────────────────────────────────────────────────────────

class TestDeleter:

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "false")

    @mock_aws
    def test_s3_bucket_deleted(self):
        """S3バケット削除"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        s3 = boto3.client("s3", region_name="ap-northeast-1")
        s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"},
        )

        event = {
            "arn": "arn:aws:s3:::test-bucket",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "deleted"

        buckets = s3.list_buckets()["Buckets"]
        assert not any(b["Name"] == "test-bucket" for b in buckets)

    @mock_aws
    def test_ec2_instance_terminated(self):
        """EC2インスタンス削除"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        instance = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = instance["Instances"][0]["InstanceId"]

        event = {
            "arn": f"arn:aws:ec2:ap-northeast-1:123456789012:instance/{instance_id}",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "deleted"

    def test_dry_run_no_deletion(self, monkeypatch):
        """DRY_RUN=true → 削除しない"""
        monkeypatch.setenv("DRY_RUN", "true")

        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        event = {
            "arn": "arn:aws:s3:::test-bucket",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "dry_run"

    def test_unknown_arn_returns_error(self):
        """未対応ARN → error"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        event = {
            "arn": "arn:aws:unknown:ap-northeast-1:123456789012:resource/test",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "error"


# ─────────────────────────────────────────────────────────────
# CloudTrail Guardian テスト
# ─────────────────────────────────────────────────────────────

class TestCloudTrailGuardian:

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:test-topic")

    def _get_guardian(self):
        import importlib
        import importlib.util
        guardian_path = os.path.join(os.path.dirname(__file__), "../lambda/cloudtrail-guardian/index.py")
        spec = importlib.util.spec_from_file_location("cloudtrail_guardian_index", guardian_path)
        guardian = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guardian)
        return guardian

    def _make_cloudtrail_event(self, event_name, trail_name="my-trail"):
        return {
            "detail": {
                "eventName": event_name,
                "eventTime": "2025-01-01T00:00:00Z",
                "awsRegion": "ap-northeast-1",
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
                "requestParameters": {"name": trail_name},
            }
        }

    def test_stop_logging_reenables(self):
        """StopLogging → 自動再有効化"""
        guardian = self._get_guardian()
        with patch.object(guardian, "cloudtrail") as mock_ct, \
             patch.object(guardian, "sns") as mock_sns:
            mock_ct.start_logging.return_value = {}
            event = self._make_cloudtrail_event("StopLogging")
            result = guardian.lambda_handler(event, {})
            assert result["status"] == "handled"
            assert result["re_enabled"] is True
            mock_ct.start_logging.assert_called_once_with(Name="my-trail")
            mock_sns.publish.assert_called_once()
            assert "CRITICAL" in mock_sns.publish.call_args[1]["Subject"]

    def test_delete_trail_sends_critical(self):
        """DeleteTrail → CRITICAL警告"""
        guardian = self._get_guardian()
        with patch.object(guardian, "cloudtrail"), \
             patch.object(guardian, "sns") as mock_sns:
            event = self._make_cloudtrail_event("DeleteTrail")
            result = guardian.lambda_handler(event, {})
            assert result["status"] == "handled"
            assert "CRITICAL" in mock_sns.publish.call_args[1]["Subject"]

    def test_update_trail_sends_warning(self):
        """UpdateTrail → WARNING警告"""
        guardian = self._get_guardian()
        with patch.object(guardian, "cloudtrail"), \
             patch.object(guardian, "sns") as mock_sns:
            event = self._make_cloudtrail_event("UpdateTrail")
            result = guardian.lambda_handler(event, {})
            assert result["status"] == "handled"
            assert "WARNING" in mock_sns.publish.call_args[1]["Subject"]

    def test_unknown_event_skipped(self):
        """未対応イベント → スキップ"""
        guardian = self._get_guardian()
        event = self._make_cloudtrail_event("UnknownEvent")
        result = guardian.lambda_handler(event, {})
        assert result["status"] == "skipped"
