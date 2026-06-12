"""
test_notifier.py
test_recheck.py
test_restorer.py
test_approver.py
test_deleter.py
test_cloudtrail_guardian.py
test_detector.py (API Gateway追加分)
を1ファイルにまとめたテスト
"""
 
import json
import base64
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
            notifier.lambda_handler(event, {})
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            assert "TagWatchman" in call_kwargs["Subject"]
            assert "Resource quarantined" in call_kwargs["Subject"]
 
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
            notifier.lambda_handler(event, {})
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            assert "Deletion approval required" in call_kwargs["Subject"]
            assert "exec-123" in call_kwargs["Message"]

    def test_approval_mail_wording_matches_url_validity(self, monkeypatch):
        """承認メール文言が実装（RUNNING中は再利用可）と整合している（v28・発見③）"""
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:test-topic")
        monkeypatch.setenv("APPROVAL_BASE_URL", "https://example.com")

        import importlib
        import notifier.index as notifier
        importlib.reload(notifier)

        with patch("notifier.index.sns") as mock_sns:
            event = {**self.BASE_EVENT, "mailType": "approval", "executionId": "exec-123"}
            notifier.lambda_handler(event, {})
            message = mock_sns.publish.call_args[1]["Message"]
            assert "最大30日間" in message
            assert "削除は一度しか実行されません" in message
            assert "AWSコンソール" in message
            assert "1回限り" not in message  # 旧文言（実装と不一致）が復活していないこと
 
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
 
    def test_apigateway_restore(self, monkeypatch):
        """API Gateway 復旧 → ステージ再作成"""
        monkeypatch.setenv("DRY_RUN", "false")
 
        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)
 
        arn = "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
        stage_info = json.dumps([
            {
                "stageName": "prod",
                "deploymentId": "dep-123",
                "variables": {"key": "value"},
                "description": "production stage",
            }
        ])
 
        mock_apigw = MagicMock()
        mock_apigw.get_tags.return_value = {
            "tags": {
                "tagwatchman:quarantined": "true",
                "tagwatchman:original-stages": base64.b64encode(stage_info.encode("utf-8")).decode("ascii"),
            }
        }
 
        with patch("boto3.client", return_value=mock_apigw):
            event = {"arn": arn, "region": "ap-northeast-1"}
            result = restorer.lambda_handler(event, {})
 
        assert result["restoreStatus"] == "restored"
 
        # ステージが再作成されたか確認
        mock_apigw.create_stage.assert_called_once_with(
            restApiId="abc123def",
            stageName="prod",
            deploymentId="dep-123",
            variables={"key": "value"},
            description="production stage",
        )
 
        # tagwatchman タグが削除されたか確認
        mock_apigw.untag_resource.assert_called_once()
        untag_keys = mock_apigw.untag_resource.call_args[1]["tagKeys"]
        assert "tagwatchman:quarantined" in untag_keys
        assert "tagwatchman:original-stages" in untag_keys
 
    def test_apigateway_restore_no_stages(self, monkeypatch):
        """API Gateway 復旧 → ステージなし・正常終了"""
        monkeypatch.setenv("DRY_RUN", "false")
 
        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)
 
        arn = "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
 
        mock_apigw = MagicMock()
        mock_apigw.get_tags.return_value = {
            "tags": {
                "tagwatchman:quarantined": "true",
                "tagwatchman:original-stages": base64.b64encode(b"[]").decode("ascii"),  # "W10="
            }
        }
 
        with patch("boto3.client", return_value=mock_apigw):
            event = {"arn": arn, "region": "ap-northeast-1"}
            result = restorer.lambda_handler(event, {})
 
        assert result["restoreStatus"] == "restored"
        mock_apigw.create_stage.assert_not_called()
 
 
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
 
    def test_apigateway_deleted(self):
        """API Gateway 削除"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)
 
        arn = "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
        mock_apigw = MagicMock()
 
        with patch("boto3.client", return_value=mock_apigw):
            event = {"arn": arn, "region": "ap-northeast-1"}
            result = deleter.lambda_handler(event, {})
 
        assert result["deleteStatus"] == "deleted"
        mock_apigw.delete_rest_api.assert_called_once_with(restApiId="abc123def")


    def test_vpc_skipped_not_deleted(self):
        """VPC（パターンE）→ 削除されず delete_failed（raise せず非同期リトライを防ぐ・v28）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        event = {
            "arn": "arn:aws:ec2:ap-northeast-1:123456789012:vpc/vpc-123",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "delete_failed"
        assert "manual deletion" in result["deleteReason"]

    def test_glue_skipped_not_deleted(self):
        """Glue（パターンE）→ 削除されず delete_failed（v28）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        event = {
            "arn": "arn:aws:glue:ap-northeast-1:123456789012:database/my-database",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "delete_failed"
        assert "notification-only" in result["deleteReason"]

    def test_workspaces_skipped_not_deleted(self):
        """Workspaces（パターンE）→ 削除されず delete_failed（v28）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        event = {
            "arn": "arn:aws:workspaces:ap-northeast-1:123456789012:workspace/ws-abc123def",
            "region": "ap-northeast-1",
        }
        result = deleter.lambda_handler(event, {})
        assert result["deleteStatus"] == "delete_failed"
        assert "notification-only" in result["deleteReason"]


    def test_iam_role_self_protected_not_deleted(self, monkeypatch):
        """自スタックの IAM ロール → 削除されず self_protected を返す（剥奪APIも呼ばない）"""
        monkeypatch.setenv("SELF_PROTECT_PREFIX", "tagwatchman-")
        monkeypatch.setenv("OPERATOR_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-operator")
        monkeypatch.setenv("LAMBDA_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_iam = MagicMock()
        with patch("boto3.client", return_value=mock_iam):
            event = {
                "arn": "arn:aws:iam::123456789012:role/tagwatchman-lambda-role",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "self_protected"
        mock_iam.delete_role.assert_not_called()
        mock_iam.detach_role_policy.assert_not_called()

    def test_iam_user_self_protected_not_deleted(self, monkeypatch):
        """自スタック prefix の IAM ユーザ → self_protected"""
        monkeypatch.setenv("SELF_PROTECT_PREFIX", "tagwatchman-")
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_iam = MagicMock()
        with patch("boto3.client", return_value=mock_iam):
            event = {
                "arn": "arn:aws:iam::123456789012:user/tagwatchman-someuser",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "self_protected"
        mock_iam.delete_user.assert_not_called()

    def test_iam_role_non_self_proceeds_to_delete(self, monkeypatch):
        """非 self の顧客ロール → ガードを素通りして通常削除（deleted）"""
        monkeypatch.setenv("SELF_PROTECT_PREFIX", "tagwatchman-")
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_iam = MagicMock()
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        with patch("boto3.client", return_value=mock_iam):
            event = {
                "arn": "arn:aws:iam::123456789012:role/some-customer-role",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "deleted"
        mock_iam.delete_role.assert_called_once()


# ─────────────────────────────────────────────────────────────
# Deleter v28 回帰: NotFound 包括判定（発見①）
# 列挙方式は SQS のプロトコル世代差（NonExistentQueue / QueueDoesNotExist）で
# 破られるため、不存在系キーワード4語（NotFound / NoSuch / NonExistent /
# DoesNotExist）の包括判定に移行。doc 調査済みの全コードがヒットすることを守る。
# ─────────────────────────────────────────────────────────────

class TestDeleterAlreadyGone:

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)

    @pytest.mark.parametrize("code", [
        "AWS.SimpleQueueService.NonExistentQueue",  # SQS（query プロトコル・2026-06-12 実機）
        "QueueDoesNotExist",                        # SQS（json プロトコル世代）
        "NotFound",                                 # SNS delete_topic
        "RepositoryNotFoundException",              # ECR
        "ClusterNotFound",                          # Redshift（ECS と違い Exception なし）
        "ServiceNotFoundException",                 # ECS delete_service
        "NotFoundException",                        # API Gateway
        "NatGatewayNotFound",                       # EC2 NAT
        "InvalidInternetGatewayID.NotFound",        # EC2 IGW
        "InvalidVpcPeeringConnectionID.NotFound",   # EC2 Peering
        "InvalidAllocationID.NotFound",             # EC2 EIP
        "NoSuchEntity",                             # IAM
        "InvalidInstanceID.NotFound",               # EC2 instance（旧列挙からの互換）
        "DBInstanceNotFound",                       # RDS（旧列挙からの互換）
        "NoSuchBucket",                             # S3（旧列挙からの互換）
        "ResourceNotFoundException",                # Lambda/DDB/EKS/ES（旧列挙からの互換）
        "ClusterNotFoundException",                 # ECS cluster（旧列挙からの互換）
    ])
    def test_not_found_codes_return_already_deleted(self, code):
        """不存在系コードは already_deleted（正常扱い・メールなし・raise なし）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.get_queue_url.side_effect = ClientError(
            {"Error": {"Code": code, "Message": "gone"}}, "GetQueueUrl"
        )
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:sqs:ap-northeast-1:123456789012:gone-queue",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "already_deleted"
        mock_client.publish.assert_not_called()

    def test_non_notfound_client_error_is_delete_failed(self):
        """不存在系でない ClientError（AccessDenied 等）は delete_failed"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.get_queue_url.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetQueueUrl"
        )
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:sqs:ap-northeast-1:123456789012:locked-queue",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "delete_failed"
        assert "AccessDenied" in result["deleteReason"]


# ─────────────────────────────────────────────────────────────
# Deleter v28 回帰: 結果メール（発見⑤）
# deleter は approver からの非同期 invoke のみ＝raise しても利用者に届かない。
# 成功/失敗とも結果メールを SNS publish し、失敗時は raise せず return する
# （再試行は承認URL再クリックに委ねる＝発見②の仕様を活かす設計）。
# ─────────────────────────────────────────────────────────────

class TestDeleterResultMail:

    TOPIC = "arn:aws:sns:ap-northeast-1:123456789012:test-topic"

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.setenv("SNS_TOPIC_ARN", self.TOPIC)

    def test_success_sends_completion_mail(self):
        """削除成功 → deleted ＋ 完了メール（ASCII Subject）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_client = MagicMock()
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "deleted"
        mock_client.delete_rest_api.assert_called_once_with(restApiId="abc123def")
        mock_client.publish.assert_called_once()
        kwargs = mock_client.publish.call_args[1]
        assert kwargs["TopicArn"] == self.TOPIC
        assert "Deletion completed" in kwargs["Subject"]
        assert kwargs["Subject"].isascii()
        assert "削除が完了しました" in kwargs["Message"]

    def test_failure_sends_failure_mail_and_does_not_raise(self):
        """削除失敗 → delete_failed ＋ 失敗メール（再クリック案内入り）・raise しない"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.delete_rest_api.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "throttled"}},
            "DeleteRestApi",
        )
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "delete_failed"
        mock_client.publish.assert_called_once()
        kwargs = mock_client.publish.call_args[1]
        assert "Deletion FAILED" in kwargs["Subject"]
        assert kwargs["Subject"].isascii()
        assert "削除に失敗しました" in kwargs["Message"]
        assert "再度クリック" in kwargs["Message"]
        assert "AWSコンソール" in kwargs["Message"]

    def test_pattern_e_failure_also_sends_mail(self):
        """パターンE skip（RuntimeError 経路）も失敗メールが飛ぶ"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_client = MagicMock()
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:glue:ap-northeast-1:123456789012:database/my-database",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "delete_failed"
        mock_client.publish.assert_called_once()
        assert "Deletion FAILED" in mock_client.publish.call_args[1]["Subject"]

    def test_no_topic_skips_mail_but_deletes(self, monkeypatch):
        """SNS_TOPIC_ARN 未設定 → メールはスキップ・削除自体は成功"""
        monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_client = MagicMock()
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "deleted"
        mock_client.publish.assert_not_called()

    def test_mail_publish_failure_does_not_change_result(self):
        """結果メール送信が失敗しても deleteStatus は変わらない（ベストエフォート）"""
        import importlib
        import deleter.index as deleter
        importlib.reload(deleter)

        mock_client = MagicMock()
        mock_client.publish.side_effect = Exception("sns down")
        with patch("boto3.client", return_value=mock_client):
            event = {
                "arn": "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def",
                "region": "ap-northeast-1",
            }
            result = deleter.lambda_handler(event, {})

        assert result["deleteStatus"] == "deleted"
 
 
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
 
    def test_put_event_selectors_sends_warning(self):
        """PutEventSelectors → WARNING警告"""
        guardian = self._get_guardian()
        with patch.object(guardian, "cloudtrail"), \
             patch.object(guardian, "sns") as mock_sns:
            event = self._make_cloudtrail_event("PutEventSelectors")
            result = guardian.lambda_handler(event, {})
            assert result["status"] == "handled"
            assert "WARNING" in mock_sns.publish.call_args[1]["Subject"]
 
    def test_unknown_event_skipped(self):
        """未対応イベント → スキップ"""
        guardian = self._get_guardian()
        event = self._make_cloudtrail_event("UnknownEvent")
        result = guardian.lambda_handler(event, {})
        assert result["status"] == "skipped"

    @pytest.mark.parametrize("event_name", [
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    ])
    def test_subject_is_ascii_and_short(self, event_name):
        """全4イベントの Subject が SNS 制約（ASCII・改行なし・100字未満）を満たす"""
        guardian = self._get_guardian()
        with patch.object(guardian, "cloudtrail"), \
             patch.object(guardian, "sns") as mock_sns:
            event = self._make_cloudtrail_event(event_name)
            guardian.lambda_handler(event, {})
            subject = mock_sns.publish.call_args[1]["Subject"]
            subject.encode("ascii")  # 非ASCIIなら UnicodeEncodeError で fail
            assert "\n" not in subject and "\r" not in subject
            assert len(subject) < 100
            assert "?" not in subject  # replace 置換に頼らず原文がASCIIであること
 
 
# ─────────────────────────────────────────────────────────────
# Detector API Gateway テスト（追加分）
# ─────────────────────────────────────────────────────────────
 
class TestDetectorAPIGateway:
 
    def _load_detector(self):
        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_boto.return_value = mock_sts
            import importlib
            import detector.index as detector
            importlib.reload(detector)
        return detector
 
    def test_apigateway_rest_arn(self):
        """CreateRestApi → REST API ARN抽出"""
        detector = self._load_detector()
 
        detail = {
            "eventSource": "apigateway.amazonaws.com",
            "eventName": "CreateRestApi",
            "awsRegion": "ap-northeast-1",
            "responseElements": {"id": "abc123def"},
            "requestParameters": {},
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
        }
        arn = detector._apigateway_rest_arn(detail, "ap-northeast-1", "123456789012")
        assert arn == "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
 
    def test_create_api_http_not_extracted(self):
        """CreateApi（HTTP API）は RESOURCE_EXTRACTORS に未登録 → スキップ"""
        detector = self._load_detector()
 
        # HTTP API の CreateApi がマッピングに存在しないことを確認
        apigw_extractors = detector.RESOURCE_EXTRACTORS.get("apigateway.amazonaws.com", {})
        assert "CreateApi" not in apigw_extractors
        assert "CreateRestApi" in apigw_extractors


# ─────────────────────────────────────────────────────────────
# Isolator 冪等性ガード テスト（タスクA #4）
# SG差し替え系6サービス: 再隔離しても original_sgs を quarantine SG で
# 上書きしない（= TAG_ORIGINAL_SGS をタグ書き込みに含めない）ことを検証。
# modify は冪等に再実行されること（#3リトライ前提）も併せて確認。
# ─────────────────────────────────────────────────────────────

class TestIsolatorIdempotency:

    QUAR = "sg-quarantine00000000"   # 隔離SG
    REAL = "sg-real000000000000"     # 本物の元SG

    @pytest.fixture
    def isolator(self, monkeypatch):
        # import時のモジュールレベル client 生成にregionが要るため設定
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
        monkeypatch.setenv("DRY_RUN", "false")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
        return isolator

    @staticmethod
    def _factory(mocks):
        """boto3.client(service, ...) をサービス名でモックに振り分ける"""
        def f(service, *args, **kwargs):
            return mocks.get(service) or MagicMock()
        return f

    @staticmethod
    def _written_keys(mock_method, kind):
        """直近のタグ書き込み呼び出しから、書き込まれたタグキー一覧を取り出す"""
        kwargs = mock_method.call_args.kwargs
        if kind == "Key":      # [{"Key": .., "Value": ..}]  (EC2/RDS/EC/Redshift)
            return [t["Key"] for t in kwargs["Tags"]]
        if kind == "key":      # [{"key": .., "value": ..}]  (ECS)
            return [t["key"] for t in kwargs["tags"]]
        if kind == "dict":     # {K: V}                       (EKS)
            return list(kwargs["tags"].keys())
        raise ValueError(kind)

    # ── 純関数: ガードの判定ロジック ───────────────────────────

    def test_helper_initial_capture_returns_real(self, isolator):
        """初回: quarantine が現在SGに無い → 本物SGをそのまま返す"""
        assert isolator._original_sgs_to_save(["sg-a", "sg-b"], self.QUAR) == ["sg-a", "sg-b"]

    def test_helper_reisolation_returns_none(self, isolator):
        """再隔離: 現在SG=quarantineのみ → None（保存スキップ）"""
        assert isolator._original_sgs_to_save([self.QUAR], self.QUAR) is None

    def test_helper_strips_quarantine_keeps_real(self, isolator):
        """混在: quarantine を除外し本物SGだけ返す"""
        assert isolator._original_sgs_to_save([self.QUAR, "sg-a"], self.QUAR) == ["sg-a"]

    def test_helper_empty_returns_none(self, isolator):
        """現在SGが空 → None"""
        assert isolator._original_sgs_to_save([], self.QUAR) is None

    # ── 5サービス: 再隔離で original を上書きしない ───────────

    def test_ec2_reisolation_preserves_original(self, isolator):
        m = MagicMock()
        m.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "SecurityGroups": [{"GroupId": self.QUAR}],
                "VpcId": "vpc-1",
            }]}]
        }
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"ec2": m})), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_ec2(
                "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-123", "ap-northeast-1")
        keys = self._written_keys(m.create_tags, "Key")
        assert isolator.TAG_QUARANTINED in keys
        assert isolator.TAG_ORIGINAL_SGS not in keys
        m.modify_instance_attribute.assert_called_once()

    def test_rds_reisolation_preserves_original(self, isolator):
        m = MagicMock()
        m.describe_db_instances.return_value = {
            "DBInstances": [{
                "VpcSecurityGroups": [{"VpcSecurityGroupId": self.QUAR}],
                "DBInstanceArn": "arn:aws:rds:ap-northeast-1:123456789012:db:mydb",
                "DBSubnetGroup": {"VpcId": "vpc-1"},
            }]
        }
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"rds": m})), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_rds(
                "arn:aws:rds:ap-northeast-1:123456789012:db:mydb", "ap-northeast-1")
        keys = self._written_keys(m.add_tags_to_resource, "Key")
        assert isolator.TAG_QUARANTINED in keys
        assert isolator.TAG_ORIGINAL_SGS not in keys
        m.modify_db_instance.assert_called_once()

    def test_ecs_reisolation_preserves_original(self, isolator):
        m = MagicMock()
        m.describe_services.return_value = {
            "services": [{"networkConfiguration": {"awsvpcConfiguration": {
                "securityGroups": [self.QUAR], "subnets": ["subnet-1"]}}}]
        }
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"ecs": m})), \
             patch.object(isolator, "_vpc_id_from_subnet", return_value="vpc-1"), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_ecs(
                "arn:aws:ecs:ap-northeast-1:123456789012:service/clu/svc", "ap-northeast-1")
        keys = self._written_keys(m.tag_resource, "key")
        assert isolator.TAG_QUARANTINED in keys
        assert isolator.TAG_ORIGINAL_SGS not in keys
        m.update_service.assert_called_once()

    def test_eks_reisolation_preserves_original(self, isolator):
        m = MagicMock()
        m.describe_cluster.return_value = {
            "cluster": {"resourcesVpcConfig": {
                "securityGroupIds": [self.QUAR], "subnetIds": ["subnet-1"]}}
        }
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"eks": m})), \
             patch.object(isolator, "_vpc_id_from_subnet", return_value="vpc-1"), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_eks(
                "arn:aws:eks:ap-northeast-1:123456789012:cluster/myclu", "ap-northeast-1")
        keys = self._written_keys(m.tag_resource, "dict")
        assert isolator.TAG_QUARANTINED in keys
        assert isolator.TAG_ORIGINAL_SGS not in keys
        m.update_cluster_config.assert_called_once()


    # ── Redshift は / 区切り保存 ──

    def test_redshift_reisolation_preserves_original(self, isolator):
        m = MagicMock()
        m.describe_clusters.return_value = {"Clusters": [{
            "VpcSecurityGroups": [{"VpcSecurityGroupId": self.QUAR}],
            "ClusterSubnetGroupName": "csg"}]}
        m.describe_cluster_subnet_groups.return_value = {
            "ClusterSubnetGroups": [{"VpcId": "vpc-1"}]}
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"redshift": m})), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_redshift(
                "arn:aws:redshift:ap-northeast-1:123456789012:cluster:myclu", "ap-northeast-1")
        keys = self._written_keys(m.create_tags, "Key")
        assert isolator.TAG_QUARANTINED in keys
        assert isolator.TAG_ORIGINAL_SGS not in keys
        m.modify_cluster.assert_called_once()
     

    def test_redshift_initial_capture_slash_encoded(self, isolator):
        m = MagicMock()
        m.describe_clusters.return_value = {"Clusters": [{
            "VpcSecurityGroups": [{"VpcSecurityGroupId": self.REAL}],
            "ClusterSubnetGroupName": "csg"}]}
        m.describe_cluster_subnet_groups.return_value = {
            "ClusterSubnetGroups": [{"VpcId": "vpc-1"}]}
        with patch.object(isolator.boto3, "client", side_effect=self._factory({"redshift": m})), \
             patch.object(isolator, "_get_or_create_quarantine_sg", return_value=self.QUAR):
            isolator._isolate_redshift(
                "arn:aws:redshift:ap-northeast-1:123456789012:cluster:myclu", "ap-northeast-1")
        tags = {t["Key"]: t["Value"] for t in m.create_tags.call_args.kwargs["Tags"]}
        assert tags[isolator.TAG_ORIGINAL_SGS] == self.REAL   # 単一なので / 区切りでもそのまま
        assert "[" not in tags[isolator.TAG_ORIGINAL_SGS]     # json.dumps の [ ] " を含まない
        m.modify_cluster.assert_called_once()
     

# ─────────────────────────────────────────────────────────────
# Isolator S3 痕跡化テスト（lossy restore 対策・型の固定）
# ─────────────────────────────────────────────────────────────

class TestIsolatorS3Trace:

    S3_ARN = "arn:aws:s3:::tagwatchman-trace-test"
    BUCKET = "tagwatchman-trace-test"
    REGION = "ap-northeast-1"

    SAMPLE_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "A1", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::tagwatchman-trace-test/*"},
            {"Sid": "A2", "Effect": "Allow", "Principal": "*",
             "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::tagwatchman-trace-test"},
            {"Sid": "D1", "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
             "Action": "s3:DeleteBucket", "Resource": "arn:aws:s3:::tagwatchman-trace-test"},
        ],
    })

    @pytest.fixture
    def isolator(self, monkeypatch):
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
        monkeypatch.setenv("DRY_RUN", "false")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
        return isolator

    def _tags(self, s3):
        resp = s3.get_bucket_tagging(Bucket=self.BUCKET)
        return {t["Key"]: t["Value"] for t in resp["TagSet"]}

    # 1) 概観 b64 の正確性＋256字内
    def test_policy_summary_b64_shape(self, isolator):
        b64 = isolator._policy_summary_b64(self.SAMPLE_POLICY)
        assert len(b64) <= 256
        decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
        assert decoded == {"st": 3, "al": 2, "dy": 1, "wild": True}

    # 2) unparsable フォールバック（例外を投げない）
    def test_policy_summary_b64_unparsable(self, isolator):
        b64 = isolator._policy_summary_b64("{not valid json")
        decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
        assert decoded == {"err": "unparsable"}

    # 3) 既存ポリシー有り → trace タグ3種＋return body、sha256 一致
    @mock_aws
    def test_s3_isolate_captures_trace_when_policy_exists(self, isolator):
        s3 = boto3.client("s3", region_name=self.REGION)
        s3.create_bucket(Bucket=self.BUCKET,
                         CreateBucketConfiguration={"LocationConstraint": self.REGION})
        s3.put_bucket_policy(Bucket=self.BUCKET, Policy=self.SAMPLE_POLICY)

        trace = isolator._isolate_s3(self.S3_ARN, self.REGION)

        assert trace["had"] is True
        assert trace["body"] == self.SAMPLE_POLICY
        tags = self._tags(s3)
        assert tags["tagwatchman:had-bucket-policy"] == "True"
        import hashlib
        assert tags["tagwatchman:original-policy-sha256"] == \
            hashlib.sha256(self.SAMPLE_POLICY.encode("utf-8")).hexdigest()
        assert tags["tagwatchman:original-policy-isolated-at"].endswith("Z")
        assert "tagwatchman:original-policy-summary-b64" in tags
        decoded = json.loads(base64.b64decode(
            tags["tagwatchman:original-policy-summary-b64"]).decode("utf-8"))
        assert decoded == {"st": 3, "al": 2, "dy": 1, "wild": True}

    # 4) 既存ポリシー無し → trace タグ非付与＋return had=False
    @mock_aws
    def test_s3_isolate_no_policy_skips_trace(self, isolator):
        s3 = boto3.client("s3", region_name=self.REGION)
        s3.create_bucket(Bucket=self.BUCKET,
                         CreateBucketConfiguration={"LocationConstraint": self.REGION})

        trace = isolator._isolate_s3(self.S3_ARN, self.REGION)

        assert trace == {"isolationStatus": "policy_denied", "had": False, "body": ""}
        tags = self._tags(s3)
        assert tags["tagwatchman:had-bucket-policy"] == "False"
        assert "tagwatchman:original-policy-sha256" not in tags
        assert "tagwatchman:original-policy-isolated-at" not in tags
        assert "tagwatchman:original-policy-summary-b64" not in tags

    # 5) handler が lostPolicy を merge（配管a の Lambda 側端点）
    @mock_aws
    def test_s3_handler_merges_lost_policy(self, isolator):
        s3 = boto3.client("s3", region_name=self.REGION)
        s3.create_bucket(Bucket=self.BUCKET,
                         CreateBucketConfiguration={"LocationConstraint": self.REGION})
        s3.put_bucket_policy(Bucket=self.BUCKET, Policy=self.SAMPLE_POLICY)

        out = isolator.lambda_handler(
            {"arn": self.S3_ARN, "region": self.REGION,
             "missingTags": ["Env"], "requiredTags": ["Env", "Project", "Owned"]},
            None,
        )

        assert out["isolationStatus"] == "policy_denied"
        assert out["lostPolicy"]["had"] is True
        assert out["lostPolicy"]["body"] == self.SAMPLE_POLICY

    # 6) lossy だが識別可能（隔離後は元本文消失・sha256 で照合可能）
    @mock_aws
    def test_s3_isolate_is_lossy_but_identifiable(self, isolator):
        s3 = boto3.client("s3", region_name=self.REGION)
        s3.create_bucket(Bucket=self.BUCKET,
                         CreateBucketConfiguration={"LocationConstraint": self.REGION})
        s3.put_bucket_policy(Bucket=self.BUCKET, Policy=self.SAMPLE_POLICY)

        trace = isolator._isolate_s3(self.S3_ARN, self.REGION)

        current = json.loads(s3.get_bucket_policy(Bucket=self.BUCKET)["Policy"])
        sids = [st.get("Sid") for st in current["Statement"]]
        assert "TagWatchmanQuarantine" in sids
        assert "A1" not in sids  # 元本文は上書きで消失
        import hashlib
        tags = self._tags(s3)
        assert tags["tagwatchman:original-policy-sha256"] == \
            hashlib.sha256(trace["body"].encode("utf-8")).hexdigest()





# ─────────────────────────────────────────────────────────────
# Restorer Lambda 同時実行数の両経路（v25 明記分・v26 追加）
# ─────────────────────────────────────────────────────────────

class TestRestorerLambdaConcurrency:

    REGION = "ap-northeast-1"
    FUNC = "tw-test-func"

    def _setup_function(self, original_concurrency_tag: str):
        """隔離済み状態（concurrency=0 + tagwatchman タグ）の Lambda を作る"""
        import io
        import zipfile

        iam = boto3.client("iam")
        role_arn = iam.create_role(
            RoleName="tw-lambda-exec",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        )["Role"]["Arn"]

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("index.py", "def handler(e, c): pass")

        lam = boto3.client("lambda", region_name=self.REGION)
        func_arn = lam.create_function(
            FunctionName=self.FUNC, Runtime="python3.12", Role=role_arn,
            Handler="index.handler", Code={"ZipFile": buf.getvalue()},
        )["FunctionArn"]

        # 隔離状態を再現
        lam.put_function_concurrency(
            FunctionName=self.FUNC, ReservedConcurrentExecutions=0)
        lam.tag_resource(Resource=func_arn, Tags={
            "tagwatchman:quarantined": "true",
            "tagwatchman:original-concurrency": original_concurrency_tag,
        })
        return lam, func_arn

    @mock_aws
    def test_lambda_restore_original_unset(self, monkeypatch):
        """元々 concurrency 未設定（タグ -1）→ delete_function_concurrency 経路"""
        monkeypatch.setenv("DRY_RUN", "false")
        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)

        lam, func_arn = self._setup_function("-1")

        result = restorer.lambda_handler(
            {"arn": func_arn, "region": self.REGION}, {})
        assert result["restoreStatus"] == "restored"

        # 制限が削除されている（未設定状態に戻る）
        conc = lam.get_function_concurrency(FunctionName=self.FUNC)
        assert "ReservedConcurrentExecutions" not in conc

        # tagwatchman タグが除去されている
        tags = lam.list_tags(Resource=func_arn)["Tags"]
        assert "tagwatchman:quarantined" not in tags
        assert "tagwatchman:original-concurrency" not in tags

    @mock_aws
    def test_lambda_restore_original_set(self, monkeypatch):
        """元の concurrency 設定あり（タグ 5）→ put_function_concurrency で値戻し経路"""
        monkeypatch.setenv("DRY_RUN", "false")
        import importlib
        import restorer.index as restorer
        importlib.reload(restorer)

        lam, func_arn = self._setup_function("5")

        result = restorer.lambda_handler(
            {"arn": func_arn, "region": self.REGION}, {})
        assert result["restoreStatus"] == "restored"

        # 元の値 5 に戻っている
        conc = lam.get_function_concurrency(FunctionName=self.FUNC)
        assert conc.get("ReservedConcurrentExecutions") == 5

        # tagwatchman タグが除去されている
        tags = lam.list_tags(Resource=func_arn)["Tags"]
        assert "tagwatchman:quarantined" not in tags
        assert "tagwatchman:original-concurrency" not in tags
