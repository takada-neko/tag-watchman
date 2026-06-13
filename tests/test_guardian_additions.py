"""
test_guardian_additions.py
──────────────────────────
既存 TestCloudTrailGuardian（test_lambdas.py）が MagicMock ベースで
カバーしていなかった3つの穴を埋める追加テスト:

  1. moto 実挙動: StopLogging で IsLogging が実際に True に戻ることを裏取り
  2. start_logging 失敗経路: re_enabled=False / error_msg 充填 / メールは飛ぶ
  3. trail_name 抽出の casing: `trailName` キー側・空のとき（自動修復スキップ）

最終的には test_lambdas.py の TestCloudTrailGuardian に統合する想定。
"""

import importlib.util
import json
import os
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

REGION = "ap-northeast-1"


def _get_guardian():
    """import 時に SNS_TOPIC_ARN を読み boto3 クライアントを生成するため、
    必ず環境変数設定後（＝mock_aws コンテキスト内）に呼ぶ。"""
    p = os.path.join(os.path.dirname(__file__), "../lambda/cloudtrail-guardian/index.py")
    spec = importlib.util.spec_from_file_location("cloudtrail_guardian_index", p)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return g


def _make_event(event_name, request_params):
    return {
        "detail": {
            "eventName": event_name,
            "eventTime": "2025-01-01T00:00:00Z",
            "awsRegion": REGION,
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
            "requestParameters": request_params,
        }
    }


def _setup_logging_trail(name="tw-guardian-trail"):
    """moto 上に「ログ記録中→停止済み」の trail を立てて返す。"""
    s3 = boto3.client("s3", region_name=REGION)
    bucket = "tw-guardian-test-bucket"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AclCheck", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Sid": "Write", "Effect": "Allow",
             "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }))
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name=name, S3BucketName=bucket)
    ct.start_logging(Name=name)
    ct.stop_logging(Name=name)
    return ct, name


class _GuardianTestBase:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        # 既定のダミー ARN。moto 実体トピックが要るテストはテスト内で上書きする。
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-northeast-1:123456789012:tw-alert")
        self._monkeypatch = monkeypatch


class TestGuardianMotoReenable(_GuardianTestBase):
    """穴1: moto 実挙動で再有効化が本当に効くか"""

    @mock_aws
    def test_stop_logging_actually_reenables(self):
        ct, name = _setup_logging_trail()
        assert ct.get_trail_status(Name=name)["IsLogging"] is False  # 前提: 停止済み
        topic = boto3.client("sns", region_name=REGION).create_topic(Name="tw-alert")["TopicArn"]
        self._monkeypatch.setenv("SNS_TOPIC_ARN", topic)

        guardian = _get_guardian()
        result = guardian.lambda_handler(_make_event("StopLogging", {"name": name}), {})

        assert result["re_enabled"] is True
        # MagicMock では決して確認できなかった「実際に戻る」を裏取り
        assert ct.get_trail_status(Name=name)["IsLogging"] is True


class TestGuardianReenableFailure(_GuardianTestBase):
    """穴2: start_logging 失敗時に re_enabled=False で、メールは飛ぶ（黙って死なない）

    注: moto は存在しない trail に生 KeyError を投げる（実 AWS は ClientError=
    TrailNotFoundException）。guardian は ClientError しか catch しないので、実機が実際に
    投げる型＝ClientError を注入して except 分岐を検証する。moto の KeyError 依存は実機と
    乖離するため使わない。"""

    def _err(self):
        return ClientError(
            {"Error": {"Code": "TrailNotFoundException", "Message": "Unknown trail"}}, "StartLogging")

    def test_failure_sets_reenabled_false_and_still_mails(self):
        guardian = _get_guardian()
        with patch.object(guardian, "cloudtrail") as mock_ct, \
             patch.object(guardian, "sns") as mock_sns:
            mock_ct.start_logging.side_effect = self._err()
            result = guardian.lambda_handler(_make_event("StopLogging", {"name": "some-trail"}), {})
        assert result["status"] == "handled"    # ハンドラ自体は完走
        assert result["re_enabled"] is False     # 修復は不発と正しく報告
        mock_sns.publish.assert_called_once()    # それでもメールは飛ぶ

    def test_failure_message_marks_reenable_failed(self):
        guardian = _get_guardian()
        with patch.object(guardian, "cloudtrail") as mock_ct, \
             patch.object(guardian, "sns") as mock_sns:
            mock_ct.start_logging.side_effect = self._err()
            guardian.lambda_handler(_make_event("StopLogging", {"name": "some-trail"}), {})
            body = mock_sns.publish.call_args[1]["Message"]
        assert "失敗" in body                     # ✅成功 ではなく ❌失敗 表記
        assert "TrailNotFoundException" in body   # 原因が人間に渡る


class TestGuardianTrailNameExtraction(_GuardianTestBase):
    """穴3: trail_name 抽出の casing 罠（detector の arn/ARN/aRN と同系統）"""

    def test_extract_from_trailname_key(self):
        guardian = _get_guardian()
        n = guardian._extract_trail_name(
            "PutEventSelectors", {"requestParameters": {"trailName": "via-trailName"}})
        assert n == "via-trailName"

    def test_extract_from_name_key(self):
        guardian = _get_guardian()
        n = guardian._extract_trail_name(
            "StopLogging", {"requestParameters": {"name": "via-name"}})
        assert n == "via-name"

    def test_empty_trail_name_skips_reenable(self):
        """両キー欠落で trail_name が取れないと start_logging はスキップ＝再有効化されない。
        『メールは飛ぶが修復は黙って不発』になる最悪ケースの固定。"""
        guardian = _get_guardian()
        with patch.object(guardian, "cloudtrail") as mock_ct, \
             patch.object(guardian, "sns"):
            result = guardian.lambda_handler(_make_event("StopLogging", {}), {})
            mock_ct.start_logging.assert_not_called()  # 空名で叩きにいかない
        assert result["re_enabled"] is False
