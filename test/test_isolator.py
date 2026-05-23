"""
test_isolator.py
────────────────
isolator Lambda のユニットテスト
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch, call

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))


@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    monkeypatch.setenv("QUARANTINE_SG_ID", "sg-quarantine123")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("AWS_REGION", "ap-northeast-1")


BASE_EVENT = {
    "arn": "",
    "missingTags": ["Env"],
    "requiredTags": ["Env", "Project", "Owned"],
    "region": "ap-northeast-1",
    "eventName": "RunInstances",
    "principal": "arn:aws:iam::123456789012:user/test",
}


class TestIsolatorDryRun:

    def test_dry_run_skips_isolation(self, monkeypatch):
        """DRY_RUN=true の場合は隔離しない"""
        monkeypatch.setenv("DRY_RUN", "true")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        event = {**BASE_EVENT, "arn": "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-123"}
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "dry_run"


class TestIsolatorEC2:

    @mock_aws
    def test_ec2_isolation(self, monkeypatch):
        """EC2 隔離 → SGを全拒否に差し替え"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")

        # VPC・SG・インスタンスを作成
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")
        subnet_id = subnet["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="original-sg", Description="original", VpcId=vpc_id)
        original_sg_id = sg["GroupId"]

        # 全拒否SGも作成（moto内で実際に存在する必要がある）
        quarantine_sg = ec2.create_security_group(GroupName="quarantine-sg", Description="quarantine", VpcId=vpc_id)
        quarantine_sg_id = quarantine_sg["GroupId"]
        monkeypatch.setenv("QUARANTINE_SG_ID", quarantine_sg_id)
        isolator.QUARANTINE_SG = quarantine_sg_id

        instance = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            SecurityGroupIds=[original_sg_id],
        )
        instance_id = instance["Instances"][0]["InstanceId"]

        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:instance/{instance_id}"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "isolated"

        # SGが差し替えられているか確認
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
        assert quarantine_sg_id in sgs


class TestIsolatorS3:

    @mock_aws
    def test_s3_isolation(self):
        """S3 隔離 → バケットポリシーで全拒否"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        s3 = boto3.client("s3", region_name="ap-northeast-1")
        s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"},
        )

        arn = "arn:aws:s3:::test-bucket"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "isolated"

        # ポリシーが設定されているか確認
        policy = s3.get_bucket_policy(Bucket="test-bucket")
        policy_doc = json.loads(policy["Policy"])
        assert policy_doc["Statement"][0]["Effect"] == "Deny"
        assert policy_doc["Statement"][0]["Sid"] == "TagWatchmanQuarantine"


class TestIsolatorLambda:

    @mock_aws
    def test_lambda_isolation(self):
        """Lambda 隔離 → 同時実行数を0に設定"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        lmb = boto3.client("lambda", region_name="ap-northeast-1")
        iam = boto3.client("iam", region_name="ap-northeast-1")

        # IAM ロール作成
        role = iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        # Lambda 関数作成
        lmb.create_function(
            FunctionName="test-function",
            Runtime="python3.12",
            Role=role["Role"]["Arn"],
            Handler="index.handler",
            Code={"ZipFile": b"def handler(e, c): pass"},
        )

        arn = f"arn:aws:lambda:ap-northeast-1:123456789012:function:test-function"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "isolated"

        # 同時実行数が0になっているか確認
        resp = lmb.get_function_concurrency(FunctionName="test-function")
        assert resp["ReservedConcurrentExecutions"] == 0


class TestIsolatorIGW:

    @mock_aws
    def test_igw_not_attached_deleted(self):
        """IGW アタッチなし → 即時削除"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        igw = ec2.create_internet_gateway()
        igw_id = igw["InternetGateway"]["InternetGatewayId"]

        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:internet-gateway/{igw_id}"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "isolated"

        # 削除されているか確認
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "internet-gateway-id", "Values": [igw_id]}]
        )
        assert len(igws["InternetGateways"]) == 0

    @mock_aws
    def test_igw_attached_raises(self):
        """IGW アタッチあり → エラー（通知フローへ）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        igw = ec2.create_internet_gateway()
        igw_id = igw["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:internet-gateway/{igw_id}"
        event = {**BASE_EVENT, "arn": arn}

        # アタッチありの場合はRuntimeErrorが発生する
        with pytest.raises(RuntimeError, match="attached to VPC"):
            isolator._isolate_igw(arn, "ap-northeast-1")


class TestIsolatorNoExtractor:

    def test_unknown_arn_skipped(self):
        """未対応ARN → スキップ"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        event = {**BASE_EVENT, "arn": "arn:aws:unknown:ap-northeast-1:123456789012:resource/test"}
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "skipped"
