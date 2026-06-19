"""S3以外5サービス（DynamoDB / SQS / SNS / OpenSearch / ECR）の
痕跡タグ均一化（ポリシー指紋タグ）検証。

- _policy_trace_pairs の純粋テストで指紋の中身（sha256/summary/isolated-at）を確定。
- 各サービスの結合テストで「サービス固有のタグAPI形式(list/dict/TagList/小文字tags)で
  指紋タグが実際に着くか」を検証。moto がポリシー本文を正規化し得るため、結合側は
  厳密な sha256 一致でなく「存在＋形式」で堅く検証する。
- 痕跡はどの Lambda も機械的に読まない（フォレンジック専用）。
"""
import base64
import hashlib
import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))

REGION = "ap-northeast-1"
ACCOUNT = "123456789012"

# 2 Allow / 1 Deny / wildcard Principal あり → summary={"st":3,"al":2,"dy":1,"wild":True}
SAMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "A1", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
         "Action": "*", "Resource": "*"},
        {"Sid": "A2", "Effect": "Allow", "Principal": "*",
         "Action": "*", "Resource": "*"},
        {"Sid": "D1", "Effect": "Deny",
         "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
         "Action": "*", "Resource": "*"},
    ],
})

HAD_KEY     = "tagwatchman:had-resource-policy"
SHA_KEY     = "tagwatchman:original-policy-sha256"
AT_KEY      = "tagwatchman:original-policy-isolated-at"
SUMMARY_KEY = "tagwatchman:original-policy-summary-b64"
S3_ONLY_KEY = "tagwatchman:had-bucket-policy"


@pytest.fixture
def isolator(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("DRY_RUN", "false")
    import importlib
    import isolator.index as isolator
    importlib.reload(isolator)
    return isolator


def _assert_fingerprint_present(tags: dict):
    assert tags[HAD_KEY] == "True"
    assert len(tags[SHA_KEY]) == 64
    int(tags[SHA_KEY], 16)  # hex であること
    assert tags[AT_KEY].endswith("Z")
    decoded = json.loads(base64.b64decode(tags[SUMMARY_KEY]).decode("utf-8"))
    assert "st" in decoded
    assert S3_ONLY_KEY not in tags  # S3専用キーは混入しない


# ─────────────────────────────────────────────────────────────
# 1) ヘルパー純粋テスト（moto非依存・指紋の中身を確定）
# ─────────────────────────────────────────────────────────────
class TestPolicyTracePairs:

    def test_with_policy(self, isolator):
        pairs = dict(isolator._policy_trace_pairs(True, SAMPLE_POLICY))
        assert pairs[HAD_KEY] == "True"
        assert pairs[SHA_KEY] == hashlib.sha256(SAMPLE_POLICY.encode("utf-8")).hexdigest()
        assert pairs[AT_KEY].endswith("Z")
        decoded = json.loads(base64.b64decode(pairs[SUMMARY_KEY]).decode("utf-8"))
        assert decoded == {"st": 3, "al": 2, "dy": 1, "wild": True}

    def test_without_policy(self, isolator):
        pairs = dict(isolator._policy_trace_pairs(False, None))
        assert pairs == {HAD_KEY: "False"}

    def test_had_true_but_empty_body_skips_fingerprint(self, isolator):
        # had=True でも body 空なら指紋は付けない（S3 と同条件 had and body）
        pairs = dict(isolator._policy_trace_pairs(True, ""))
        assert pairs == {HAD_KEY: "True"}

    def test_uses_neutral_key_not_s3_specific(self, isolator):
        pairs = dict(isolator._policy_trace_pairs(True, SAMPLE_POLICY))
        assert S3_ONLY_KEY not in pairs  # had-bucket-policy は使わない

    def test_summary_b64_within_tag_limit(self, isolator):
        pairs = dict(isolator._policy_trace_pairs(True, SAMPLE_POLICY))
        assert len(pairs[SUMMARY_KEY]) <= 256
        assert len(pairs[SHA_KEY]) <= 256


# ─────────────────────────────────────────────────────────────
# 2) 各サービス結合テスト（タグAPI形式 list/dict/TagList/小文字tags）
# ─────────────────────────────────────────────────────────────
class TestDynamoDBTraceParity:
    @mock_aws
    def test_fingerprint_with_policy(self, isolator):
        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName="tw-trace",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        arn = ddb.describe_table(TableName="tw-trace")["Table"]["TableArn"]
        ddb.put_resource_policy(ResourceArn=arn, Policy=SAMPLE_POLICY)

        isolator._isolate_dynamodb(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in ddb.list_tags_of_resource(ResourceArn=arn)["Tags"]}
        _assert_fingerprint_present(tags)

    @mock_aws
    def test_no_policy_skips_fingerprint(self, isolator):
        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName="tw-trace2",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        arn = ddb.describe_table(TableName="tw-trace2")["Table"]["TableArn"]

        isolator._isolate_dynamodb(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in ddb.list_tags_of_resource(ResourceArn=arn)["Tags"]}
        assert tags[HAD_KEY] == "False"
        assert SHA_KEY not in tags


class TestSQSTraceParity:
    @mock_aws
    def test_fingerprint_with_policy(self, isolator):
        sqs = boto3.client("sqs", region_name=REGION)
        url = sqs.create_queue(QueueName="tw-trace")["QueueUrl"]
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": SAMPLE_POLICY})
        arn = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

        isolator._isolate_sqs(arn, REGION)

        tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        _assert_fingerprint_present(tags)

    @mock_aws
    def test_no_policy_skips_fingerprint(self, isolator):
        sqs = boto3.client("sqs", region_name=REGION)
        url = sqs.create_queue(QueueName="tw-trace2")["QueueUrl"]
        arn = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

        isolator._isolate_sqs(arn, REGION)

        tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        assert tags[HAD_KEY] == "False"
        assert SHA_KEY not in tags


class TestSNSTraceParity:
    @mock_aws
    def test_fingerprint_with_policy(self, isolator):
        sns = boto3.client("sns", region_name=REGION)
        arn = sns.create_topic(Name="tw-trace")["TopicArn"]
        sns.set_topic_attributes(
            TopicArn=arn, AttributeName="Policy", AttributeValue=SAMPLE_POLICY)

        isolator._isolate_sns(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}
        _assert_fingerprint_present(tags)

    @mock_aws
    def test_no_policy_skips_fingerprint(self, isolator):
        sns = boto3.client("sns", region_name=REGION)
        arn = sns.create_topic(Name="tw-trace2")["TopicArn"]
        # 作成直後の SNS は __default_policy_ID が付くため厳密な「ポリシー無し」に
        # ならないことがある。ここでは had フラグの記録自体を検証する。
        isolator._isolate_sns(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}
        assert tags[HAD_KEY] in ("True", "False")


class TestECRTraceParity:
    @mock_aws
    def test_fingerprint_with_policy(self, isolator):
        ecr = boto3.client("ecr", region_name=REGION)
        ecr.create_repository(repositoryName="tw-trace")
        arn = ecr.describe_repositories(
            repositoryNames=["tw-trace"])["repositories"][0]["repositoryArn"]
        ecr.set_repository_policy(repositoryName="tw-trace", policyText=SAMPLE_POLICY)

        isolator._isolate_ecr(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
        _assert_fingerprint_present(tags)

    @mock_aws
    def test_no_policy_skips_fingerprint(self, isolator):
        ecr = boto3.client("ecr", region_name=REGION)
        ecr.create_repository(repositoryName="tw-trace2")
        arn = ecr.describe_repositories(
            repositoryNames=["tw-trace2"])["repositories"][0]["repositoryArn"]

        isolator._isolate_ecr(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
        assert tags[HAD_KEY] == "False"
        assert SHA_KEY not in tags


class TestOpenSearchTraceParity:
    @mock_aws
    def test_fingerprint_with_policy(self, isolator):
        es = boto3.client("es", region_name=REGION)
        es.create_elasticsearch_domain(
            DomainName="tw-trace",
            AccessPolicies=SAMPLE_POLICY,
        )
        arn = es.describe_elasticsearch_domain(
            DomainName="tw-trace")["DomainStatus"]["ARN"]

        isolator._isolate_opensearch(arn, REGION)

        tags = {t["Key"]: t["Value"]
                for t in es.list_tags(ARN=arn)["TagList"]}
        _assert_fingerprint_present(tags)
