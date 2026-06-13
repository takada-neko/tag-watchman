"""
test_isolator.py
────────────────
isolator Lambda のユニットテスト
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
 
 
@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    monkeypatch.setenv("QUARANTINE_SG_ID", "sg-quarantine123")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("AWS_REGION", "ap-northeast-1")
    monkeypatch.setenv("OPERATOR_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-operator")
    monkeypatch.setenv("LAMBDA_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
 
 
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
        assert result["isolationStatus"] == "network_isolated"
 
        # 隔離SGが対象VPC内に動的作成されたか確認
        q_resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": ["tagwatchman-quarantine"]},
                {"Name": "vpc-id",     "Values": [vpc_id]},
            ]
        )
        assert len(q_resp["SecurityGroups"]) == 1
        quarantine_sg_id = q_resp["SecurityGroups"][0]["GroupId"]
 
        # SGが差し替えられているか確認
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
        assert quarantine_sg_id in sgs
        assert original_sg_id not in sgs
 
        # 元のSGがタグに保存されているか確認
        tag_resp = ec2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": ["tagwatchman:original-sgs"]},
            ]
        )
        saved = tag_resp["Tags"][0]["Value"].split("/")
        assert original_sg_id in saved


class TestIsolatorRDS:

    @mock_aws
    def test_rds_isolation(self):
        """RDS 隔離 → 対象DBのVPC内に隔離SGを動的作成し差し替え"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        rds = boto3.client("rds", region_name="ap-northeast-1")

        # VPC・subnet・SG・DBSubnetGroup・DBインスタンスを作成
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
        subnet_id = subnet["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="original-sg", Description="orig", VpcId=vpc_id)
        original_sg_id = sg["GroupId"]

        rds.create_db_subnet_group(
            DBSubnetGroupName="test-subnet-group",
            DBSubnetGroupDescription="test",
            SubnetIds=[subnet_id],
        )
        rds.create_db_instance(
            DBInstanceIdentifier="test-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            AllocatedStorage=20,
            MasterUsername="admin",
            MasterUserPassword="Password123!",
            DBSubnetGroupName="test-subnet-group",
            VpcSecurityGroupIds=[original_sg_id],
        )

        arn = "arn:aws:rds:ap-northeast-1:123456789012:db:test-db"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "network_isolated"

        # 隔離SGが対象VPC内に動的作成されたか
        q_resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": ["tagwatchman-quarantine"]},
                {"Name": "vpc-id",     "Values": [vpc_id]},
            ]
        )
        assert len(q_resp["SecurityGroups"]) == 1
        quarantine_sg_id = q_resp["SecurityGroups"][0]["GroupId"]

        # DBのSGが差し替えられているか
        db = rds.describe_db_instances(DBInstanceIdentifier="test-db")["DBInstances"][0]
        current_sgs = [s["VpcSecurityGroupId"] for s in db.get("VpcSecurityGroups", [])]
        assert quarantine_sg_id in current_sgs
        assert original_sg_id not in current_sgs

        # 元のSGがタグに保存されているか
        tags = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])["TagList"]
        tagmap = {t["Key"]: t["Value"] for t in tags}
        saved = tagmap["tagwatchman:original-sgs"].split("/")
        assert original_sg_id in saved


class TestIsolatorEKS:

    @mock_aws
    def test_eks_isolation(self):
        """EKS 隔離 → クラスタのVPC内に隔離SGを動的作成し差し替え"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        eks = boto3.client("eks", region_name="ap-northeast-1")
        iam = boto3.client("iam", region_name="ap-northeast-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        original_sg_id = ec2.create_security_group(
            GroupName="original-sg", Description="orig", VpcId=vpc_id
        )["GroupId"]
        role = iam.create_role(
            RoleName="eks-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow",
                               "Principal": {"Service": "eks.amazonaws.com"},
                               "Action": "sts:AssumeRole"}],
            }),
        )["Role"]["Arn"]

        eks.create_cluster(
            name="test-cluster",
            roleArn=role,
            resourcesVpcConfig={
                "subnetIds": [subnet_id],
                "securityGroupIds": [original_sg_id],
            },
        )
        arn = eks.describe_cluster(name="test-cluster")["cluster"]["arn"]
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "network_isolated"

        # 隔離SGが対象VPC内に動的作成されたか
        q_resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": ["tagwatchman-quarantine"]},
                {"Name": "vpc-id",     "Values": [vpc_id]},
            ]
        )
        assert len(q_resp["SecurityGroups"]) == 1
        quarantine_sg_id = q_resp["SecurityGroups"][0]["GroupId"]

        # クラスタのSGが差し替えられているか
        cl = eks.describe_cluster(name="test-cluster")["cluster"]
        current = cl["resourcesVpcConfig"].get("securityGroupIds", [])
        assert quarantine_sg_id in current
        assert original_sg_id not in current

        # 元のSGがタグに保存されているか
        tags = eks.list_tags_for_resource(resourceArn=arn)["tags"]
        saved = tags["tagwatchman:original-sgs"].split("/")
        assert original_sg_id in saved

 
class TestIsolatorECS:

    @mock_aws
    def test_ecs_isolation(self):
        """ECS 隔離 → サービスのVPC内に隔離SGを動的作成し差し替え（subnetは温存）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        ecs = boto3.client("ecs", region_name="ap-northeast-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        original_sg_id = ec2.create_security_group(
            GroupName="original-sg", Description="orig", VpcId=vpc_id
        )["GroupId"]

        ecs.create_cluster(clusterName="test-cluster")
        ecs.register_task_definition(
            family="test-task",
            containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}],
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256", memory="512",
        )
        ecs.create_service(
            cluster="test-cluster",
            serviceName="test-service",
            taskDefinition="test-task",
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet_id],
                    "securityGroups": [original_sg_id],
                }
            },
        )

        arn = "arn:aws:ecs:ap-northeast-1:123456789012:service/test-cluster/test-service"
        event = {**BASE_EVENT, "arn": arn}

        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "network_isolated"

        # 隔離SGが対象VPC内に動的作成されたか
        q_resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": ["tagwatchman-quarantine"]},
                {"Name": "vpc-id",     "Values": [vpc_id]},
            ]
        )
        assert len(q_resp["SecurityGroups"]) == 1
        quarantine_sg_id = q_resp["SecurityGroups"][0]["GroupId"]

        # サービスのSGが差し替えられ、subnetは温存されているか
        svc = ecs.describe_services(cluster="test-cluster", services=["test-service"])["services"][0]
        awsvpc = svc["networkConfiguration"]["awsvpcConfiguration"]
        assert quarantine_sg_id in awsvpc["securityGroups"]
        assert original_sg_id not in awsvpc["securityGroups"]
        assert awsvpc["subnets"] == [subnet_id]

        # 元のSGがタグに保存されているか
        tags = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
        tagmap = {t["key"]: t["value"] for t in tags}
        saved = tagmap["tagwatchman:original-sgs"].split("/")
        assert original_sg_id in saved


class TestIsolatorRedshift:

    def test_redshift_isolation(self):
        """Redshift 隔離 → ClusterSubnetGroupName経由でVPC解決しSG差し替え（MagicMock）

        moto は modify_cluster のSG差し替えが壊れている（差し替え後が空になる）ため、
        実AWS準拠の呼び出し経路を MagicMock で検証する。SG差し替えの実挙動は
        タスク6の実機確認でカバーする。
        """
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        arn = "arn:aws:redshift:ap-northeast-1:123456789012:cluster:test-cluster"
        event = {**BASE_EVENT, "arn": arn}

        mock_rs = MagicMock()
        mock_ec2 = MagicMock()

        mock_rs.describe_clusters.return_value = {
            "Clusters": [{
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-original", "Status": "active"}],
                "ClusterSubnetGroupName": "test-csg",
            }]
        }
        mock_rs.describe_cluster_subnet_groups.return_value = {
            "ClusterSubnetGroups": [{"VpcId": "vpc-12345"}]
        }
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.create_security_group.return_value = {"GroupId": "sg-quarantine"}

        def client_factory(service, *args, **kwargs):
            return {"redshift": mock_rs, "ec2": mock_ec2}.get(service, MagicMock())

        with patch("boto3.client", side_effect=client_factory):
            result = isolator.lambda_handler(event, {})

        assert result["isolationStatus"] == "network_isolated"

        # 隔離SGが解決済みVPCで作成されたか
        mock_ec2.create_security_group.assert_called_once()
        assert mock_ec2.create_security_group.call_args[1]["VpcId"] == "vpc-12345"

        # 元のSGがタグに保存されたか（Redshiftは create_tags）
        tag_call = mock_rs.create_tags.call_args
        assert tag_call[1]["ResourceName"] == arn
        saved = {t["Key"]: t["Value"] for t in tag_call[1]["Tags"]}
        assert saved["tagwatchman:original-sgs"] == "sg-original"

        # 隔離SGに差し替えられたか
        mod_call = mock_rs.modify_cluster.call_args
        assert mod_call[1]["ClusterIdentifier"] == "test-cluster"
        assert mod_call[1]["VpcSecurityGroupIds"] == ["sg-quarantine"]


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
        assert result["isolationStatus"] == "policy_denied"
 
        # ポリシーが設定されているか確認
        policy = s3.get_bucket_policy(Bucket="test-bucket")
        policy_doc = json.loads(policy["Policy"])
        assert policy_doc["Statement"][0]["Effect"] == "Deny"
        assert policy_doc["Statement"][0]["Sid"] == "TagWatchmanQuarantine"
 
        # タグ付与は主要操作のDenyに含まれない（復旧の道を残す）
        quarantine_actions = policy_doc["Statement"][0]["Action"]
        assert "s3:PutBucketTagging" not in quarantine_actions
 
        # 主要操作Denyはlambda-role（restorer）を除外している（復旧操作のため）
        q_cond = policy_doc["Statement"][0]["Condition"]["StringNotLike"]["aws:PrincipalArn"]
        assert "arn:aws:iam::123456789012:role/tagwatchman-lambda-role" in q_cond
 
        # 許可ロール以外のタグ付与を拒否する条件付きDenyが存在する
        tagging_stmt = next(
            s for s in policy_doc["Statement"]
            if s["Sid"] == "TagWatchmanTaggingRestriction"
        )
        assert tagging_stmt["Effect"] == "Deny"
        assert "s3:PutBucketTagging" in tagging_stmt["Action"]
        not_like = tagging_stmt["Condition"]["StringNotLike"]["aws:PrincipalArn"]
        assert "arn:aws:iam::123456789012:role/tagwatchman-operator" in not_like
        assert "arn:aws:iam::123456789012:role/tagwatchman-lambda-role" in not_like


    # 7) 既存タグ（必須タグ等）を隔離時に保持する（put_bucket_tagging 全置換バグの回帰防止）
    @mock_aws
    def test_s3_isolate_preserves_existing_tags(self):
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        region = "ap-northeast-1"
        bucket = "tagwatchman-trace-test"
        arn = "arn:aws:s3:::tagwatchman-trace-test"
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "A1", "Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                 "Action": "s3:GetObject", "Resource": arn + "/*"},
            ],
        })

        s3 = boto3.client("s3", region_name=region)
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": region})
        s3.put_bucket_policy(Bucket=bucket, Policy=policy)
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
            {"Key": "Env", "Value": "test"},
            {"Key": "Project", "Value": "your-project-name"},
            {"Key": "Owned", "Value": "takada"},
        ]})

        isolator._isolate_s3(arn, region)

        def _tags():
            resp = s3.get_bucket_tagging(Bucket=bucket)
            return {t["Key"]: t["Value"] for t in resp["TagSet"]}

        tags = _tags()
        assert tags["Env"] == "test"
        assert tags["Project"] == "your-project-name"
        assert tags["Owned"] == "takada"
        assert tags["tagwatchman:quarantined"] == "true"
        assert "tagwatchman:original-policy-sha256" in tags

        # 再隔離で tagwatchman: 系が重複しない（冪等）
        isolator._isolate_s3(arn, region)
        tags2 = _tags()
        tw_keys = [k for k in tags2 if k.startswith("tagwatchman:")]
        assert len(tw_keys) == len(set(tw_keys))
        assert tags2["Env"] == "test"
 
 
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
 
        arn = "arn:aws:lambda:ap-northeast-1:123456789012:function:test-function"
        event = {**BASE_EVENT, "arn": arn}
 
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "concurrency_zero"
 
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
        assert result["isolationStatus"] == "network_immediate_delete"
 
        # 削除されているか確認
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "internet-gateway-id", "Values": [igw_id]}]
        )
        assert len(igws["InternetGateways"]) == 0
 
    @mock_aws
    def test_igw_attached_notify_only(self):
        """IGW アタッチあり → 通知のみ・正常終了（RuntimeError なし）"""
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
 
        # RuntimeError が発生しないことを確認
        isolator._isolate_igw(arn, "ap-northeast-1")
 
        # IGW が削除されていないことを確認（通知のみなので残っている）
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "internet-gateway-id", "Values": [igw_id]}]
        )
        assert len(igws["InternetGateways"]) == 1
 
 
class TestIsolatorEIP:
 
    @mock_aws
    def test_eip_not_attached_released(self):
        """EIP アタッチなし → 即時解放"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        eip = ec2.allocate_address(Domain="vpc")
        alloc_id = eip["AllocationId"]
 
        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:elastic-ip/{alloc_id}"
        event = {**BASE_EVENT, "arn": arn}
 
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "network_immediate_delete"
 
        # 解放されているか確認
        addresses = ec2.describe_addresses(
            Filters=[{"Name": "allocation-id", "Values": [alloc_id]}]
        )
        assert len(addresses["Addresses"]) == 0
 
    @mock_aws
    def test_eip_attached_notify_only(self):
        """EIP アタッチあり → 通知のみ・正常終了（RuntimeError なし）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")
        subnet_id = subnet["Subnet"]["SubnetId"]
        instance = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet_id)
        instance_id = instance["Instances"][0]["InstanceId"]
 
        eip = ec2.allocate_address(Domain="vpc")
        alloc_id = eip["AllocationId"]
        ec2.associate_address(InstanceId=instance_id, AllocationId=alloc_id)
 
        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:elastic-ip/{alloc_id}"
 
        # RuntimeError が発生しないことを確認
        isolator._isolate_eip(arn, "ap-northeast-1")
 
        # EIP が解放されていないことを確認（通知のみなので残っている）
        addresses = ec2.describe_addresses(
            Filters=[{"Name": "allocation-id", "Values": [alloc_id]}]
        )
        assert len(addresses["Addresses"]) == 1
 
 
class TestIsolatorVPC:
 
    @mock_aws
    def test_vpc_notify_only(self):
        """VPC → 通知のみ・正常終了（RuntimeError なし）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        ec2 = boto3.client("ec2", region_name="ap-northeast-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
 
        arn = f"arn:aws:ec2:ap-northeast-1:123456789012:vpc/{vpc_id}"
        event = {**BASE_EVENT, "arn": arn}
 
        # RuntimeError が発生せず正常終了することを確認
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "notify_only"
 
        # VPC が削除されていないことを確認
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        assert len(vpcs["Vpcs"]) == 1
 
 
class TestIsolatorGlue:
 
    def test_glue_notify_only(self):
        """Glue → 通知のみ・正常終了（RuntimeError なし）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        arn = "arn:aws:glue:ap-northeast-1:123456789012:database/my-database"
        event = {**BASE_EVENT, "arn": arn}
 
        # RuntimeError が発生せず正常終了することを確認
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "notify_only"


class TestIsolatorWorkspaces:

    def test_workspaces_notify_only(self):
        """Workspaces → 通知のみ・正常終了（RuntimeError なし）"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        arn = "arn:aws:workspaces:ap-northeast-1:123456789012:workspace/ws-abc123def"
        event = {**BASE_EVENT, "arn": arn}

        # RuntimeError が発生せず正常終了することを確認
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "notify_only"

    def test_workspaces_mapped_to_notify_only(self):
        """Workspaces ARN が通知のみハンドラに解決される"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        arn = "arn:aws:workspaces:ap-northeast-1:123456789012:workspace/ws-abc123def"
        fn = isolator._find_isolator(arn)
        assert fn is isolator._isolate_workspaces
 
 
class TestIsolatorAPIGateway:
 
    def test_apigateway_stages_deleted_and_tag_saved(self):
        """API Gateway 隔離 → ステージ削除・タグ保存"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        arn = "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
        event = {**BASE_EVENT, "arn": arn}
 
        mock_apigw = MagicMock()
        mock_apigw.get_stages.return_value = {
            "item": [
                {
                    "stageName": "prod",
                    "deploymentId": "dep-123",
                    "variables": {"key": "value"},
                    "description": "production stage",
                }
            ]
        }
 
        with patch("boto3.client", return_value=mock_apigw):
            result = isolator.lambda_handler(event, {})
 
        assert result["isolationStatus"] == "stages_deleted"
 
        # ステージが削除されたか確認
        mock_apigw.delete_stage.assert_called_once_with(
            restApiId="abc123def", stageName="prod"
        )
 
        # タグが保存されたか確認
        tag_call = mock_apigw.tag_resource.call_args
        saved_tags = tag_call[1]["tags"]
        assert saved_tags["tagwatchman:quarantined"] == "true"
        stage_info = json.loads(base64.b64decode(saved_tags["tagwatchman:original-stages"]))
        assert stage_info[0]["stageName"] == "prod"
        assert stage_info[0]["deploymentId"] == "dep-123"
 
    def test_apigateway_no_stages(self):
        """API Gateway ステージなし → タグのみ保存・正常終了"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        arn = "arn:aws:apigateway:ap-northeast-1::/restapis/abc123def"
        event = {**BASE_EVENT, "arn": arn}
 
        mock_apigw = MagicMock()
        mock_apigw.get_stages.return_value = {"item": []}
 
        with patch("boto3.client", return_value=mock_apigw):
            result = isolator.lambda_handler(event, {})
 
        assert result["isolationStatus"] == "stages_deleted"
        mock_apigw.delete_stage.assert_not_called()
        # mock_apigw.delete_stage.assert_not_called() の直後に追加
        saved_tags = mock_apigw.tag_resource.call_args[1]["tags"]
        assert json.loads(base64.b64decode(saved_tags["tagwatchman:original-stages"])) == []
 
 
class TestIsolatorTaggingRestriction:
 
    def test_no_role_arns_skips_restriction(self, monkeypatch):
        """許可ロールARN未設定 → タグ付与制限ステートメントは付かない"""
        monkeypatch.setenv("OPERATOR_ROLE_ARN", "")
        monkeypatch.setenv("LAMBDA_ROLE_ARN", "")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        stmt = isolator._make_tagging_deny_statement(["s3:PutBucketTagging"], "arn:aws:s3:::x")
        assert stmt is None
 
    def test_role_arns_present_builds_restriction(self, monkeypatch):
        """許可ロールARN設定あり → 条件付きDenyを生成"""
        monkeypatch.setenv("OPERATOR_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-operator")
        monkeypatch.setenv("LAMBDA_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        stmt = isolator._make_tagging_deny_statement(["s3:PutBucketTagging"], "arn:aws:s3:::x")
        assert stmt["Effect"] == "Deny"
        assert stmt["Sid"] == "TagWatchmanTaggingRestriction"
        assert len(stmt["Condition"]["StringNotLike"]["aws:PrincipalArn"]) == 2
 
 
class TestIsolatorNoExtractor:
 
    def test_unknown_arn_skipped(self):
        """未対応ARN → スキップ"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
 
        event = {**BASE_EVENT, "arn": "arn:aws:unknown:ap-northeast-1:123456789012:resource/test"}
        result = isolator.lambda_handler(event, {})
        assert result["isolationStatus"] == "skipped"


class TestIsolatorSelfProtection:
    """IAM 自己保全ガード（_is_self_protected_iam と isolator skip 挙動）"""

    def _reload(self, monkeypatch, prefix="tagwatchman-"):
        monkeypatch.setenv("SELF_PROTECT_PREFIX", prefix)
        monkeypatch.setenv("OPERATOR_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-operator")
        monkeypatch.setenv("LAMBDA_ROLE_ARN", "arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)
        return isolator

    # ── 判定ロジック ──
    def test_prefix_match_role(self, monkeypatch):
        iso = self._reload(monkeypatch)
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-operator")
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-sfn-role")
        assert iso._is_self_protected_iam("arn:aws:iam::999999999999:role/tagwatchman-anything")

    def test_prefix_match_user(self, monkeypatch):
        iso = self._reload(monkeypatch)
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:user/tagwatchman-someuser")

    def test_explicit_arn_match_outside_prefix(self, monkeypatch):
        # prefix を外れた別スタック名でも、明示 ARN 一致なら守る
        iso = self._reload(monkeypatch, prefix="otherstack-")
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-operator")

    def test_non_self_role_not_protected(self, monkeypatch):
        iso = self._reload(monkeypatch)
        assert not iso._is_self_protected_iam("arn:aws:iam::123456789012:role/some-customer-role")
        assert not iso._is_self_protected_iam("arn:aws:iam::123456789012:user/customer-user")

    def test_non_iam_arn_passthrough(self, monkeypatch):
        iso = self._reload(monkeypatch)
        assert not iso._is_self_protected_iam("arn:aws:ec2:ap-northeast-1:123456789012:instance/i-abc")
        assert not iso._is_self_protected_iam("arn:aws:s3:::some-bucket")

    def test_empty_prefix_falls_back_to_explicit(self, monkeypatch):
        # SELF_PROTECT_PREFIX 未設定（空）でも明示 ARN は守る／無関係ロールは素通り
        iso = self._reload(monkeypatch, prefix="")
        assert iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-lambda-role")
        assert not iso._is_self_protected_iam("arn:aws:iam::123456789012:role/tagwatchman-sfn-role")

    # ── skip 挙動（剥奪 API を一切呼ばない）──
    def test_isolate_iam_role_skips_self(self, monkeypatch):
        iso = self._reload(monkeypatch)
        from unittest.mock import MagicMock, patch
        mock_iam = MagicMock()
        with patch.object(iso.boto3, "client", return_value=mock_iam):
            iso._isolate_iam_role("arn:aws:iam::123456789012:role/tagwatchman-lambda-role", "ap-northeast-1")
        mock_iam.list_attached_role_policies.assert_not_called()
        mock_iam.detach_role_policy.assert_not_called()
        mock_iam.delete_role_policy.assert_not_called()
        mock_iam.tag_role.assert_not_called()

    def test_isolate_iam_user_skips_self(self, monkeypatch):
        iso = self._reload(monkeypatch)
        from unittest.mock import MagicMock, patch
        mock_iam = MagicMock()
        with patch.object(iso.boto3, "client", return_value=mock_iam):
            iso._isolate_iam_user("arn:aws:iam::123456789012:user/tagwatchman-someuser", "ap-northeast-1")
        mock_iam.list_attached_user_policies.assert_not_called()
        mock_iam.update_access_key.assert_not_called()
        mock_iam.tag_user.assert_not_called()

    def test_isolate_iam_role_proceeds_for_non_self(self, monkeypatch):
        # 非 self は従来通り剥奪が走る（ガードが正常系を壊していないことの担保）
        iso = self._reload(monkeypatch)
        from unittest.mock import MagicMock, patch
        mock_iam = MagicMock()
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        with patch.object(iso.boto3, "client", return_value=mock_iam):
            iso._isolate_iam_role("arn:aws:iam::123456789012:role/some-customer-role", "ap-northeast-1")
        # v33 の lossy 保全（_capture_iam_policies）が剥奪前に list_attached_role_policies を
        # 1回読み、その後の detach ループでもう1回読むため計2回。回数は固定せず「ガードが止めず
        # 剥奪が走った」ことだけ担保する（将来 capture が取得済みリストを再利用しても壊れない）。
        mock_iam.list_attached_role_policies.assert_called()
        mock_iam.tag_role.assert_called_once()


    def test_handler_returns_self_protected_for_self_role(self, monkeypatch):
        """handler 経由：self ロールは isolationStatus=self_protected を返す（剥奪もしない）"""
        iso = self._reload(monkeypatch)
        from unittest.mock import MagicMock, patch
        mock_iam = MagicMock()
        with patch.object(iso.boto3, "client", return_value=mock_iam):
            event = {"arn": "arn:aws:iam::123456789012:role/tagwatchman-lambda-role",
                     "region": "ap-northeast-1"}
            result = iso.lambda_handler(event, {})
        assert result["isolationStatus"] == "self_protected"
        mock_iam.detach_role_policy.assert_not_called()
        mock_iam.tag_role.assert_not_called()


# ─────────────────────────────────────────────────────────────
# パターンE 8サービス notify_only 回帰（v26 追加分）
# E サービスは隔離 API を叩かないため moto 不要。
# 将来 E サービスを追加・変更した際の包括的な回帰網。
# ─────────────────────────────────────────────────────────────

E_SERVICES = [
    ("elasticache",
     "arn:aws:elasticache:ap-northeast-1:123456789012:cluster:my-cache",
     "_isolate_elasticache"),
    ("kinesis",
     "arn:aws:kinesis:ap-northeast-1:123456789012:stream/my-stream",
     "_isolate_kinesis"),
    ("stepfunctions",
     "arn:aws:states:ap-northeast-1:123456789012:stateMachine:my-sm",
     "_isolate_stepfunctions"),
    ("vpc",
     "arn:aws:ec2:ap-northeast-1:123456789012:vpc/vpc-12345678",
     "_isolate_vpc"),
    ("glue",
     "arn:aws:glue:ap-northeast-1:123456789012:database/my-database",
     "_isolate_glue"),
    ("workspaces",
     "arn:aws:workspaces:ap-northeast-1:123456789012:workspace/ws-abc123def",
     "_isolate_workspaces"),
    ("secretsmanager",
     "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:tw-probe-AbC123",
     "_isolate_secretsmanager"),
    ("cloudfront",
     "arn:aws:cloudfront::123456789012:distribution/E383RYYP0LWN8U",
     "_isolate_cloudfront"),
]


class TestIsolatorNotifyOnlyRegression:

    @pytest.mark.parametrize("name,arn,fn_name",
                             E_SERVICES, ids=[s[0] for s in E_SERVICES])
    def test_e_service_resolves_and_returns_notify_only(self, name, arn, fn_name):
        """E サービスの ARN が専用ハンドラに解決され、handler が notify_only を返す"""
        import importlib
        import isolator.index as isolator
        importlib.reload(isolator)

        # ① ルーティング解決の回帰
        fn = isolator._find_isolator(arn)
        assert fn is getattr(isolator, fn_name), (
            f"{name}: {arn} が {fn_name} に解決されない")

        # ② handler 経由で notify_only が返る（隔離 API は叩かない）
        result = isolator.lambda_handler({**BASE_EVENT, "arn": arn}, {})
        assert result["isolationStatus"] == "notify_only"
