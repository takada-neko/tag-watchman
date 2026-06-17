**English** | [日本語](README.md)

# 🔒 TagWatchman — Real-Time AWS Untagged Resource Auto-Isolator

**Detect, quarantine, and delete untagged AWS resources in real time — tag governance and tag compliance *without* AWS Organizations or SCPs. Open source, deploy via CloudFormation / SAM.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/deploy-CloudFormation%20%2F%20SAM-orange)](https://console.aws.amazon.com/cloudformation)
[![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900?logo=amazonaws&logoColor=white)]()
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)]()

---

**TagWatchman** is an open-source, serverless, agent-style AWS tag-enforcement tool. It watches resource-creation events through **EventBridge** and **CloudTrail**, checks them against your required-tag policy, and **quarantines untagged resources within seconds** — then deletes them after a grace period if they are never tagged. It brings **tag-based governance and cost control** to individuals, startups, and small teams who don't want (or can't use) AWS Organizations and Service Control Policies (SCPs).

---

## Why TagWatchman?

On AWS, resources are easy to create — which means **"resources nobody knows the owner or purpose of"** quietly pile up before you notice.

- An EC2 instance spun up by someone who has since left the team is still running.
- A throwaway RDS instance created for testing is still sitting in your production account.
- Unmanaged resources turn into cost, operational, and security risks.

Defining tag rules is easy, but without enforcement — *"if you forget a tag, the resource simply won't work"* — governance tends to erode in practice. AWS Organizations and SCPs can enforce this at the org level, but they are **overkill for individuals, startups, and small teams**.

TagWatchman delivers **tag-based governance without SCPs**. It effectively makes tagging mandatory, and as a side effect neutralizes unmanaged resources — reducing your security exposure along the way.

---

## Features

|  | TagWatchman | Typical OSS tools |
|---|---|---|
| Detection | ✅ Real-time (EventBridge) | ❌ Scheduled scans (hours of delay) |
| Service coverage | ✅ 20+ major AWS services | ❌ EC2 / RDS only |
| Quarantine phase | ✅ Yes — operations blocked immediately **(exceptions apply※)** | ❌ None (notify, or delete outright) |
| Human approval | ✅ One-click approval by email | ❌ None |
| Deployment | ✅ IaC deploy (SAM-ready) | ❌ Complex CLI steps |

※ For some AWS services, TagWatchman uses an approach other than network isolation, for technical or security reasons.

👉 [See per-resource behavior in detail](docs/resource_behavior.md)

---

## How It Works

### Standard flow (under-tagged resources)

```
① Resource created (EC2 / RDS / S3 / Lambda, etc.)
        ↓ Real-time detection (within seconds)
② Required-tag check
        ↓ Tags missing
③ Immediate quarantine (operations blocked) + Email ① notification
        ↓ 7-day grace period
        ├─ Tags added (via operator role) → auto-recovery, deletion cancelled ✅
        └─ Still untagged → Email ② (deletion-approval request)
                ↓ Click the approval URL
④ Resource deleted
```

### CloudTrail-specific flow

```
CloudTrail disabled / deleted / reconfigured is detected
        ↓ Fires immediately, regardless of tags
StopLogging       → Auto re-enable + 🚨 CRITICAL alert email
DeleteTrail       → 🚨 CRITICAL alert email (manual re-creation required)
UpdateTrail       → ⚠️ WARNING alert email
PutEventSelectors → ⚠️ WARNING alert email
```

> **⚠️ Adding the required tags cancels deletion.**
> Even on a false positive, you're safe as long as you tag the resource within the grace period.

### Supported AWS services

For every service, "quarantine" means **denying data read/write and major operations while still allowing the operations needed to recover** (such as adding tags). The design renders a resource *"unable to cause harm"* while leaving a clear path back.

| Category | Services | Quarantine method | Recovery |
|---|---|---|---|
| Compute | EC2, Lambda, ECS, EKS | Swap security group to deny-all / set reserved concurrency to 0 | Auto-recovery on tagging |
| Database | RDS, DynamoDB, Redshift | Swap SG to deny-all / deny major operations via resource policy | Auto-recovery on tagging |
| Storage | S3, ECR | Deny major operations via bucket / repository policy | Auto-recovery on tagging |
| Messaging | SQS, SNS | Deny major operations via policy | Auto-recovery on tagging |
| Analytics | OpenSearch | Deny major operations via access policy | Auto-recovery on tagging |
| Networking | IGW, NAT Gateway, VPC Peering, Elastic IP | **Conditional immediate deletion ※1** | — |
| Notify only | VPC, Glue, ElastiCache, Workspaces, Kinesis, Step Functions, Secrets Manager, CloudFront | **Notify only (no quarantine / deletion) ※2** | — |
| Identity | IAM Role, IAM User | **Detach all policies & deactivate access keys ※3** | Tagging removes the quarantine tag (re-attaching policies is manual) |
| API | API Gateway | Disable the endpoint by deleting the stage | Auto-recovery on tagging |
| Audit | CloudTrail | Dedicated flow (auto re-enable) | — |

**Out of scope:** Transit Gateway / Direct Connect (excluded because they involve physical connectivity and core networking).

> **※ Recovery for services quarantined via resource policy (S3 / DynamoDB / SQS / SNS / ECR / OpenSearch)**
> Adding tags lifts the quarantine and the resource becomes usable again. However, if you had set a **custom resource policy before quarantine, that original policy is not restored automatically** (quarantine replaces it with a deny policy). The full text of the original policy is included in the detection email, so re-apply it manually if needed. Resources that had no custom policy simply return to their original state.

> **※ Detecting IAM Role / IAM User / CloudFront requires the global event-forwarding stack (us-east-1) from Quick Start step 2.**

👉 [See per-resource behavior in detail](docs/resource_behavior.md)

**※1 Networking (conditional immediate deletion) behavior**

- IGW: not attached → immediate delete / attached → notify only
- NAT Gateway / VPC Peering: immediate delete
- Elastic IP: not associated → immediate release / associated → notify only

**※2 Why these are notify-only**

- VPC: deleting it would cut off communication for every resource inside — too broad an impact to automate.
- ElastiCache: due to how state is reflected, network isolation can't be applied reliably, so notify-only.
- Glue: its resource policy applies to the entire Data Catalog, so per-database quarantine isn't possible.
- Kinesis / Step Functions: AWS's resource-policy model can't express a deny-all quarantine, so notify-only.
- Secrets Manager / CloudFront: stopping a secret or a distribution is too impactful, so notify-only.
- Workspaces: network isolation doesn't fit this service, so notify-only.

**※3 IAM resource behavior**

- Policy detachment and key deactivation happen automatically.
- Recovery (re-attaching policies, recreating keys) **must be done manually by a human**.
- The email notification clearly states that manual action is required.

---

## Recovering Quarantined Resources (Operator Role)

A quarantined resource **recovers automatically once you add the required tags**. But if *anyone* could add tags, an attacker could simply tag their own resource to lift the quarantine. To prevent this, tagging is allowed **only through a dedicated operator role** (`tagwatchman-operator`).

```
Regular users / administrators        → tagging quarantined resources is denied
Switch role to tagwatchman-operator   → tagging is allowed (= the recovery trigger)
```

You decide who can assume this role via the `TrustedPrincipals` parameter at deploy time (multiple principals allowed).

**Example recovery procedure (CLI)**

```bash
# 1. Switch to the operator role
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/tagwatchman-operator \
  --role-session-name tag-restore \
  --query 'Credentials' --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo $CREDS | python3 -c "import sys,json;print(json.load(sys.stdin)['SessionToken'])")

# 2. Add the required tags (example: an S3 bucket)
aws s3api put-bucket-tagging --bucket <BUCKET_NAME> \
  --tagging 'TagSet=[{Key=Env,Value=prod},{Key=Project,Value=your-project},{Key=Owned,Value=your-team}]'

# 3. Return to your original permissions
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

Once the tags are applied, TagWatchman automatically lifts the quarantine.

> **Note:** Tag-add restriction is strictly enforced for resource-policy services (S3 / DynamoDB / SQS / SNS / ECR / OpenSearch). For services quarantined by swapping the security group (EC2 / RDS, etc.), tag-add is governed by IAM, so we recommend tightening tag-add permissions operationally.

---

## Quick Start

### Prerequisites

- AWS CLI / AWS SAM CLI configured (CloudShell works too)
- CloudTrail enabled (if not, see [here](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html))
- The ARN of the IAM entity that will use the `tagwatchman-operator` role

### 1. Deploy (main stack)

```bash
sam build
sam deploy --guided --capabilities CAPABILITY_NAMED_IAM
```

> **💡 `--capabilities CAPABILITY_NAMED_IAM` is required.**
> TagWatchman creates named IAM roles (such as `tagwatchman-operator`), so deployment fails without it.

Example parameters:

```
Stack Name: tagwatchman
NotificationEmail: your@email.com        # Recipient for notification / approval emails
RequiredTags: Env,Project,Owned          # Required tag keys (comma-separated)
TagAllowedValues: Env:prod|stg|test,Project:your-project-name  # Replace your-project-name with your own project name
TagMatchMode: Env:exact,Project:prefix   # Env = exact match / Project = prefix match
DeleteDelaySeconds: 604800               # Grace period (default 7 days = 604800 seconds)
DryRun: true                             # Always start with true to verify behavior
TrustedPrincipals: arn:aws:iam::123456789012:role/Admin  # ARN(s) allowed to use the operator role (comma-separated)
OperatorAllowedCidr:                     # Optional. Restrict the operator role's source IP (e.g. 203.0.113.0/24). Blank = no restriction
```

> **💡 `TrustedPrincipals` lists the ARNs of people who can tag (= recover) quarantined resources.**
> Find your own ARN with `aws sts get-caller-identity`. If it looks like `assumed-role/Admin/xxx`, specify the base role `arn:aws:iam::<ACCOUNT_ID>:role/Admin`.

> **💡 Replace `your-project-name` with your own project name.**
> With `Project:my-api`, prefix matches like `my-api`, `my-api-v2`, and `my-api-batch` are all accepted.

### 2. Deploy (global event-forwarding stack)

IAM Role / IAM User / CloudFront are AWS global services, so their creation events are delivered only to us-east-1. To detect them, deploy a lightweight forwarding stack in us-east-1 (an EventBridge rule only — no extra cost).

```bash
cd global-events
sam build
sam deploy --region us-east-1 --stack-name tagwatchman-global-events \
  --capabilities CAPABILITY_NAMED_IAM --resolve-s3
cd ..
```

> **💡 If you deployed the main stack to a region other than ap-northeast-1**, add `--parameter-overrides CoreRegion=<your main stack's region>`.

### 3. Verify (DryRun)

With `DryRun: true`, create an untagged resource and confirm that the email notification arrives.

### 4. Go live

```bash
sam deploy --parameter-overrides DryRun=false
```

---

## Uninstall (Delete the Stacks)

```bash
sam delete --stack-name tagwatchman
sam delete --stack-name tagwatchman-global-events --region us-east-1
```

> **💡 Stop any running Step Functions executions before deleting.**
> If state machines are still running (quarantined and waiting out the grace period), stack deletion can stall. Stop those executions from the Step Functions console first, then delete.

---

## Configuration

Tag **matching rules** (required tags, allowed values, match mode) can be changed from **AWS Systems Manager Parameter Store** — applied instantly, no redeploy required.

| Parameter | Default | Description |
|---|---|---|
| `/tagwatchman/required-tags` | `Env,Project,Owned` | Required tag keys (comma-separated) |
| `/tagwatchman/tag-allowed-values` | `Env:prod\|stg\|test,Project:your-project-name` | Allowed values per key (`\|`-separated) |
| `/tagwatchman/tag-match-mode` | `Env:exact,Project:prefix` | Match mode (`exact` = exact match / `prefix` = prefix match) |

> **💡 DryRun and the grace period are deploy parameters (they cannot be changed in Parameter Store).**
> `DryRun` and `DeleteDelaySeconds` are CloudFormation parameters (Lambda environment variables). Changing them requires a redeploy:
> ```bash
> sam deploy --parameter-overrides DryRun=false DeleteDelaySeconds=604800
> ```

> More practical guidance — how to think about tag design, how to choose allowed values, and so on — is provided in the upgraded-edition documentation.

---

## Architecture

<img height="800" alt="TagWatchman architecture: EventBridge and CloudTrail trigger a Step Functions workflow of Lambda functions that detect, quarantine, await approval, and delete untagged AWS resources" src="https://github.com/user-attachments/assets/0c03b2e1-b968-4ba9-b907-f2ace73e7efc" />

> The forwarding stack (us-east-1) for global services such as IAM and CloudFront is omitted from the diagram.

## Running Cost

TagWatchman itself costs almost nothing to run on AWS.

| Service | Approx. monthly |
|---|---|
| Lambda (8 functions) | $0+ |
| Step Functions | $0+ |
| EventBridge | $0+ |
| SNS | $0+ |
| API Gateway | $0+ |
| **CloudTrail** | **$2+ if not already set up** |

> If CloudTrail is already enabled in your account, you can adopt TagWatchman at **zero additional cost**.

## Editions & Pricing

TagWatchman's core is **open source (Apache License 2.0)** and free. Deploy and modify it however you like.

There's also an **optional, paid upgraded edition** that helps you adopt it in production more practically. The upgraded edition is **not required** to use the core.

| Plan | Contents | Price |
|---|---|---|
| Core (OSS) | The full agent and everything in this repo | **Free** |
| Upgraded edition | Detailed tag-design guide + IaC template set | [¥2,500 (tax incl.)](https://buy.stripe.com/9B67sN0Js1zKe5M0ro3ZK01) |

> The upgraded edition collects operational know-how that's hard to judge from the core alone — how to decide your own tag design, how to safely roll out into an existing environment, and more.
> You can purchase it via the link above. ⭐ Stars are appreciated too!

---

## FAQ

**Q. What value should I put in the `Owned` tag?**
A. Any value works, but we recommend a team name (`backend`, `infra`, etc.) over a personal name (`Takada`). Using a team name means you don't have to update tags when members join or move. Only an empty string counts as a violation.

**Q. Why can't normal admin permissions tag a quarantined resource?**
A. Because if anyone could tag it, an attacker could lift their own quarantine by self-tagging. Tagging is restricted to the `tagwatchman-operator` role, and you limit who can assume that role via `TrustedPrincipals` — keeping recovery in trusted hands only.

**Q. Where do I change the allowed tag values?**
A. Update `/tagwatchman/tag-allowed-values` in AWS Systems Manager Parameter Store. Changes take effect immediately, no redeploy needed.

**Q. What if I'm late adding tags?**
A. As long as it's within 7 days of quarantine, adding the tags cancels deletion automatically. We also recommend verifying with `DryRun: true` first.

**Q. Are my properly tagged, managed resources affected?**
A. Not at all. TagWatchman only acts on *missing tags*. A tagged resource is treated as a managed resource and is never quarantined or deleted.

**Q. If an IGW is tagged but attached, will it be deleted?**
A. If it's tagged, it's never quarantined or deleted. If it's under-tagged *and* attached, you only get a notification — no auto-deletion — and you handle it manually.

**Q. If an IAM resource is quarantined, does it recover automatically?**
A. Adding tags removes the quarantine tag automatically, but re-attaching the detached policies and recreating access keys must be done by a human. The email notification includes guidance.

**Q. What happens to unsupported services?**
A. They are out of scope for detection and quarantine (the resource keeps working as-is).

---

## Roadmap

- [ ] Scheduled scan notifications for existing resources (optional)
- [ ] Slack notifications
- [ ] Approval dashboard
- [ ] Multi-region support
- [ ] HTTP API (API Gateway v2) support
- [ ] More advanced operator-role IP restriction

---

## Keywords

> open source · AWS tag governance · tag compliance · tag enforcement · tag policy without SCP · untagged resource detection · AWS resource quarantine · cloud governance · FinOps · AWS cost optimization · AWS security automation · serverless · AWS Step Functions · Amazon EventBridge · AWS CloudTrail · AWS CloudFormation · AWS SAM · DevOps

---

## License

This software is released under the [Apache License 2.0](LICENSE).

Copyright © 2026 takada-neko
