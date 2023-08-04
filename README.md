# Terraform AWS CloudTrail Module

This module creates an AWS CloudTrail trail and the necessary AWS resources to support logging and monitoring AWS account activity.

## Features

- AWS CloudTrail creation: This module creates a CloudTrail trail that logs API activity in your AWS account.
- S3 bucket creation: The module creates an S3 bucket to store the CloudTrail logs.
- Encryption: Logs stored in the S3 bucket are encrypted using AWS Key Management Service (AWS KMS).

## Usage

```hcl
module "cloudtrail" {
  source                       = "github.com/lincolnloop/terraform-aws-cloudtrail.git"
  name                         = "cloudtrail"
  description                  = "Cloudtrail"
  cloudwatch_log_group_name    = "/aws/cloudtrail"
  cloudwatch_retention_in_days = 1
  cloudtrail_iam_role_name     = "CloudWatchRole"
  s3_prefix                    = "cloudtrail"
  tags                         = var.tags
}

```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| tags | Configuration for CloudTrail alarms and tags. | `object` | Review next section for default value | yes |
| cloudtrail_iam_role_name | IAM Role name for CloudTrail Role. | `string` | `CloudTrail` | no |
| cloudwatch_log_group_name | Name for the CloudWatch log group that will contain the cloudtrail logs. | `string` | `/aws/cloudtrail` | no |
| cloudwatch_retention_in_days | Cloudwatch log group retention specified in days. | `number` | `1` | no |
| description | Description for the cloud trail group and new policy group. | `string` | `cloudtrail` | yes |
| name | Name for the cloudtrail group configuration and new policy group. | `string` | `cloudtrail` | no |
| s3_prefix | S3 naming and configuration prefix. | `string` | n/a | yes |
| organization | Set the `is_organization_trail` flag on the trail. | `bool` | `false` | no |

### Variable `tags`

This input variable controls the tags that will be added to all the resources.
```
  cloudtrail_tags = {
    Application = "cloudtrail"
  }
```

Default value is shown here

## Outputs

| Name | Description |
|------|-------------|
| cloudtrail_arn | The ARN of the CloudTrail trail. |
| s3_bucket_arn | The ARN of the CloudTrail S3 bucket. |
| cloudwatch_log_group_arn | The ARN of the Cloudwatch log group. |


## Requirements

- Terraform 1.4 or newer
- AWS Provider 4.67 or newer
