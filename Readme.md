
```markdown
# Terraform AWS CloudTrail Module

This module creates an AWS CloudTrail trail and the necessary AWS resources to support logging and monitoring AWS account activity.

## Features

- AWS CloudTrail creation: This module creates a CloudTrail trail that logs API activity in your AWS account.
- S3 bucket creation: The module creates an S3 bucket to store the CloudTrail logs.
- Encryption: Logs stored in the S3 bucket are encrypted using AWS Key Management Service (AWS KMS).

## Usage

```hcl
module "cloudtrail" {
  source = "github.com/your_org/aws_cloudtrail"

  trail_name         = "my_trail"
  s3_bucket_name     = "my_bucket"
  enable_log_file_validation = true
  is_multi_region_trail = true
  enable_logging = true
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| trail_name | The name of the trail. | `string` | n/a | yes |
| s3_bucket_name | The name of the S3 bucket where the CloudTrail logs will be stored. | `string` | n/a | yes |
| enable_log_file_validation | Specifies whether log file integrity validation is enabled. | `bool` | `false` | no |
| is_multi_region_trail | Specifies whether the trail is applied to all regions or the current region. | `bool` | `false` | no |
| enable_logging | Specifies whether the trail is publishing events to CloudWatch Logs. | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| cloudtrail_arn | The ARN of the CloudTrail trail. |
| s3_bucket_id | The ID of the S3 bucket. |

## Requirements

- Terraform 0.14 or newer
- AWS Provider 3.0 or newer

## License
