##########################################
#  Data configurations for the module    #
##########################################

data "aws_iam_policy_document" "cloudtrail_cloudwatch" {
  statement {
    sid       = "AWSCloudTrailC"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail.name}:log-stream:*"]
  }
}

data "aws_iam_policy_document" "cloudtrail_key_policy" {
  policy_id = "Key policy created by CloudTrail"

  statement {
    sid = "Enable IAM User Permissions"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "Allow CloudTrail to encrypt logs"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid = "Allow CloudTrail to describe key"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  statement {
    sid = "Allow principals in the account to decrypt log files"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid = "Allow alias creation during setup"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.us-east-1.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid = "Enable cross account log decryption"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }
}

##########################################
#  IAM configurations for ClodTrail S3   #
##########################################

module "cloudtrail_cloudwatch_role" {
  source      = "./modules/iam_service_role"
  name        = "Cloudtrail"
  services    = ["cloudtrail.amazonaws.com"]
  policy_json = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
  tags        = local.cloudtrail.tags
}

data "aws_iam_policy_document" "cloudtrail-s3" {
  statement {
    sid = "AWSCloudTrailAclCheck20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }
  statement {
    sid = "AWSCloudTrailWrite20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      values   = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
  }
  statement {
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
    effect    = "Deny"
    actions   = ["*"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]
    condition {
      test     = "Bool"
      values   = [false]
      variable = "aws:SecureTransport"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail-s3" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail-s3.json
}

##########################################
#   S3 configurations for CloudTrail     #  
##########################################

resource "aws_s3_bucket" "cloudtrail-logging" {
  bucket = "${var.s3_prefix}aws-cloudtrail-logging"
  acl    = "log-delivery-write"

  versioning {
    # Requires root AWS access
    # mfa_delete = true
    enabled = true
  }

  lifecycle_rule {
    id      = "Delete previous after 35 days"
    prefix  = ""
    enabled = true

    noncurrent_version_expiration {
      days = "35"
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = local.cloudtrail.tags
}

resource "aws_s3_bucket_public_access_block" "cloudtrail-logging" {
  bucket                  = aws_s3_bucket.cloudtrail-logging.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail-logging" {
  bucket = aws_s3_bucket.cloudtrail-logging.bucket
  policy = <<-EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "*",
                "Resource": "${aws_s3_bucket.cloudtrail-logging.arn}/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }
        ]
    }
    EOF
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.s3_prefix}aws-cloudtrail"
  acl    = "private"
  logging {
    target_bucket = aws_s3_bucket.cloudtrail-logging.bucket
  }
  versioning {
    # Requires root AWS access
    # mfa_delete = true
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "Delete previous after 35 days"
    prefix  = ""
    enabled = true

    noncurrent_version_expiration {
      days = "35"
    }
  }
  tags = local.cloudtrail.tags
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

##########################################
#   CloudWatch resources                 #  
##########################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudtrail"
  retention_in_days = 1
  tags              = local.cloudtrail.tags
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail" {
  for_each       = local.cloudtrail.alarms
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  name           = each.key
  pattern        = each.value.pattern
  metric_transformation {
    name      = each.key
    namespace = "LogMetrics"
    value     = 1
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail" {
  for_each            = local.cloudtrail.alarms
  alarm_name          = each.key
  alarm_description   = each.value.description
  period              = 3600
  statistic           = "Maximum"
  namespace           = "LogMetrics"
  metric_name         = each.key
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = lookup(each.value, "threshold", 0)
  alarm_actions       = [aws_sns_topic.aws_chatbot.arn]
  tags                = local.cloudtrail.tags
}

##########################################
#   KMS and encryption resources         # 
##########################################

resource "aws_kms_key" "cloudtrail" {
  description             = "Cloudtrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cloudtrail_key_policy.json
  tags                    = local.cloudtrail.tags
}

resource "aws_kms_alias" "cloudtrail" {
  target_key_id = aws_kms_key.cloudtrail.arn
  name          = "alias/cloudtrail"
}

##########################################
#   CloudTrail Resources                 #  
##########################################

resource "aws_cloudtrail" "this" {
  name                       = "cloudtrail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail.bucket
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = module.cloudtrail_cloudwatch_role.arn
  kms_key_id                 = aws_kms_key.cloudtrail.arn
  enable_log_file_validation = true
  is_multi_region_trail      = true
  tags                       = local.cloudtrail.tags
  depends_on                 = [aws_s3_bucket_policy.cloudtrail-s3]
}