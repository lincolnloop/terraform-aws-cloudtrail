##########################################
#  Data configurations for the module    #
##########################################
data "aws_caller_identity" "current" {}
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

data "aws_iam_policy_document" "aws_cloudtrail_sns" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.cloudtrail.arn]
  }
}

##########################################
#   KMS and encryption resources         # 
##########################################

resource "aws_kms_key" "cloudtrail" {
  description             = var.description
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cloudtrail_key_policy.json
  tags                    = var.cloudtrail_config.tags
}

resource "aws_kms_alias" "cloudtrail" {
  target_key_id = aws_kms_key.cloudtrail.arn
  name          = "alias/cloudtrail"
}

##########################################
#   CloudTrail Resources                 #  
##########################################

resource "aws_cloudtrail" "this" {
  name                       = var.name
  s3_bucket_name             = aws_s3_bucket.cloudtrail-logging.bucket
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn
  kms_key_id                 = aws_kms_key.cloudtrail.arn
  enable_log_file_validation = true
  is_multi_region_trail      = true
  tags                       = var.cloudtrail_config.tags
  depends_on                 = [aws_s3_bucket_policy.cloudtrail-s3]
}