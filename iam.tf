##########################################
#  IAM configurations for ClodTrail S3   #
##########################################

# Data blocks
data "aws_organizations_organization" "current" {}

data "aws_iam_policy_document" "cloudtrail-s3" {
  statement {
    sid = "AWSCloudTrailAclCheck20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail-logging.arn]
    condition {
      test     = "StringEquals"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"]
      variable = "AWS:SourceArn"
    }
  }
  statement {
    sid = "AWSCloudTrailWrite20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    resources = concat(
      ["${aws_s3_bucket.cloudtrail-logging.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"],
      var.organization ? ["${aws_s3_bucket.cloudtrail-logging.arn}/AWSLogs/${data.aws_organizations_organization.current.id}/*"] : [],
    )
    condition {
      test     = "StringEquals"
      values   = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
    condition {
      test     = "StringEquals"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"]
      variable = "AWS:SourceArn"
    }
  }
  statement {
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
    effect    = "Deny"
    actions   = ["*"]
    resources = ["${aws_s3_bucket.cloudtrail-logging.arn}/*"]
    condition {
      test     = "Bool"
      values   = [false]
      variable = "aws:SecureTransport"
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_role_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["cloudtrail.amazonaws.com"]
      type        = "Service"
    }
  }
}
##########################################
#  IAM Roles                             #
##########################################

# Cloudwatch Role
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name               = var.cloudtrail_iam_role_name
  path               = "/service-role/"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_role_assume_policy.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_role_policy" {
  name   = var.cloudtrail_iam_role_name
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
  role   = aws_iam_role.cloudtrail_cloudwatch_role.id
}

# IAM bucket policy
resource "aws_s3_bucket_policy" "cloudtrail-s3" {
  bucket = aws_s3_bucket.cloudtrail-logging.id
  policy = data.aws_iam_policy_document.cloudtrail-s3.json
}