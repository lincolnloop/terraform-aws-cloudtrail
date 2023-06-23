##########################################
#  IAM configurations for ClodTrail S3   #
##########################################

module "cloudtrail_cloudwatch_role" {
  source      = "./modules/iam_service_role"
  name        = var.cloudtrail_iam_role_name
  services    = ["cloudtrail.amazonaws.com"]
  policy_json = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
  tags        = var.cloudtrail_config.tags
}
module "aws_chatbot_role" {
  source              = "./modules/iam_service_role"
  name                = var.chatbot_iam_role_name
  services            = ["chatbot.amazonaws.com"]
  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  policy_json         = data.aws_iam_policy_document.aws_chatbot.json
  tags                = var.cloudtrail_config.tags
}
data "aws_iam_policy_document" "cloudtrail-s3" {
  statement {
    sid = "AWSCloudTrailAclCheck20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail-logging.arn]
  }
  statement {
    sid = "AWSCloudTrailWrite20150319"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail-logging.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
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
    resources = ["${aws_s3_bucket.cloudtrail-logging.arn}/*"]
    condition {
      test     = "Bool"
      values   = [false]
      variable = "aws:SecureTransport"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail-s3" {
  bucket = aws_s3_bucket.cloudtrail-logging.id
  policy = data.aws_iam_policy_document.cloudtrail-s3.json
}