##########################################
#   S3 configurations for CloudTrail     #  
##########################################

resource "aws_s3_bucket" "cloudtrail-logging" {
  bucket = "${var.s3_prefix}-aws-cloudtrail"
  tags   = var.cloudtrail_config.tags
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail-logging" {
  bucket = aws_s3_bucket.cloudtrail-logging.id
  rule {
    object_ownership = "ObjectWriter"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail-logging" {
  bucket = aws_s3_bucket.cloudtrail-logging.bucket
  rule {
    apply_server_side_encryption_by_default {
      # AES256 is the only supported option for bucket logging
      # https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html#server-access-logging-overview
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "cloudtrail-logging" {
  bucket = aws_s3_bucket.cloudtrail-logging.bucket
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail-logging" {
  bucket = aws_s3_bucket.cloudtrail-logging.bucket
  rule {
    id     = "Delete previous after 35 days"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = "35"
    }
  }
}