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
  tags = var.cloudtrail_config.tags
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
  tags = var.cloudtrail_config.tags
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}