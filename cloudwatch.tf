##########################################
#   SNS resources                        #  
##########################################
resource "aws_sns_topic" "cloudtrail" {
  name              = var.cloudtrail_sns_topic_name
  kms_master_key_id = aws_kms_key.cloudtrail.arn
  tags              = var.cloudtrail_tags
}

resource "aws_sns_topic_policy" "cloudtrail" {
  arn    = aws_sns_topic.cloudtrail.arn
  policy = data.aws_iam_policy_document.aws_cloudtrail_sns.json
}

##########################################
#   CloudWatch resources                 #  
##########################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = var.cloudwatch_log_group_name
  retention_in_days = var.cloudwatch_retention_in_days
  tags              = var.cloudtrail_tags
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail" {
  for_each       = var.cloudtrail_alarms
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
  for_each            = var.cloudtrail_alarms
  alarm_name          = each.key
  alarm_description   = each.value.description
  period              = 3600
  statistic           = "Maximum"
  namespace           = "LogMetrics"
  metric_name         = each.key
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = lookup(each.value, "threshold", 0)
  alarm_actions       = [aws_sns_topic.cloudtrail.arn]
  tags                = var.cloudtrail_tags
}