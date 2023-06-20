##########################################
#   CloudWatch resources                 #  
##########################################



resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = var.cloudwatch_log_group_name
  retention_in_days = var.cloudwatch_retention_in_days
  tags              = var.cloudtrail_config.tags
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail" {
  for_each       = var.cloudtrail_config.alarms
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
  for_each            = var.cloudtrail_config.alarms
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
  tags                = var.cloudtrail_config.tags
}