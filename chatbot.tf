resource "aws_sns_topic" "aws_chatbot" {
  name              = var.chatbot_sns_topic_name
  kms_master_key_id = var.chatbot_kms_master_key_name
  tags              = var.cloudtrail_config.tags
}

resource "aws_sns_topic_policy" "aws_chatbot" {
  arn    = aws_sns_topic.aws_chatbot.arn
  policy = data.aws_iam_policy_document.aws_chatbot_sns.json
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name          = "GuardDuty"
  event_pattern = jsonencode({ source : ["aws.guardduty"] })
  tags          = var.cloudtrail_config.tags
}

resource "aws_cloudwatch_event_target" "guardduty" {
  arn  = aws_sns_topic.aws_chatbot.arn
  rule = aws_cloudwatch_event_rule.guardduty.name
}
