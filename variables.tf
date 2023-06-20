variable "cloudtrail_config" {
  description = "Configuration for CloudTrail alarms and tags"
  type = object({
    tags = map(string)
    alarms = map(object({
      description = string
      pattern = string
      threshold = optional(number)
    }))
  })
  default = {}
}
variable "cloudwatch_log_group_name" {
  type = string
  description = "Name for the CloudWatch log group that will contain the cloudtrail logs"
  default = "/cloudtrail"
}
variable "cloudwatch_retention_in_days" {
  type = number
  description = "Cloudwatch log group retention specified in days"
  default = 1
}
variable "name" {
  type        = string
  description = "Name for the cloudtrail group configuration and new policy group"
}
variable "description" {
  type        = string
  description = "Description for the cloud trail group and new policy group"
}
variable "iam_role_name" {
  type        = string
  description = "IAM Role name for CloudTrail Role"
  default     = "CloudTrail"
}
variable "s3_prefix" {
  type        = string
  description = "S3 naming and configuration prefix"
}