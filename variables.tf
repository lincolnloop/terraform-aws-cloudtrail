variable "tags" {
  description = "Tags configuration for CloudTrail"
  type        = map(string)
  default = {
    Application = "cloudtrail"
  }
}

variable "cloudtrail_iam_role_name" {
  type        = string
  description = "IAM Role name for CloudTrail Role"
  default     = "CloudTrail"
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
variable "description" {
  type        = string
  description = "Description for the cloud trail group and new policy group"
  default     = "CloudTrail logs"
}
variable "name" {
  type        = string
  description = "Name for the cloudtrail group configuration and new policy group"
  default     = "cloudtrail"
}
variable "s3_prefix" {
  type        = string
  description = "S3 naming and configuration prefix"
}