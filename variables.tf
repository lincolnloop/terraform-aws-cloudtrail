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
  default = {
    tags = {
      Application = "cloudtrail"
    }
    alarms = {
      "CIS-3.1-UnauthorizedAPICalls" = {
        description = "3.1 - Ensure a log metric filter and alarm exist for unauthorized API calls "
        pattern     = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"
        threshold   = 5
      }
      "CIS-3.2-ConsoleSigninWithoutMFA" = {
        description = "3.2 - Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA "
        pattern     = "{($.eventName=\"ConsoleLogin\") && ($.additionalEventData.MFAUsed !=\"Yes\")}"
      }
      "CIS-3.3-RootAccountUsage" = {
        description = "3.3 - Ensure a log metric filter and alarm exist for usage of \"root\" account"
        pattern     = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"
      }
      "CIS-3.4-IAMPolicyChanges" = {
        description = "3.4 - Ensure a log metric filter and alarm exist for IAM policy changes"
        pattern     = "{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}"
      }
      "CIS-3.5-CloudTrailChanges" = {
        description = "3.5 - Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
        pattern     = "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"
      }
      "CIS-3.6-ConsoleAuthenticationFailure" = {
        description = "3.6 - Ensure a log metric filter and alarm exist for AWS Management Console authentication failures"
        pattern     = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"
        threshold   = 5
      }
      "CIS-3.7-DisableOrDeleteCMK" = {
        description = "3.7 - Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs"
        pattern     = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}"
      }
      "CIS-3.8-S3BucketPolicyChanges" = {
        description = "3.8 - Ensure a log metric filter and alarm exist for S3 bucket policy changes"
        pattern     = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"
      }
      "CIS-3.9-AWSConfigChanges" = {
        description = "3.9 - Ensure a log metric filter and alarm exist for AWS Config configuration changes"
        pattern     = "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}"
      }
      "CIS-3.10-SecurityGroupChanges" = {
        description = "3.10 - Ensure a log metric filter and alarm exist for security group changes"
        pattern     = "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}"
      }
      "CIS-3.11-NetworkACLChanges" = {
        description = "3.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
        pattern     = "{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}"
      }
      "CIS-3.11-NetworkACLChanges" = {
        description = "3.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
        pattern     = "{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}"
      }
      "CIS-3.12-NetworkGatewayChanges" = {
        description = "3.12 - Ensure a log metric filter and alarm exist for changes to network gateways"
        pattern     = "{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}"
      }
      "CIS-3.13-RouteTableChanges" = {
        description = "3.13 - Ensure a log metric filter and alarm exist for route table changes"
        pattern     = "{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}"
      }
      "CIS-3.14-VPCChanges" = {
        description = "3.14 – Ensure a log metric filter and alarm exist for VPC changes"
        pattern     = "{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}"
      }
    }
  }
}
variable "cloudtrail_iam_role_name" {
  type        = string
  description = "IAM Role name for CloudTrail Role"
  default     = "CloudTrail"
}
variable "cloudtrail_sns_topic_name" {
  type        = string
  description = "SNS topic name for cloudtrail"
  default     = "aws-cloudtrail"
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