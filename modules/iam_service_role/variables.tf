variable "services" {
  type = list(any)
}
variable "name" {}
variable "include_policy_json" {
  default     = true
  description = "With dynamic JSON, terraform can't deteremine if the object should be created. This forces it."
}
variable "path" {
  default = "/service-role/"
}
variable "policy_json" {
  default = ""
}
variable "managed_policy_arns" {
  type    = list(string)
  default = []
}
variable "tags" {
  type    = map(string)
  default = {}
}
