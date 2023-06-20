data "aws_iam_policy_document" "this" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = var.services
      type        = "Service"
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.name
  path               = var.path
  assume_role_policy = data.aws_iam_policy_document.this.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "this" {
  count  = var.include_policy_json ? 1 : 0
  name   = var.name
  policy = var.policy_json
  role   = aws_iam_role.this.id
}

resource "aws_iam_role_policy_attachment" "this" {
  count      = length(var.managed_policy_arns)
  policy_arn = element(var.managed_policy_arns, count.index)
  role       = aws_iam_role.this.name
}
