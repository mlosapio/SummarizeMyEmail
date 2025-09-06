# Terraform configuration for serverless email summarization service using AWS SES, Lambda, Bedrock, and S3.
# Assumptions:
# - Use variables for domain name and whitelisted email addresses.
# - Lambda uses Python 3.12 runtime.
# - Bedrock model: anthropic.claude-3-5-sonnet-20240620-v1:0 (update if needed).
# - Region: us-east-1 (SES receiving is region-specific).
# - Inbound email address: summarize@yourdomain.com (customize recipients in receipt rule).
# - Summary sent back to the email's envelope sender (the forwarder).
# - S3 stores raw emails for full content access.
# - Parse email body for custom prompt (text before forwarded message) to override default LLM prompt.
# - Whitelist sender email addresses via Lambda env var; discard if not whitelisted.

provider "aws" {
  region = "us-east-1"  # Change if needed; must match SES receiving region.
}

# Variables
variable "domain_name" {
  description = "The domain name to use (e.g., example.com). Must be registered in Route 53 or manually configured."
  type        = string
}

variable "whitelisted_emails" {
  description = "List of email addresses allowed to forward emails (e.g., ['user1@gmail.com', 'user2@example.com'])"
  type        = list(string)
  default     = []
}

# Create Route 53 hosted zone for the domain
resource "aws_route53_zone" "zone" {
  name = var.domain_name
}

# SES Domain Identity
resource "aws_ses_domain_identity" "domain_identity" {
  domain = var.domain_name
}

# SES Domain Verification Record
resource "aws_route53_record" "ses_verification" {
  zone_id = aws_route53_zone.zone.zone_id
  name    = "_amazonses.${var.domain_name}"
  type    = "TXT"
  ttl     = 600
  records = [aws_ses_domain_identity.domain_identity.verification_token]
}

# DKIM for SES
resource "aws_ses_domain_dkim" "dkim" {
  domain = aws_ses_domain_identity.domain_identity.domain
}

resource "aws_route53_record" "dkim_records" {
  count   = 3
  zone_id = aws_route53_zone.zone.zone_id
  name    = "${element(aws_ses_domain_dkim.dkim.dkim_tokens, count.index)}._domainkey.${var.domain_name}"
  type    = "CNAME"
  ttl     = 600
  records = ["${element(aws_ses_domain_dkim.dkim.dkim_tokens, count.index)}.dkim.amazonses.com"]
}

# SPF Record (for sending)
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.zone.zone_id
  name    = var.domain_name
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com -all"]
}

# MX Record for receiving emails via SES
resource "aws_route53_record" "mx" {
  zone_id = aws_route53_zone.zone.zone_id
  name    = var.domain_name
  type    = "MX"
  ttl     = 600
  records = ["10 inbound-smtp.us-east-1.amazonaws.com"]  # Updated to correct MX for SES receiving
}

# Optional: DMARC Record
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.zone.zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 600
  records = ["v=DMARC1; p=none;"]  # Customize policy as needed
}

# S3 Bucket for storing inbound emails
resource "aws_s3_bucket" "email_bucket" {
  bucket = "${replace(var.domain_name, ".", "-")}-emails"
}

# S3 Bucket Public Access Block (required for newer AWS accounts)
resource "aws_s3_bucket_public_access_block" "email_bucket" {
  bucket = aws_s3_bucket.email_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Policy to allow SES to write
data "aws_iam_policy_document" "s3_ses_policy" {
  statement {
    sid       = "AllowSESPut"
    actions   = ["s3:PutObject"]
    effect    = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.email_bucket.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:Referer"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "email_bucket_policy" {
  bucket = aws_s3_bucket.email_bucket.id
  policy = data.aws_iam_policy_document.s3_ses_policy.json
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "email-summarizer-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda: Logs, S3 Get, Bedrock Invoke, SES Send
data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    actions   = ["s3:GetObject"]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.email_bucket.arn}/*"]
  }

  statement {
    actions   = ["bedrock:InvokeModel"]
    effect    = "Allow"
    resources = ["*"]  # Or specify model ARN, e.g., arn:aws:bedrock:us-east-1::model/anthropic.claude-3-5-sonnet-20240620-v1:0
  }

  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_policy_attach" {
  name   = "lambda-execution-policy"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

# Zip the Lambda code (inline Python code with fixes for KeyError: 'actions' and NameError: 'var')
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = <<EOF
import json
import boto3
import email
from email.parser import BytesParser
import os
import re

def lambda_handler(event, context):
    # Log event for debugging
    print(f"Event: {json.dumps(event, indent=2)}")

    # Extract SES event details
    ses_event = event['Records'][0]['ses']
    mail = ses_event['mail']
    message_id = mail['messageId']
    bucket = "${replace(var.domain_name, ".", "-")}-emails"  # Hardcode bucket name from Terraform
    key = f"emails/{message_id}"  # Construct object key using messageId and prefix

    # Get raw email from S3
    s3 = boto3.client('s3')
    raw_email = s3.get_object(Bucket=bucket, Key=key)['Body'].read()

    # Parse email
    msg = BytesParser().parsebytes(raw_email)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode()
                break
    else:
        body = msg.get_payload(decode=True).decode()

    # Check sender email against whitelist
    sender = ses_event['mail']['source']  # Envelope from (forwarder)
    whitelisted_emails = os.environ.get('WHITELISTED_EMAILS', '').split(',')
    if whitelisted_emails and sender.lower() not in [e.strip().lower() for e in whitelisted_emails if e]:
        print(f"Sender email {sender} not whitelisted; discarding.")
        return {"disposition": "STOP_RULE_SET"}

    # Parse for custom prompt: Text before forwarded message marker
    custom_prompt = "Summarize the following email content in bullet points:"
    email_content = body
    forwarded_marker = re.search(r'(-{3,}\s*Forwarded message\s*-{3,})|(\nFrom:\s)', body, re.IGNORECASE)
    if forwarded_marker:
        prompt_text = body[:forwarded_marker.start()].strip()
        if prompt_text:
            custom_prompt = prompt_text
        email_content = body[forwarded_marker.start():].strip()

    # Summarize with Bedrock (Claude 3.5 Sonnet)
    bedrock = boto3.client('bedrock-runtime')
    prompt = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1000,
        "messages": [
            {
                "role": "user",
                "content": f"{custom_prompt} {email_content}"
            }
        ]
    }
    response = bedrock.invoke_model(
        modelId='anthropic.claude-3-5-sonnet-20240620-v1:0',
        body=json.dumps(prompt),
        contentType='application/json',
        accept='application/json'
    )
    response_body = json.loads(response['body'].read())
    summary = response_body['content'][0]['text']

    # Send summary via SES back to sender
    ses = boto3.client('ses')
    ses.send_email(
        Source="noreply@${var.domain_name}",  # Verified sender
        Destination={'ToAddresses': [sender]},
        Message={
            'Subject': {'Data': 'Email Summary'},
            'Body': {'Text': {'Data': summary}}
        }
    )

    # Return disposition to continue or stop
    return {"disposition": "CONTINUE"}
EOF
    filename = "lambda_function.py"
  }
}

# Lambda Function with env var for whitelist
resource "aws_lambda_function" "email_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "email-summarizer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 512  # Added to ensure sufficient memory for email processing

  environment {
    variables = {
      WHITELISTED_EMAILS = join(",", var.whitelisted_emails)
    }
  }
}

# Permission for SES to invoke Lambda
resource "aws_lambda_permission" "ses_invoke" {
  statement_id  = "AllowExecutionFromSES"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.email_processor.function_name
  principal     = "ses.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}

# SES Receipt Rule Set
resource "aws_ses_receipt_rule_set" "main" {
  rule_set_name = "email-summarizer-rules"
}

# Activate the Rule Set
resource "aws_ses_active_receipt_rule_set" "active" {
  rule_set_name = aws_ses_receipt_rule_set.main.rule_set_name
}

# SES Receipt Rule
resource "aws_ses_receipt_rule" "process_email" {
  rule_set_name = aws_ses_receipt_rule_set.main.rule_set_name
  name          = "summarize-email"
  recipients    = ["summarize@${var.domain_name}"]
  enabled       = true
  scan_enabled  = true

  s3_action {
    bucket_name       = aws_s3_bucket.email_bucket.bucket
    object_key_prefix = "emails/"
    position          = 1
  }

  lambda_action {
    function_arn    = aws_lambda_function.email_processor.arn
    invocation_type = "Event"
    position        = 2
  }
}

data "aws_caller_identity" "current" {}

# Outputs
output "domain_name" {
  value = var.domain_name
}

output "lambda_function_name" {
  value = aws_lambda_function.email_processor.function_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.email_bucket.bucket
}

output "ses_domain_identity" {
  value = aws_ses_domain_identity.domain_identity.id
}
