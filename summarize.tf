# Terraform configuration for serverless email summarization service using AWS SES, Lambda, Bedrock, and S3.
# Features:
# - Processes emails sent to summarize@yourdomain.com, summarizes content, and adds calendar events if instructed.
# - Uses static calendarToken (b7f4a9c2e1d8) for DynamoDB operations.
# - Stores raw emails in S3 bucket derived from domain name.
# - Sends summary back to the sender via SES.
# - Ensures environment variables are properly set for S3 bucket, source email, and calendar token.

provider "aws" {
  region = "us-east-1"
}

# Variables
variable "domain_name" {
  description = "The domain name to use (e.g., yourdomain.com). Must be registered in Route 53 or manually configured."
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
  records = ["10 inbound-smtp.us-east-1.amazonaws.com"]
}

# Optional: DMARC Record
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.zone.zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 600
  records = ["v=DMARC1; p=none;"]
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

# IAM Policy for Lambda: Logs, S3 Get, Bedrock Invoke, SES Send, DynamoDB
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
    resources = ["*"]
  }

  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    actions   = ["dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    effect    = "Allow"
    resources = ["arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/Calendars"]
  }
}

resource "aws_iam_role_policy" "lambda_policy_attach" {
  name   = "lambda-execution-policy"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

# Zip the Lambda code with improved prompt and environment variable validation
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
import uuid
from datetime import datetime, timezone, timedelta

def utc_now_dtstamp():
    """Return current UTC timestamp in iCalendar format (YYYYMMDDTHHMMSSZ)."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def is_allday(dt: str) -> bool:
    """True if dt is an all-day date in YYYYMMDD format."""
    return isinstance(dt, str) and len(dt) == 8 and dt.isdigit()

def lambda_handler(event, context):
    # Validate environment variables
    required_env_vars = ['EMAIL_BUCKET_NAME', 'SOURCE_EMAIL', 'CALENDAR_TOKEN']
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        print(f"Missing required environment variables: {missing_vars}")
        return {"disposition": "STOP_RULE_SET"}

    bucket = os.environ['EMAIL_BUCKET_NAME']
    source_email = os.environ['SOURCE_EMAIL']
    calendar_token = os.environ['CALENDAR_TOKEN']

    # Log event for debugging
    try:
        print(f"Event: {json.dumps(event, indent=2)}")
    except Exception:
        print("Event received (unable to pretty-print).")

    # Extract SES event details
    try:
        ses_event = event['Records'][0]['ses']
        mail = ses_event['mail']
        message_id = mail['messageId']
        key = f"emails/{message_id}"  # Construct object key using messageId and prefix
    except KeyError as e:
        print(f"Failed to extract SES event details: {e}")
        return {"disposition": "STOP_RULE_SET"}

    # Get raw email from S3
    s3 = boto3.client('s3')
    try:
        raw_email = s3.get_object(Bucket=bucket, Key=key)['Body'].read()
    except Exception as e:
        print(f"Failed to fetch email from s3://{bucket}/{key}: {e}")
        return {"disposition": "STOP_RULE_SET"}

    # Parse email
    try:
        msg = BytesParser().parsebytes(raw_email)
    except Exception as e:
        print(f"Failed to parse raw email bytes: {e}")
        return {"disposition": "STOP_RULE_SET"}

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if ctype == 'text/plain' and 'attachment' not in disp:
                try:
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    break
                except Exception:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
        except Exception:
            body = msg.get_payload()

    if not isinstance(body, str):
        body = str(body or "")

    # Check sender email against whitelist
    sender = mail['source']  # Envelope from (forwarder)
    whitelisted_emails = os.environ.get('WHITELISTED_EMAILS', '').split(',')
    if whitelisted_emails and sender.lower() not in [e.strip().lower() for e in whitelisted_emails if e.strip()]:
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

    print(f"Custom prompt: {custom_prompt}")

    # Check if instructions to add calendar events
    add_to_calendar = 'add calendar' in custom_prompt.lower()
    print(f"Add to calendar detected: {add_to_calendar}")

    # Build Claude prompt with stricter requirements and examples
    claude_content = f"{custom_prompt}\n{email_content}"
    if add_to_calendar:
        claude_content = (
            f"{custom_prompt}\n"
            "Additionally, extract any mentioned events as a JSON array of objects with keys: "
            "summary (string), dtstart (in YYYYMMDDTHHMMSSZ UTC format for timed events or YYYYMMDD for all-day events), "
            "dtend (in YYYYMMDDTHHMMSSZ UTC format for timed events or YYYYMMDD for all-day events, after dtstart), "
            "description (string), location (string, empty if none), rrule (valid RFC 5545 recurrence rule or omit if not recurring), "
            "status (default CONFIRMED), eventId (unique UUID), dtstamp (UTC now in YYYYMMDDTHHMMSSZ). "
            "Ensure: 1) Valid JSON with proper brackets; 2) Always include summary, dtstart, dtend, eventId, dtstamp; "
            "3) Use YYYYMMDD for all-day events and YYYYMMDDTHHMMSSZ for timed events; "
            "4) Avoid edge-case timings (e.g., 23:59:59 to 00:00:00); "
            "5) Escape commas in summary, description, location with \\,; "
            "6) Assume events start/stop times are in local NYC time (EDT/EST) and convert to UTC Z; "
            "7) For all-day events, dtend must be exclusive (next day); "
            "8) Always include EVENTS_JSON: <json array>, even if empty (e.g., EVENTS_JSON: []); "
            "Example input: 'Team meeting on October 10, 2025, from 2:00 PM to 3:00 PM in Conference Room A for Joe.'\n"
            "Example output:\n"
            "Summary:\n- Team meeting scheduled for October 10, 2025, from 2:00 PM to 3:00 PM for Joe.\n"
            "EVENTS_JSON: [{\"summary\": \"Team Meeting\", \"dtstart\": \"20251010T180000Z\", \"dtend\": \"20251010T190000Z\", "
            "\"description\": \"Team meeting for Joe\", \"location\": \"Conference Room A\", \"status\": \"CONFIRMED\", "
            "\"eventId\": \"<uuid>\", \"dtstamp\": \"<current_utc>\"}] \n"
            "Example input: 'School Picture Day on September 19, 2025.'\n"
            "Example output:\n"
            "Summary:\n- School Picture Day on September 19, 2025.\n"
            "EVENTS_JSON: [{\"summary\": \"School Picture Day\", \"dtstart\": \"20250919\", \"dtend\": \"20250920\", "
            "\"description\": \"School Picture Day\", \"location\": \"\", \"status\": \"CONFIRMED\", "
            "\"eventId\": \"<uuid>\", \"dtstamp\": \"<current_utc>\"}] \n"
            f"Email content: {email_content}"
        )

    # Summarize with Bedrock (Claude 3.5 Sonnet)
    bedrock = boto3.client('bedrock-runtime')
    prompt = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,  # Increased to handle detailed responses
        "messages": [
            {
                "role": "user",
                "content": claude_content
            }
        ]
    }

    try:
        response = bedrock.invoke_model(
            modelId='anthropic.claude-3-5-sonnet-20240620-v1:0',
            body=json.dumps(prompt),
            contentType='application/json',
            accept='application/json'
        )
        response_body = json.loads(response['body'].read())
        response_text = response_body['content'][0]['text']
    except Exception as e:
        print(f"Bedrock invoke failed: {e}")
        response_text = "Sorry—automatic summarization failed."
        # Ensure EVENTS_JSON is included even on failure
        response_text += "\nEVENTS_JSON: []"

    print(f"Claude full response: {response_text[:5000]}")

    # Parse response for summary and events
    events = []
    summary = response_text
    if add_to_calendar:
        if 'EVENTS_JSON:' not in response_text:
            print("No EVENTS_JSON found in Claude response; assuming no events.")
            summary = response_text.strip()
            events_json = "[]"
        else:
            parts = response_text.split('EVENTS_JSON:', 1)
            summary = parts[0].strip()
            events_json = parts[1].strip()
        print(f"Parsed summary: {summary[:1000]}")
        print(f"Raw events_json: {events_json[:2000]}")
        try:
            events = json.loads(events_json)
            if not isinstance(events, list):
                print("EVENTS_JSON is not a list; ignoring.")
                events = []
            else:
                print(f"Parsed events count: {len(events)}")
        except Exception as e:
            print(f"Failed to parse events JSON: {str(e)}")
            events = []

    # Send summary via SES back to sender
    ses = boto3.client('ses')
    try:
        ses.send_email(
            Source=source_email,
            Destination={'ToAddresses': [sender]},
            Message={
                'Subject': {'Data': 'Email Summary'},
                'Body': {'Text': {'Data': summary}}
            }
        )
    except Exception as e:
        print(f"Failed to send SES summary email: {e}")

    # If events extracted, update/insert into DynamoDB
    if events:
        dynamodb = boto3.client('dynamodb')
        print(f"Using calendar_token: {calendar_token}")

        # Fetch existing events for token (for update/match logic)
        try:
            db_response = dynamodb.query(
                TableName='Calendars',
                KeyConditionExpression='calendarToken = :token',
                ExpressionAttributeValues={':token': {'S': calendar_token}}
            )
            existing = db_response.get('Items', [])
            print(f"Existing events count: {len(existing)}")
        except Exception as e:
            print(f"Failed to query DynamoDB: {str(e)}")
            existing = []

        def find_existing(dtstart_val: str, summary_val: str):
            for ex in existing:
                ex_dt = ex.get('dtstart', {}).get('S') or ex.get('eventStartTime', {}).get('S')
                ex_sum = (ex.get('summary', {}).get('S') or '').lower()
                if ex_dt == dtstart_val and ex_sum == summary_val.lower():
                    return ex
            return None

        for event in events:
            try:
                print(f"Processing event: {json.dumps(event, indent=2)}")
            except Exception:
                print("Processing event (unable to pretty-print).")

            # Required fields
            if 'summary' not in event or 'dtstart' not in event or 'dtend' not in event or 'eventId' not in event or 'dtstamp' not in event:
                print("Skipping event: Missing required fields (summary, dtstart, dtend, eventId, dtstamp)")
                continue

            # Normalize and enforce rules
            dtstart = event['dtstart']
            dtend = event['dtend']
            summary_ev = event['summary']
            description = event.get('description', '')
            location = event.get('location', '')
            rrule = event.get('rrule', None)
            status = event.get('status', 'CONFIRMED')
            event_id = event['eventId']
            dtstamp_val = event['dtstamp']

            # Ensure all-day events use exclusive DTEND (next day)
            if is_allday(dtstart) and is_allday(dtend):
                if dtend <= dtstart:
                    d = datetime.strptime(dtstart, "%Y%m%d")
                    dtend = (d + timedelta(days=1)).strftime("%Y%m%d")
                    event['dtend'] = dtend

            # Match existing event (exact dtstart and case-insensitive summary)
            matched_item = find_existing(dtstart, summary_ev)

            if matched_item:
                print(f"Matched existing event for update: dtstart={dtstart}, summary={summary_ev}")
                key = {
                    'calendarToken': {'S': calendar_token},
                    'eventStartTime': {'S': matched_item.get('eventStartTime', {}).get('S', dtstart)}
                }

                update_expr = (
                    'SET summary = :sum, dtend = :end, description = :desc, '
                    'location = :loc, status = :stat, eventId = :eid, dtstart = :start, dtstamp = :dts'
                )
                attr_vals = {
                    ':sum': {'S': summary_ev},
                    ':end': {'S': dtend},
                    ':desc': {'S': description},
                    ':loc': {'S': location},
                    ':stat': {'S': status},
                    ':eid': {'S': event_id},
                    ':start': {'S': dtstart},
                    ':dts': {'S': dtstamp_val},
                }
                if rrule:
                    update_expr += ', rrule = :rr'
                    attr_vals[':rr'] = {'S': rrule}

                try:
                    dynamodb.update_item(
                        TableName='Calendars',
                        Key=key,
                        UpdateExpression=update_expr,
                        ExpressionAttributeValues=attr_vals
                    )
                    print("UpdateItem succeeded")
                except Exception as e:
                    print(f"Failed to update item: {str(e)}")
            else:
                print(f"No match found; inserting new event: dtstart={dtstart}, summary={summary_ev}")
                item = {
                    'calendarToken': {'S': calendar_token},
                    'eventStartTime': {'S': dtstart},
                    'eventId': {'S': event_id},
                    'summary': {'S': summary_ev},
                    'dtstart': {'S': dtstart},
                    'dtend': {'S': dtend},
                    'dtstamp': {'S': dtstamp_val},
                    'description': {'S': description},
                    'location': {'S': location},
                    'status': {'S': status}
                }
                if rrule:
                    item['rrule'] = {'S': rrule}
                try:
                    dynamodb.put_item(
                        TableName='Calendars',
                        Item=item
                    )
                    print("PutItem succeeded")
                except Exception as e:
                    print(f"Failed to put item: {str(e)}")
    else:
        print("No events to process for DynamoDB")

    # Return disposition to continue or stop further rule processing
    return {"disposition": "CONTINUE"}
EOF
    filename = "lambda_function.py"
  }
}

# Lambda Function with env vars for whitelist and calendar token
resource "aws_lambda_function" "email_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "email-summarizer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 512

  environment {
    variables = {
      WHITELISTED_EMAILS = join(",", var.whitelisted_emails)
      CALENDAR_TOKEN     = "b7f4a9c2e1d8"
      EMAIL_BUCKET_NAME  = "${replace(var.domain_name, ".", "-")}-emails"
      SOURCE_EMAIL       = "noreply@${var.domain_name}"
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
