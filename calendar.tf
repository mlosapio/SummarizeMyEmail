# Terraform configuration for Tokenized ICS Feed Calendar Project
# Serves ICS feed from DynamoDB via API Gateway using a static, hard-to-guess URI path (no authentication).
# Features:
# - DynamoDB table with a static calendarToken (e.g., b7f4a9c2e1d8).
# - API Gateway with direct DynamoDB Query, no API key or IAM authentication required.
# - Endpoint: https://<api-id>.execute-api.us-east-1.amazonaws.com/prod/ics-b7f4a9c2e1d8.ics
# - Cost: ~$0.0027/month (Free Tier), ~$0.119/month (without Free Tier) for low traffic.
# - Security relies on obscurity of the static URI path; use cautiously and consider additional protections.

# Define the region variable
variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

# DynamoDB Table for Calendar Events
resource "aws_dynamodb_table" "calendars" {
  name         = "Calendars"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "calendarToken"
  range_key    = "eventStartTime"

  attribute {
    name = "calendarToken"
    type = "S"
  }

  attribute {
    name = "eventStartTime"
    type = "S"
  }

  tags = {
    Name = "ICSFeedCalendars"
  }
}

# IAM Role for API Gateway to access DynamoDB
resource "aws_iam_role" "api_gateway_role" {
  name = "ics_feed_api_gateway_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })
}

# Policy for API Gateway to query DynamoDB
resource "aws_iam_policy" "api_gateway_dynamodb_policy" {
  name        = "api_gateway_dynamodb_access"
  description = "Allow API Gateway to query DynamoDB"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.calendars.arn
      },
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow"
        Resource = "arn:aws:logs:${var.region}:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_gateway_dynamodb_attach" {
  role       = aws_iam_role.api_gateway_role.name
  policy_arn = aws_iam_policy.api_gateway_dynamodb_policy.arn
}

# API Gateway
resource "aws_api_gateway_rest_api" "ics_api" {
  name        = "ICSFeedAPI"
  description = "API for tokenized ICS feeds with static URI"
}

# Resource policy to allow public access
resource "aws_api_gateway_rest_api_policy" "ics_api_policy" {
  rest_api_id = aws_api_gateway_rest_api.ics_api.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.ics_api.id}/*/*/ics-b7f4a9c2e1d8.ics"
      }
    ]
  })
}

# Resource for /ics-b7f4a9c2e1d8.ics
resource "aws_api_gateway_resource" "feed" {
  rest_api_id = aws_api_gateway_rest_api.ics_api.id
  parent_id   = aws_api_gateway_rest_api.ics_api.root_resource_id
  path_part   = "ics-b7f4a9c2e1d8.ics"
}

# GET Method
resource "aws_api_gateway_method" "get_feed" {
  rest_api_id      = aws_api_gateway_rest_api.ics_api.id
  resource_id      = aws_api_gateway_resource.feed.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = false
}

# Integration with DynamoDB (Query operation)
resource "aws_api_gateway_integration" "dynamodb_integration" {
  rest_api_id             = aws_api_gateway_rest_api.ics_api.id
  resource_id             = aws_api_gateway_resource.feed.id
  http_method             = aws_api_gateway_method.get_feed.http_method
  type                    = "AWS"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:${var.region}:dynamodb:action/Query"
  credentials             = aws_iam_role.api_gateway_role.arn

  # Query with calendarToken
  request_templates = {
    "application/json" = <<EOF
{
  "TableName": "${aws_dynamodb_table.calendars.name}",
  "KeyConditionExpression": "calendarToken = :token",
  "ExpressionAttributeValues": {
    ":token": {"S": "b7f4a9c2e1d8"}
  }
}
EOF
  }
}

# Method Response
resource "aws_api_gateway_method_response" "get_feed_response" {
  rest_api_id = aws_api_gateway_rest_api.ics_api.id
  resource_id = aws_api_gateway_resource.feed.id
  http_method = aws_api_gateway_method.get_feed.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Content-Type"        = true
    "method.response.header.Content-Disposition" = true
  }

  response_models = {
    "text/calendar" = "Empty"
  }
}

# Integration Response (Transform DynamoDB output to ICS)
resource "aws_api_gateway_integration_response" "get_feed_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.ics_api.id
  resource_id = aws_api_gateway_resource.feed.id
  http_method = aws_api_gateway_method.get_feed.http_method
  status_code = aws_api_gateway_method_response.get_feed_response.status_code

  response_parameters = {
    "method.response.header.Content-Type"        = "'text/calendar; charset=UTF-8'"
    "method.response.header.Content-Disposition" = "'attachment; filename=\"calendar.ics\"'"
  }

  # Mapping template with proper line endings, fixed RRULE, and all-day event handling
  response_templates = {
    "text/calendar" = <<EOF
BEGIN:VCALENDAR\r\n
VERSION:2.0\r\n
PRODID:-//YourApp//ICS Feed//EN\r\n
#foreach($item in $input.path('$.Items'))
BEGIN:VEVENT\r\n
UID:$item.eventId.S\r\n
#if($item.dtstart.S.endsWith("T000000Z") && $item.dtend.S.endsWith("T235959Z"))
DTSTART;VALUE=DATE:$item.dtstart.S.substring(0,8)\r\n
DTEND;VALUE=DATE:$item.dtend.S.substring(0,8)\r\n
#else
DTSTART:$item.dtstart.S\r\n
DTEND:$item.dtend.S\r\n
#end
SUMMARY:$util.escapeJavaScript($item.summary.S).replaceAll("\n","\\n").replaceAll(",","\\,")\r\n
DESCRIPTION:$util.escapeJavaScript($item.description.S).replaceAll("\n","\\n").replaceAll(",","\\,")\r\n
#if($item.location.S && $item.location.S != "")LOCATION:$util.escapeJavaScript($item.location.S).replaceAll("\n","\\n").replaceAll(",","\\,")\r\n#end
#if($item.rrule.S && $item.rrule.S != "")RRULE:$item.rrule.S\r\n#end
STATUS:$item.status.S\r\n
END:VEVENT\r\n
#end
END:VCALENDAR\r\n
EOF
  }

  depends_on = [aws_api_gateway_integration.dynamodb_integration]
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "prod" {
  depends_on = [
    aws_api_gateway_integration.dynamodb_integration,
    aws_api_gateway_integration_response.get_feed_integration_response,
    aws_api_gateway_rest_api_policy.ics_api_policy
  ]

  rest_api_id = aws_api_gateway_rest_api.ics_api.id

  lifecycle {
    create_before_destroy = true
  }
}

# API Gateway Stage with fixed access log format
resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.ics_api.id
  deployment_id = aws_api_gateway_deployment.prod.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_log.arn
    format          = "$context.identity.sourceIp $context.requestTime $context.requestId $context.httpMethod $context.path $context.status"
  }
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway_log" {
  name              = "/aws/apigateway/ICSFeedAPI"
  retention_in_days = 7
}

# Outputs
output "api_endpoint" {
  value       = "${aws_api_gateway_stage.prod.invoke_url}/ics-b7f4a9c2e1d8.ics"
  description = "API endpoint for ICS feed with static URI"
}
