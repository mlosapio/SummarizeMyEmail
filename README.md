# Summarize My Email

## Overview

This Terraform project deploys a serverless email summarization and calendar integration service on AWS. Emails sent to `summarize@yourdomain.com` are summarized using Amazon Bedrock (Claude 3.5 Sonnet). If the email includes instructions like "add calendar," events are extracted and added to a DynamoDB table. Calendar events are served as an ICS feed via API Gateway using a static, hard-to-guess token for access.

The project consists of two main Terraform files:
- `calendar.tf`: Configures DynamoDB, API Gateway, and IAM for serving the ICS feed.
- `summarize.tf`: Configures SES, Route53, S3, Lambda, and Bedrock for email processing and summarization.

## Features

- **Email Summarization**: AI-powered bullet-point summaries of email content.
- **Calendar Event Extraction**: Automatically detects and adds events to DynamoDB if instructed.
- **ICS Feed**: Publicly accessible ICS endpoint for calendar subscriptions (e.g., Google Calendar, Apple Calendar).
- **Email Whitelisting**: Restricts processing to specified sender emails.
- **Serverless Architecture**: Uses AWS Lambda, SES, S3, DynamoDB, API Gateway, and Bedrock.
- **Low Cost**: Eligible for AWS Free Tier; estimated ~$0.0027/month with Free Tier, ~$0.119/month without for low traffic (based on ICS feed component).

## Architecture

- **SES & Route53**: Handles email receiving with MX records, verification (TXT, DKIM, SPF, DMARC), and triggers Lambda on receipt.
- **S3**: Stores raw incoming emails.
- **Lambda**: Parses emails, uses Bedrock for summarization and event extraction, sends summary replies via SES, and upserts events in DynamoDB using a static calendar token (`default`).
- **Bedrock**: Invokes Claude 3.5 Sonnet for generating summaries and structured event data.
- **DynamoDB**: Stores calendar events with `calendarToken` as hash key and `eventStartTime` as range key.
- **API Gateway**: Queries DynamoDB and generates ICS format responses via a GET endpoint (e.g., `/ics-default.ics` or configured via `ics_filename` variable).

Security for the ICS feed relies on obscurity of the static URI path (no authentication). Use cautiously.

## Prerequisites

- AWS account with permissions for SES, Lambda, S3, DynamoDB, API Gateway, Route53, Bedrock, and IAM.
- Domain name (e.g., `yourdomain.com`) for email handling (must be verifiable in SES).
- Terraform installed.
- AWS CLI configured with credentials.

## Installation

1. Clone the repository:
   ```
   git clone git@github.com:mlosapio/SummarizeMyEmail.git
   cd SummarizeMyEmail
   ```

2. Edit `summarize.tfvars` to set:
   - `domain_name`: Your domain (e.g., "yourdomain.com").
   - `whitelisted_emails`: Array of allowed sender emails (e.g., ["user@example.com"]).

3. Initialize Terraform:
   ```
   terraform init
   ```

4. Apply the configuration:
   ```
   terraform apply -var-file="summarize.tfvars"
   ```

5. Verify SES domain identity and DNS records in Route53 (or manually if not using Route53).
6. Note the outputted API endpoint for the ICS feed.

## Usage

### Summarizing Emails
- Send or forward an email to `summarize@yourdomain.com`.
- Optional: Include a custom prompt before the forwarded content (e.g., "Summarize in detail:").
- If whitelisted, receive a summarized reply from `noreply@yourdomain.com`.

### Adding Calendar Events
- Include "add calendar" in the email body or subject.
- The AI extracts events (e.g., dates, times, summaries) and adds them to DynamoDB.
- Events support all-day or timed formats, locations, descriptions, and RRULE recurrences.

### Accessing the ICS Feed
- Subscribe to the endpoint: `https://<api-id>.execute-api.us-east-1.amazonaws.com/prod/<ics_filename>` (e.g., `/ics-default.ics`).
- Use in calendar apps by adding the URL as a subscribed calendar.

## Customization

- Update the calendar token in `summarize.tf` (Lambda env var) and `calendar.tf` (request template and output).
- Modify the Bedrock prompt in the Lambda code for custom summarization logic.
- Adjust `ics_filename` variable in `calendar.tf` for the ICS endpoint path.

## Security Notes

- **ICS Feed**: Relies on security by obscurity (static token in URL). Not suitable for sensitive data; consider adding authentication for production.
- **Email Whitelisting**: Prevents unauthorized usage; configure via `whitelisted_emails`.
- **Permissions**: Lambda has targeted IAM policies for S3, Bedrock, SES, and DynamoDB.

## Costs

- **ICS Feed Component**: ~$0.0027/month (Free Tier), ~$0.119/month without for low traffic.
- **Email Processing**: Costs for SES (~$0.10/1,000 emails), Lambda invocations (~$0.20/1M requests), Bedrock (~$0.003/1,000 input tokens), S3 storage (minimal), DynamoDB (pay-per-request).
- Monitor via AWS Cost Explorer; mostly Free Tier eligible for low usage.

## Troubleshooting

- Check Lambda logs in CloudWatch for errors.
- Ensure SES domain is verified (status in AWS Console).
- Validate DNS records propagate correctly.
- If events aren't added, review the Bedrock response parsing in Lambda code.

## Contributing

Fork the repository, make changes, and submit a pull request.
