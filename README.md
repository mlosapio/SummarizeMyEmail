# Email Summarizer: Serverless AWS Service

[![AWS](https://img.shields.io/badge/AWS-Serverless-orange?logo=amazon-aws)](https://aws.amazon.com/serverless/)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-blueviolet?logo=terraform)](https://www.terraform.io/)

## Overview

This project deploys a serverless email summarization service on AWS. Users forward emails to a custom address (e.g., summarize@yourdomain.com), and an AI-powered LLM (Amazon Bedrock with Anthropic Claude 3.5 Sonnet) generates a summary, emailed back to the sender. Key features:

- **Custom Prompts**: Add instructions (e.g., "Extract action items:") before the forwarded email content to customize the LLM's response.
- **Whitelisting**: Only emails from specified sender addresses are processed to prevent abuse.
- **Privacy-Focused**: Emails are processed ephemerally; raw emails are stored temporarily in S3 but can be configured for auto-deletion.
- **Serverless**: Uses AWS SES (email handling), Lambda (processing), Bedrock (LLM), S3 (storage), and Route 53 (DNS).

Ideal for personal productivity, newsletter digestion, or automated email workflows. Estimated cost: ~$0.01 per processed message (10KB email, 1,500 input tokens, 300 output tokens).

## How It Works

1. **Email Forwarding**:
   - Forward an email to summarize@yourdomain.com.
   - Optionally, include a custom prompt (e.g., "Summarize in 3 bullets:") before the forwarded message marker (e.g., --- Forwarded message --- or From:).

2. **Processing Flow**:
   - AWS SES receives the email and triggers a receipt rule.
   - The email is stored in an S3 bucket for full content access.
   - A Lambda function is invoked with email metadata.
   - Lambda:
     - Retrieves the email from S3.
     - Checks the sender against a whitelist (environment variable).
     - Parses the body for a custom prompt (defaults to "Summarize the following email content in bullet points:").
     - Invokes Bedrock to generate the summary.
     - Sends the summary back via SES from noreply@yourdomain.com.
   - Non-whitelisted emails are discarded silently.

3. **Key Technologies**:
   - **AWS SES**: Handles inbound/outbound emails and triggers processing.
   - **AWS Lambda**: Python 3.12 function for logic (parsing, whitelisting, LLM call).
   - **Amazon Bedrock**: Uses Claude 3.5 Sonnet for summarization.
   - **AWS S3**: Temporary storage for raw emails.
   - **AWS Route 53**: Manages DNS records (MX, TXT, CNAME) for email routing and verification.

## Architecture Diagram

The architecture is illustrated below using Mermaid syntax (renderable on GitHub or Mermaid Live).

```mermaid
graph TD
    A[User Email Client] -->|Forward Email| B[AWS SES Inbound]
    B -->|Store Raw Email| C[AWS S3 Bucket]
    B -->|Trigger (Receipt Rule)| D[AWS Lambda Function]
    D -->|Get Email Content| C
    D -->|Check Whitelist| E[Environment Vars]
    D -->|Invoke LLM| F[Amazon Bedrock - Claude 3.5]
    F -->|Return Summary| D
    D -->|Send Summary Email| G[AWS SES Outbound]
    G -->|Email Response| A
    H[AWS Route 53] -->|DNS Records (MX, TXT, CNAME)| B

    subgraph Security & Config
        E[Environment Vars]
        I[IAM Roles/Policies]
    end

    I --> D
```

- **User Interaction**: Starts and ends with the user's email client.
- **Data Flow**: Email → SES → S3/Lambda → Bedrock → SES → User.
- **Control Flow**: Whitelisting and prompts handled in Lambda.

## Deployment

### Prerequisites
- **AWS Account**: Permissions for SES, Lambda, Bedrock, S3, Route 53, and IAM (see IAM policy below).
- **Domain Ownership**: A registered domain (e.g., via Route 53 or another registrar). Update name servers to point to the Route 53 hosted zone created by Terraform.
- **Terraform**: Version 1.5+ installed.
- **AWS CLI**: Configured with credentials.
- **Bedrock Access**: Enable Anthropic Claude models in the AWS Bedrock console (us-east-1).

### Steps
1. **Clone the Repository**:
   ```bash
   git clone <repo-url>
   cd <repo-directory>
   ```

2. **Configure terraform.tfvars**:
   - Create a terraform.tfvars file in the root directory.
   - Example (replace with your values):
     ```hcl
     domain_name = "yourdomain.com"

     whitelisted_emails = ["your.email@example.com", "another.email@domain.com"]
     ```
   - domain_name: Your domain for email handling.
   - whitelisted_emails: List of allowed sender emails (case-insensitive).

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Review Plan**:
   ```bash
   terraform plan
   ```

5. **Apply Changes**:
   ```bash
   terraform apply
   ```
   - Creates: Route 53 hosted zone, SES identity, DNS records, S3 bucket, IAM role, Lambda function, SES receipt rules.
   - Output includes hosted zone name servers—update your domain registrar with these.

6. **Verify SES**:
   - In the AWS SES console, confirm domain verification (may take up to 72 hours for DNS propagation).
   - Test sending from noreply@yourdomain.com (SES may require manual verification for new domains).

7. **Test the Service**:
   - From a whitelisted email, forward a message to summarize@yourdomain.com. Optionally include a custom prompt (e.g., "Extract action items:").
   - Check your inbox for the summary response.
   - Monitor Lambda logs in CloudWatch (/aws/lambda/email-summarizer) for debugging.

8. **Cleanup**:
   ```bash
   terraform destroy
   ```
   - Note: This won't delete the domain registration if managed outside Terraform.

## Configuration

### Terraform Variables
- domain_name (string, required): Domain for SES and Route 53 (e.g., "example.com").
- whitelisted_emails (list(string), optional, default: []): Emails allowed to trigger summarization.

### Lambda Environment Variables
- WHITELISTED_EMAILS: Comma-separated list from var.whitelisted_emails (set by Terraform).

### Customizing
- **LLM Prompt**: Edit the default in lambda_function.py (e.g., change max_tokens or model ID).
- **S3 Lifecycle**: Add a lifecycle policy to delete old emails (e.g., after 7 days):
  ```hcl
  resource "aws_s3_bucket_lifecycle_configuration" "email_bucket_lifecycle" {
    bucket = aws_s3_bucket.email_bucket.id
    rule {
      id     = "expire-emails"
      status = "Enabled"
      expiration {
        days = 7
      }
    }
  }
  ```
- **Error Handling**: Enhance Lambda for retries or notifications (e.g., via SNS).

## Important Points to Note

- **Costs**:
  - **SES**: $0.10 per 1,000 emails received/sent + data transfer (~$0.001 for 10KB email).
  - **Lambda**: $0.20 per 1M requests + $0.00001667 per GB-second (~$0.000083 for 512MB, 10s).
  - **Bedrock**: $0.003/1K input tokens + $0.015/1K output tokens (~$0.009 for 1,500 in + 300 out).
  - **S3/Route 53**: ~$0.50/month for hosted zone + storage.
  - Total per message: ~$0.01. Free tier may apply for low usage.
  - Monitor with AWS Cost Explorer.

- **Security**:
  - Whitelisting prevents spam; update via Terraform re-apply.
  - IAM: Least privilege—Lambda role only allows necessary actions.
  - Data: Emails in S3 are private; enable encryption if needed (e.g., add aws_s3_bucket_server_side_encryption_configuration).
  - SES Sandbox: New accounts start in sandbox mode—request production access for unlimited sending via AWS Support.

- **Limitations**:
  - Email Size: SES limits ~10MB; large attachments may fail.
  - DNS Propagation: MX/TXT/CNAME records may take 48-72 hours.
  - Bedrock Region: Must be us-east-1 (or adjust provider region).
  - No Attachments: Current Lambda parses text/plain only; extend for HTML/multipart if needed.

- **Scalability**: Serverless—handles high volume automatically.
- **Maintenance**: Update Bedrock model ID if deprecated. Monitor Lambda for timeouts (current: 30s, 512MB).

## Example terraform.tfvars

```hcl
domain_name = "summarizemyemail.com"

whitelisted_emails = ["john.doe@gmail.com", "jane.smith@outlook.com", "alice@examplecorp.com"]
```

## Troubleshooting

- **Email Not Received**:
  - Check MX records: dig MX yourdomain.com.
  - Ensure SES domain is verified in the AWS SES console.
  - Verify DNS propagation for MX, TXT, and CNAME records.

- **Lambda Not Triggered**:
  - Confirm SES receipt rule is active (email-summarizer-rules) in SES console.
  - Check CloudWatch Logs (/aws/lambda/email-summarizer) for errors.
  - Verify aws_lambda_permission.ses_invoke is applied.

- **Whitelist Issues**:
  - Whitelisting is case-insensitive; ensure exact email match in whitelisted_emails.
  - Test with a whitelisted email forwarding to summarize@yourdomain.com.

- **Bedrock Errors**:
  - Confirm access to Claude 3.5 Sonnet in Bedrock console (us-east-1).
  - Check IAM role for bedrock:InvokeModel permission.

- **Terraform Errors**:
  - Ensure AWS credentials have required permissions (see IAM policy below).
  - Enable debug logging: export TF_LOG=DEBUG and rerun terraform apply.

## IAM Policy for Deployment

Ensure your AWS credentials have permissions for the following actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:CreateHostedZone",
        "route53:ChangeResourceRecordSets",
        "ses:*",
        "s3:CreateBucket",
        "s3:PutBucketPolicy",
        "s3:GetObject",
        "s3:PutObject",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "bedrock:InvokeModel",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Pull requests welcome! For major changes, open an issue first.

---

Built with ❤️ using AWS and Terraform. For questions, contact [your-email@example.com].
