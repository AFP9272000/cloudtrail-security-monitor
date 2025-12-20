# CloudTrail Security Monitor

> Real-time AWS security monitoring system that detects suspicious activities in CloudTrail and sends instant email alerts.

![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20CloudTrail%20%7C%20SNS-orange)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Cost](https://img.shields.io/badge/Cost-~%240.30%2Fmonth-brightgreen)

## ðŸ“‹ Overview

An enterprise-grade security monitoring system that automatically analyzes AWS CloudTrail events and alerts on suspicious activities. Built with serverless architecture for cost-effective, scalable security operations.

**Key Features:**
- âœ… Real-time detection of 25+ high-priority security events
- âœ… Automated email alerts via SNS
- âœ… Event deduplication to prevent alert fatigue
- âœ… Runs automatically every 15 minutes via EventBridge
- âœ… Production-ready code with comprehensive error handling
- âœ… Costs less than \.30/month to operate

## ðŸ—ï¸ Architecture

\\\
CloudTrail â†’ Lambda (every 15 min) â†’ Event Analyzer â†’ SNS â†’ Email Alerts
                â†“
           DynamoDB (deduplication)
\\\

**Components:**
- **AWS Lambda**: Serverless function that retrieves and analyzes CloudTrail events
- **CloudTrail**: Logs all AWS API calls for security monitoring
- **EventBridge**: Triggers Lambda every 15 minutes automatically
- **DynamoDB**: Tracks processed events to prevent duplicate alerts
- **SNS**: Sends email notifications for detected incidents
- **KMS**: Encrypts DynamoDB table data

## ðŸš¨ Detection Capabilities

### Critical Events
- CloudTrail disabled/deleted (\DeleteTrail\, \StopLogging\)
- S3 bucket deletion (\DeleteBucket\)
- KMS key deletion (\ScheduleKeyDeletion\)
- Root account console login

### High Priority Events
- IAM user/role creation (\CreateUser\, \CreateRole\)
- Access key creation (\CreateAccessKey\)
- Policy modifications (\PutUserPolicy\, \AttachRolePolicy\)
- EC2 instance termination (\TerminateInstances\)
- RDS deletion (\DeleteDBInstance\)
- Security group with 0.0.0.0/0 (\AuthorizeSecurityGroupIngress\)
- Public S3 bucket policies (\PutBucketPolicy\)

### Medium Priority Events
- VPC modifications
- Security group changes
- IAM trust policy updates

## ðŸš€ Deployment

### Prerequisites
- AWS Account with appropriate IAM permissions
- Python 3.11+
- AWS CLI configured
- PowerShell (for deployment scripts) or Bash

### Quick Start

1. **Clone the repository**
\\\ash
git clone https://github.com/YOUR_USERNAME/cloudtrail-security-monitor.git
cd cloudtrail-security-monitor
\\\

2. **Configure environment**
\\\ash
cp .env.example .env
# Edit .env with your AWS account details
\\\

3. **Deploy infrastructure** (choose one)

**Option A: Manual Deployment (PowerShell)**
\\\powershell
.\cloudtrail_debug_final.ps1
\\\

**Option B: Terraform** (coming soon)
\\\ash
cd terraform
terraform init
terraform plan
terraform apply
\\\

4. **Verify deployment**
\\\powershell
.\final_verification_test.ps1
\\\

## ðŸ“ Project Structure

\\\
cloudtrail-security-monitor/
â”œâ”€â”€ cloudtrail_monitor.py          # Main Lambda handler
â”œâ”€â”€ requirements.txt                 # Python dependencies
â”œâ”€â”€ config/
â”‚   â””â”€â”€ config.yaml                  # Application configuration
â”œâ”€â”€ src/
â”‚   â”œâ”€â”€ analyzers/
â”‚   â”‚   â””â”€â”€ event_analyzer.py        # Event detection logic
â”‚   â”œâ”€â”€ handlers/
â”‚   â”‚   â””â”€â”€ alert_handler.py         # SNS alerting
â”‚   â””â”€â”€ utils/
â”‚       â”œâ”€â”€ state_manager.py         # DynamoDB operations
â”‚       â”œâ”€â”€ logger.py                # Structured logging
â”‚       â””â”€â”€ config_loader.py         # Config management
â”œâ”€â”€ tests/
â”‚   â””â”€â”€ unit/
â”‚       â””â”€â”€ test_monitor.py          # Unit tests
â””â”€â”€ terraform/                       # IaC (optional)
\\\

## ðŸ§ª Testing

### Run Verification Tests
\\\powershell
# Comprehensive test suite
.\comprehensive_test.ps1

# Final verification
.\final_verification_test.ps1

# View real-time dashboard
.\dashboard_simple.ps1
\\\

### Create Test Events
\\\ash
# Test IAM user creation detection
aws iam create-user --user-name test-user --region us-east-2

# Test EC2 termination detection
aws ec2 terminate-instances --instance-ids i-fakeid123 --region us-east-2
\\\

## ðŸ’° Cost Breakdown

| Service | Monthly Cost |
|---------|--------------|
| Lambda | ~\.12 |
| DynamoDB | ~\.05 |
| SNS | Free (email) |
| CloudTrail | Free (first trail) |
| EventBridge | Free |
| **Total** | **~\.17-0.30/month** |

## ðŸ” Security Considerations

- Lambda uses least-privilege IAM role
- DynamoDB table encrypted with KMS
- No hardcoded credentials
- CloudTrail logs encrypted in S3
- Environment variables for sensitive config

## ðŸ“Š Monitoring

View Lambda execution logs:
\\\ash
aws logs tail /aws/lambda/cloudtrail-monitor --follow --region us-east-2
\\\

Check EventBridge rule:
\\\ash
aws events describe-rule --name cloudtrail-monitor-schedule --region us-east-2
\\\

## ðŸ› ï¸ Configuration

Edit \config/config.yaml\ to customize:
- Detection patterns
- Alert thresholds
- Lookback window (default: 15 minutes)
- Severity levels

## ðŸ“§ Alert Format

Example email alert:
\\\
SECURITY ALERT - HIGH SEVERITY
1 Incidents Detected

INCIDENT #1:
  Event: TerminateInstances
  Description: EC2 instance(s) terminated
  User: RoleAuditor
  Source IP: Unknown
  Time: 2025-12-16 22:43:30+00:00
  Action: Verify termination was authorized
\\\

## ðŸ¤ Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## ðŸ“ License

MIT License - see LICENSE file for details

## ðŸŽ“ Skills Demonstrated

This project showcases:
- **AWS Services**: Lambda, CloudTrail, EventBridge, SNS, DynamoDB, KMS, IAM
- **Security**: Threat detection, event analysis, security monitoring
- **DevSecOps**: Automated security, CI/CD ready, IaC
- **Python**: Async programming, error handling, logging
- **Architecture**: Serverless design, event-driven, scalable
- **Cost Optimization**: ~\.30/month for production security monitoring

## ðŸ”— Related Projects

- [OWASP Juice Shop Deployment]((https://github.com/AFP9272000/secure-vulnerable-website-juiceshop))
- [Other DevSecOps Projects](https://github.com/AFP9272000)

## ðŸ“ž Contact

**Addison** - [LinkedIn](www.linkedin.com/in/addison-p-6406b225b) | [Email](mailto:addisonpirlo2@gmail.com)

---

â­ **Star this repo if you found it helpful!**
