# CloudTrail Security Monitor

Real-time AWS security monitoring system that detects suspicious activities in CloudTrail and sends instant email alerts.

![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20CloudTrail%20%7C%20SNS-orange)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Cost](https://img.shields.io/badge/Cost-~0.30%2Fmonth-brightgreen)

## Overview

An enterprise-grade security monitoring system that automatically analyzes AWS CloudTrail events and alerts on suspicious activities. Built with serverless architecture for cost-effective, scalable security operations.

**Key Features:**
- Real-time detection of 25+ high-priority security events
- Automated email alerts via SNS
- Event deduplication to prevent alert fatigue
- Runs automatically every 15 minutes via EventBridge
- Production-ready code with comprehensive error handling
- Costs less than $0.30/month to operate

## Architecture

```
CloudTrail → Lambda (every 15 min) → Event Analyzer → SNS → Email Alerts
                ↓
           DynamoDB (deduplication)
```

**Components:**
- **AWS Lambda**: Serverless function that retrieves and analyzes CloudTrail events
- **CloudTrail**: Logs all AWS API calls for security monitoring
- **EventBridge**: Triggers Lambda every 15 minutes automatically
- **DynamoDB**: Tracks processed events to prevent duplicate alerts
- **SNS**: Sends email notifications for detected incidents
- **KMS**: Encrypts DynamoDB table data

## Detection Capabilities

### Critical Events
- CloudTrail disabled/deleted (`DeleteTrail`, `StopLogging`)
- S3 bucket deletion (`DeleteBucket`)
- KMS key deletion (`ScheduleKeyDeletion`)
- Root account console login

### High Priority Events
- IAM user/role creation (`CreateUser`, `CreateRole`)
- Access key creation (`CreateAccessKey`)
- Policy modifications (`PutUserPolicy`, `AttachRolePolicy`)
- EC2 instance termination (`TerminateInstances`)
- RDS deletion (`DeleteDBInstance`)
- Security group with 0.0.0.0/0 (`AuthorizeSecurityGroupIngress`)
- Public S3 bucket policies (`PutBucketPolicy`)

### Medium Priority Events
- VPC modifications
- Security group changes
- IAM trust policy updates

## Deployment

### Prerequisites
- AWS Account with appropriate IAM permissions
- Python 3.11+
- AWS CLI configured
- PowerShell (for deployment scripts) or Bash

### Quick Start

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/cloudtrail-security-monitor.git
cd cloudtrail-security-monitor
```

**2. Configure environment**
```bash
cp .env.example .env
# Edit .env with your AWS account details
```

**3. Deploy infrastructure**

*Option A: Manual Deployment (PowerShell)*
```powershell
.\cloudtrail_debug_final.ps1
```

*Option B: Terraform* (coming soon)
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

**4. Verify deployment**
```powershell
.\final_verification_test.ps1
```

## Project Structure

```
cloudtrail-security-monitor/
├── cloudtrail_monitor.py          # Main Lambda handler
├── requirements.txt                # Python dependencies
├── config/
│   └── config.yaml                 # Application configuration
├── src/
│   ├── analyzers/
│   │   └── event_analyzer.py       # Event detection logic
│   ├── handlers/
│   │   └── alert_handler.py        # SNS alerting
│   └── utils/
│       ├── state_manager.py        # DynamoDB operations
│       ├── logger.py               # Structured logging
│       └── config_loader.py        # Config management
├── tests/
│   └── unit/
│       └── test_monitor.py         # Unit tests
└── terraform/                      # IaC (optional)
```

## Testing

### Run Verification Tests
```powershell
# Comprehensive test suite
.\comprehensive_test.ps1

# Final verification
.\final_verification_test.ps1

# View real-time dashboard
.\dashboard_simple.ps1
```

### Create Test Events
```bash
# Test IAM user creation detection
aws iam create-user --user-name test-user --region us-east-2

# Test EC2 termination detection
aws ec2 terminate-instances --instance-ids i-fakeid123 --region us-east-2
```

## Cost Breakdown

| Service | Monthly Cost |
|---------|--------------|
| Lambda | ~$0.12 |
| DynamoDB | ~$0.05 |
| SNS | Free (email) |
| CloudTrail | Free (first trail) |
| EventBridge | Free |
| **Total** | **~$0.17-0.30/month** |

## Security Considerations

- Lambda uses least-privilege IAM role
- DynamoDB table encrypted with KMS
- No hardcoded credentials
- CloudTrail logs encrypted in S3
- Environment variables for sensitive config

## Monitoring

**View Lambda execution logs:**
```bash
aws logs tail /aws/lambda/cloudtrail-monitor --follow --region us-east-2
```

**Check EventBridge rule:**
```bash
aws events describe-rule --name cloudtrail-monitor-schedule --region us-east-2
```

## Configuration

Edit `config/config.yaml` to customize:
- Detection patterns
- Alert thresholds
- Lookback window (default: 15 minutes)
- Severity levels

## Alert Format

Example email alert:
```
SECURITY ALERT - HIGH SEVERITY
1 Incidents Detected

INCIDENT #1:
  Event: TerminateInstances
  Description: EC2 instance(s) terminated
  User: RoleAuditor
  Source IP: Unknown
  Time: 2025-12-16 22:43:30+00:00
  Action: Verify termination was authorized
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Skills Demonstrated

This project showcases:
- **AWS Services**: Lambda, CloudTrail, EventBridge, SNS, DynamoDB, KMS, IAM
- **Security**: Threat detection, event analysis, security monitoring
- **DevSecOps**: Automated security, CI/CD ready, IaC
- **Python**: Async programming, error handling, logging
- **Architecture**: Serverless design, event-driven, scalable
- **Cost Optimization**: ~$0.30/month for production security monitoring

## Related Projects

- [OWASP Juice Shop Deployment](https://github.com/AddisonPirlo/owasp-juice-shop-devsecops)
- [Other DevSecOps Projects](https://github.com/AddisonPirlo)

## Contact

**Addison Pirlo** - [LinkedIn](https://www.linkedin.com/in/addison-pirlo-98b1a8297/) | [Email](mailto:addisonpirlo2@gmail.com)

---

⭐ **Star this repo if you found it helpful!**
