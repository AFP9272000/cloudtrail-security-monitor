Critical Events:
1. Root account usage
2. CloudTrail disabled/deleted
3. IAM policy changes allowing admin access
4. Security group rule allowing 0.0.0.0/0 on sensitive ports
5. KMS key scheduled for deletion
6. S3 bucket policy changes to public

High Priority Events (Alert within 5 minutes):
1. New IAM user creation
2. New IAM role creation
3. IAM access key creation
4. Console login from new IP/country
5. EC2 instance termination
6. RDS database deletion
7. S3 bucket deletion
8. VPC/subnet deletion

Medium Priority Events (Alert within 15 minutes):
1. Security group rule modifications
2. Network ACL changes
3. Route table modifications
4. Failed console login attempts (>3 in 10 minutes)
5. Unusual API call patterns