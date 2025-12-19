"""
Event Analyzer - Analyzes CloudTrail events for security concerns
"""

import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging


class EventAnalyzer:
    """Analyzes CloudTrail events for security threats"""
    
    # Event patterns that indicate security concerns
    CRITICAL_EVENTS = {
        'DeleteTrail': {
            'severity': 'CRITICAL',
            'description': 'CloudTrail was disabled or deleted',
            'remediation': 'Immediately investigate who disabled CloudTrail and restore it'
        },
        'StopLogging': {
            'severity': 'CRITICAL',
            'description': 'CloudTrail logging was stopped',
            'remediation': 'Re-enable CloudTrail logging and investigate'
        },
        'DeleteBucket': {
            'severity': 'CRITICAL',
            'description': 'S3 bucket was deleted',
            'remediation': 'Verify if deletion was authorized'
        },
        'ScheduleKeyDeletion': {
            'severity': 'CRITICAL',
            'description': 'KMS key scheduled for deletion',
            'remediation': 'Cancel key deletion if unauthorized'
        },
        'ConsoleLogin': {
            'severity': 'CRITICAL',
            'description': 'Root account console login detected',
            'remediation': 'Verify root account usage was necessary',
            'condition': lambda e: self._is_root_user(e)
        }
    }
    
    HIGH_PRIORITY_EVENTS = {
        'CreateUser': {
            'severity': 'HIGH',
            'description': 'New IAM user created',
            'remediation': 'Verify user creation was authorized'
        },
        'CreateRole': {
            'severity': 'HIGH',
            'description': 'New IAM role created',
            'remediation': 'Review role permissions'
        },
        'CreateAccessKey': {
            'severity': 'HIGH',
            'description': 'New IAM access key created',
            'remediation': 'Verify key creation and ensure MFA is enabled'
        },
        'PutUserPolicy': {
            'severity': 'HIGH',
            'description': 'IAM user policy modified',
            'remediation': 'Review policy changes for privilege escalation'
        },
        'AttachUserPolicy': {
            'severity': 'HIGH',
            'description': 'Policy attached to IAM user',
            'remediation': 'Review attached policy for excessive permissions'
        },
        'AttachRolePolicy': {
            'severity': 'HIGH',
            'description': 'Policy attached to IAM role',
            'remediation': 'Review attached policy for excessive permissions'
        },
        'TerminateInstances': {
            'severity': 'HIGH',
            'description': 'EC2 instance(s) terminated',
            'remediation': 'Verify termination was authorized'
        },
        'DeleteDBInstance': {
            'severity': 'HIGH',
            'description': 'RDS database instance deleted',
            'remediation': 'Verify deletion and check if backups exist'
        },
        'AuthorizeSecurityGroupIngress': {
            'severity': 'HIGH',
            'description': 'Security group rule added',
            'remediation': 'Review for overly permissive rules (0.0.0.0/0)',
            'condition': lambda e: self._check_open_security_group(e)
        },
        'PutBucketPolicy': {
            'severity': 'HIGH',
            'description': 'S3 bucket policy modified',
            'remediation': 'Check if bucket became publicly accessible',
            'condition': lambda e: self._check_public_bucket_policy(e)
        }
    }
    
    MEDIUM_PRIORITY_EVENTS = {
        'ModifyVpcAttribute': {
            'severity': 'MEDIUM',
            'description': 'VPC attributes modified',
            'remediation': 'Review VPC configuration changes'
        },
        'CreateVpc': {
            'severity': 'MEDIUM',
            'description': 'New VPC created',
            'remediation': 'Verify VPC creation was planned'
        },
        'DeleteSecurityGroup': {
            'severity': 'MEDIUM',
            'description': 'Security group deleted',
            'remediation': 'Verify deletion was authorized'
        },
        'RevokeSecurityGroupIngress': {
            'severity': 'MEDIUM',
            'description': 'Security group rule removed',
            'remediation': 'Verify rule removal was intentional'
        },
        'UpdateAssumeRolePolicy': {
            'severity': 'MEDIUM',
            'description': 'IAM role trust policy modified',
            'remediation': 'Review trust relationship changes'
        }
    }
    
    def __init__(self, config):
        """Initialize the event analyzer
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Merge all event patterns
        self.event_patterns = {}
        self.event_patterns.update(self.CRITICAL_EVENTS)
        self.event_patterns.update(self.HIGH_PRIORITY_EVENTS)
        self.event_patterns.update(self.MEDIUM_PRIORITY_EVENTS)
        
        # Failed login tracking (for brute force detection)
        self.failed_logins = {}
    
    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a CloudTrail event for security concerns
        
        Args:
            event: CloudTrail event dictionary
            
        Returns:
            Analysis result with severity and description
        """
        event_name = event.get('EventName', '')
        event_source = event.get('EventSource', '')
        username = event.get('Username', 'Unknown')
        source_ip = event.get('SourceIPAddress', 'Unknown')
        user_agent = event.get('UserAgent', '')
        event_time = event.get('EventTime')
        
        # Check if event matches known patterns
        if event_name in self.event_patterns:
            pattern = self.event_patterns[event_name]
            
            # Check if there's a condition that must be met
            if 'condition' in pattern:
                if not pattern['condition'](event):
                    return self._create_safe_result()
            
            # Create detailed analysis
            return {
                'is_suspicious': True,
                'severity': pattern['severity'],
                'description': pattern['description'],
                'remediation': pattern['remediation'],
                'event_name': event_name,
                'username': username,
                'source_ip': source_ip,
                'event_time': str(event_time),
                'event_id': event.get('EventId'),
                'aws_region': event.get('AwsRegion', 'Unknown'),
                'details': self._extract_relevant_details(event)
            }
        
        # Check for failed console logins (potential brute force)
        if event_name == 'ConsoleLogin':
            error_code = event.get('ErrorCode', '')
            if error_code == 'Failed authentication':
                return self._check_failed_login_pattern(event)
        
        # Check for unusual API activity patterns
        unusual_activity = self._check_unusual_activity(event)
        if unusual_activity:
            return unusual_activity
        
        # Event is not suspicious
        return self._create_safe_result()
    
    def _create_safe_result(self) -> Dict[str, Any]:
        """Create a result for non-suspicious events"""
        return {
            'is_suspicious': False,
            'severity': 'INFO',
            'description': 'No security concerns detected'
        }
    
    def _is_root_user(self, event: Dict[str, Any]) -> bool:
        """Check if event was performed by root user"""
        user_identity = event.get('UserIdentity', {})
        return user_identity.get('Type') == 'Root'
    
    def _check_open_security_group(self, event: Dict[str, Any]) -> bool:
        """Check if security group rule allows 0.0.0.0/0 on sensitive ports"""
        request_params = event.get('RequestParameters', {})
        
        if not request_params:
            return False
        
        # Extract IP permissions
        ip_permissions = request_params.get('ipPermissions', {})
        if isinstance(ip_permissions, dict):
            ip_permissions = [ip_permissions]
        elif not isinstance(ip_permissions, list):
            return False
        
        # Sensitive ports
        sensitive_ports = {22, 3389, 1433, 3306, 5432, 27017}
        
        for permission in ip_permissions:
            from_port = permission.get('fromPort')
            to_port = permission.get('toPort')
            
            # Check IP ranges
            ip_ranges = permission.get('ipRanges', {})
            if isinstance(ip_ranges, dict):
                ip_ranges = [ip_ranges]
            
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('cidrIp', '')
                
                # Check if allows all IPs
                if cidr_ip == '0.0.0.0/0':
                    # Check if port range includes sensitive ports
                    if from_port and to_port:
                        for port in sensitive_ports:
                            if from_port <= port <= to_port:
                                return True
        
        return False
    
    def _check_public_bucket_policy(self, event: Dict[str, Any]) -> bool:
        """Check if S3 bucket policy makes bucket public"""
        request_params = event.get('RequestParameters', {})
        
        if not request_params:
            return False
        
        # Get bucket policy
        bucket_policy = request_params.get('bucketPolicy', '')
        
        if not bucket_policy:
            return False
        
        try:
            # Parse policy JSON
            policy = json.loads(bucket_policy) if isinstance(bucket_policy, str) else bucket_policy
            
            # Check for public access
            statements = policy.get('Statement', [])
            for statement in statements:
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check if allows public access
                if effect == 'Allow':
                    if principal == '*' or principal == {'AWS': '*'}:
                        return True
        except (json.JSONDecodeError, TypeError):
            pass
        
        return False
    
    def _check_failed_login_pattern(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Check for brute force login attempts"""
        username = event.get('Username', 'Unknown')
        source_ip = event.get('SourceIPAddress', 'Unknown')
        event_time = event.get('EventTime')
        
        # Track failed logins per username
        key = f"{username}:{source_ip}"
        
        if key not in self.failed_logins:
            self.failed_logins[key] = []
        
        self.failed_logins[key].append(event_time)
        
        # Check if more than 3 failed attempts in last 10 minutes
        recent_failures = len([
            t for t in self.failed_logins[key]
            if (event_time - t).total_seconds() < 600
        ])
        
        if recent_failures >= 3:
            return {
                'is_suspicious': True,
                'severity': 'HIGH',
                'description': f'Multiple failed login attempts detected ({recent_failures} attempts)',
                'remediation': 'Investigate potential brute force attack and consider blocking IP',
                'event_name': 'ConsoleLogin',
                'username': username,
                'source_ip': source_ip,
                'event_time': str(event_time),
                'details': {'failed_attempt_count': recent_failures}
            }
        
        return self._create_safe_result()
    
    def _check_unusual_activity(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for unusual activity patterns"""
        username = event.get('Username', 'Unknown')
        source_ip = event.get('SourceIPAddress', 'Unknown')
        user_agent = event.get('UserAgent', '')
        
        # Check for API calls from unusual locations
        # PLACEHOLDER - IN PRODUCTION MAINTAIN BASELINE
        
        # Check for suspicious user agents (potential automated attacks)
        suspicious_agents = ['curl', 'wget', 'python-requests', 'boto', 'aws-cli']
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                # This might be legitimate (automation), so only flag as medium
                return {
                    'is_suspicious': True,
                    'severity': 'MEDIUM',
                    'description': f'API call with automation tool: {agent}',
                    'remediation': 'Verify if automated access is expected',
                    'event_name': event.get('EventName'),
                    'username': username,
                    'source_ip': source_ip,
                    'event_time': str(event.get('EventTime')),
                    'details': {'user_agent': user_agent}
                }
        
        return None
    
    def _extract_relevant_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant details from event for alerting"""
        details = {}
        
        # Add request parameters if they exist
        if 'RequestParameters' in event:
            details['request_parameters'] = event['RequestParameters']
        
        # Add response elements if they exist
        if 'ResponseElements' in event:
            details['response_elements'] = event['ResponseElements']
        
        # Add error information if it exists
        if 'ErrorCode' in event:
            details['error_code'] = event['ErrorCode']
        if 'ErrorMessage' in event:
            details['error_message'] = event['ErrorMessage']
        
        # Add user identity details
        if 'UserIdentity' in event:
            user_identity = event['UserIdentity']
            details['user_identity'] = {
                'type': user_identity.get('Type'),
                'principal_id': user_identity.get('PrincipalId'),
                'arn': user_identity.get('Arn'),
                'account_id': user_identity.get('AccountId')
            }
        
        return details