"""
Alert Handler - Manages security alert delivery via multiple channels
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

from botocore.exceptions import ClientError


class AlertHandler:
    """Handles alert formatting and delivery"""
    
    # Alert templates
    ALERT_TEMPLATES = {
        'CRITICAL': {
            'emoji': '🚨',
            'prefix': '[CRITICAL]',
            'color': '#DC143C'
        },
        'HIGH': {
            'emoji': '⚠️',
            'prefix': '[HIGH]',
            'color': '#FF8C00'
        },
        'MEDIUM': {
            'emoji': '⚡',
            'prefix': '[MEDIUM]',
            'color': '#FFD700'
        }
    }
    
    def __init__(self, sns_client, sns_topic_arn: str, config):
        """Initialize alert handler
        
        Args:
            sns_client: Boto3 SNS client
            sns_topic_arn: ARN of SNS topic for alerts
            config: Configuration object
        """
        self.sns_client = sns_client
        self.sns_topic_arn = sns_topic_arn
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Alert tracking (for deduplication and cooldown)
        self.recent_alerts = {}
        self.cooldown_minutes = int(os.getenv('ALERT_COOLDOWN_MINUTES', '60'))
        
        # Optional integrations
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.enable_slack = os.getenv('ENABLE_SLACK', 'false').lower() == 'true'
    
    def send_alert(self, incident: Dict[str, Any]) -> bool:
        """Send alert for a single incident
        
        Args:
            incident: Incident dictionary with event and analysis
            
        Returns:
            True if alert sent successfully
        """
        analysis = incident['analysis']
        event = incident['event']
        
        # Check if we should suppress this alert (cooldown)
        if self._should_suppress_alert(incident):
            self.logger.info(
                f"Suppressing duplicate alert for {analysis['event_name']} "
                f"(cooldown period active)"
            )
            return False
        
        try:
            # Format alert message
            subject = self._format_alert_subject(analysis)
            message = self._format_alert_message(analysis, event)
            
            # Send via SNS
            self._send_sns_alert(subject, message, analysis['severity'])
            
            # Send via Slack if enabled
            if self.enable_slack and self.slack_webhook_url:
                self._send_slack_alert(analysis, event)
            
            # Track this alert
            self._track_alert(incident)
            
            self.logger.info(f"Alert sent successfully for {analysis['event_name']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
            return False
    
    def send_batch_alert(self, incidents: List[Dict[str, Any]], severity: str) -> bool:
        """Send a batched alert for multiple incidents
        
        Args:
            incidents: List of incidents
            severity: Severity level
            
        Returns:
            True if alert sent successfully
        """
        if not incidents:
            return False
        
        try:
            # Format batch message
            subject = f"[{severity}] {len(incidents)} Security Incidents Detected"
            message = self._format_batch_message(incidents, severity)
            
            # Send via SNS
            self._send_sns_alert(subject, message, severity)
            
            # Send via Slack if enabled
            if self.enable_slack and self.slack_webhook_url:
                self._send_slack_batch_alert(incidents, severity)
            
            self.logger.info(f"Batch alert sent for {len(incidents)} incidents")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send batch alert: {e}")
            return False
    
    def _format_alert_subject(self, analysis: Dict[str, Any]) -> str:
        """Format alert subject line"""
        template = self.ALERT_TEMPLATES[analysis['severity']]
        return f"{template['prefix']} {analysis['description']}"
    
    def _format_alert_message(self, analysis: Dict[str, Any], event: Dict[str, Any]) -> str:
        """Format detailed alert message"""
        template = self.ALERT_TEMPLATES[analysis['severity']]
        
        message_parts = [
            "=" * 70,
            f"{template['emoji']} SECURITY ALERT - {analysis['severity']} SEVERITY",
            "=" * 70,
            "",
            f"Event: {analysis['event_name']}",
            f"Description: {analysis['description']}",
            f"Time: {analysis['event_time']}",
            f"User: {analysis['username']}",
            f"Source IP: {analysis['source_ip']}",
            f"AWS Region: {analysis['aws_region']}",
            f"Event ID: {analysis['event_id']}",
            "",
            "RECOMMENDED ACTION:",
            f"  {analysis['remediation']}",
            ""
        ]
        
        # Add detailed information if available
        if 'details' in analysis and analysis['details']:
            message_parts.append("ADDITIONAL DETAILS:")
            details = analysis['details']
            
            # Format user identity
            if 'user_identity' in details:
                user_id = details['user_identity']
                message_parts.extend([
                    f"  User Type: {user_id.get('type', 'Unknown')}",
                    f"  Principal ID: {user_id.get('principal_id', 'Unknown')}",
                    f"  ARN: {user_id.get('arn', 'Unknown')}",
                    f"  Account ID: {user_id.get('account_id', 'Unknown')}",
                ])
            
            # Format request parameters
            if 'request_parameters' in details:
                message_parts.append("")
                message_parts.append("  Request Parameters:")
                req_params = details['request_parameters']
                message_parts.append(f"    {json.dumps(req_params, indent=6)}")
            
            # Format error information
            if 'error_code' in details:
                message_parts.append("")
                message_parts.append(f"  Error Code: {details['error_code']}")
            if 'error_message' in details:
                message_parts.append(f"  Error Message: {details['error_message']}")
            
            message_parts.append("")
        
        message_parts.extend([
            "=" * 70,
            "This is an automated security alert from CloudTrail Monitor",
            f"Generated at: {datetime.utcnow().isoformat()}Z",
            "=" * 70
        ])
        
        return "\n".join(message_parts)
    
    def _format_batch_message(self, incidents: List[Dict[str, Any]], severity: str) -> str:
        """Format batch alert message"""
        template = self.ALERT_TEMPLATES[severity]
        
        message_parts = [
            "=" * 70,
            f"{template['emoji']} SECURITY ALERT - {severity} SEVERITY",
            f"{len(incidents)} Incidents Detected",
            "=" * 70,
            ""
        ]
        
        # Summarize each incident
        for i, incident in enumerate(incidents, 1):
            analysis = incident['analysis']
            message_parts.extend([
                f"INCIDENT #{i}:",
                f"  Event: {analysis['event_name']}",
                f"  Description: {analysis['description']}",
                f"  User: {analysis['username']}",
                f"  Source IP: {analysis['source_ip']}",
                f"  Time: {analysis['event_time']}",
                f"  Action: {analysis['remediation']}",
                ""
            ])
        
        message_parts.extend([
            "=" * 70,
            "This is an automated security alert from CloudTrail Monitor",
            f"Generated at: {datetime.utcnow().isoformat()}Z",
            "=" * 70
        ])
        
        return "\n".join(message_parts)
    
    def _send_sns_alert(self, subject: str, message: str, severity: str) -> None:
        """Send alert via SNS
        
        Args:
            subject: Alert subject
            message: Alert message
            severity: Severity level
        """
        try:
            response = self.sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject,
                Message=message,
                MessageAttributes={
                    'severity': {
                        'DataType': 'String',
                        'StringValue': severity
                    },
                    'alert_type': {
                        'DataType': 'String',
                        'StringValue': 'security'
                    }
                }
            )
            
            self.logger.debug(f"SNS message published: {response['MessageId']}")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(f"SNS publish failed: {error_code} - {e}")
            raise
    
    def _send_slack_alert(self, analysis: Dict[str, Any], event: Dict[str, Any]) -> None:
        """Send alert to Slack
        
        Args:
            analysis: Analysis result
            event: CloudTrail event
        """
        if not self.slack_webhook_url:
            return
        
        try:
            import requests
            
            template = self.ALERT_TEMPLATES[analysis['severity']]
            
            # Create Slack message
            slack_message = {
                'text': f"{template['emoji']} *Security Alert - {analysis['severity']}*",
                'attachments': [
                    {
                        'color': template['color'],
                        'fields': [
                            {
                                'title': 'Event',
                                'value': analysis['event_name'],
                                'short': True
                            },
                            {
                                'title': 'User',
                                'value': analysis['username'],
                                'short': True
                            },
                            {
                                'title': 'Description',
                                'value': analysis['description'],
                                'short': False
                            },
                            {
                                'title': 'Source IP',
                                'value': analysis['source_ip'],
                                'short': True
                            },
                            {
                                'title': 'Time',
                                'value': analysis['event_time'],
                                'short': True
                            },
                            {
                                'title': 'Recommended Action',
                                'value': analysis['remediation'],
                                'short': False
                            }
                        ],
                        'footer': 'CloudTrail Security Monitor',
                        'ts': int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.slack_webhook_url,
                json=slack_message,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.debug("Slack alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
    
    def _send_slack_batch_alert(self, incidents: List[Dict[str, Any]], severity: str) -> None:
        """Send batch alert to Slack"""
        if not self.slack_webhook_url:
            return
        
        try:
            import requests
            
            template = self.ALERT_TEMPLATES[severity]
            
            # Create fields for each incident
            fields = []
            for i, incident in enumerate(incidents[:5], 1):  # Limit to 5 for readability
                analysis = incident['analysis']
                fields.append({
                    'title': f'Incident #{i}: {analysis["event_name"]}',
                    'value': f"{analysis['description']}\nUser: {analysis['username']}\nTime: {analysis['event_time']}",
                    'short': False
                })
            
            if len(incidents) > 5:
                fields.append({
                    'title': 'Additional Incidents',
                    'value': f'... and {len(incidents) - 5} more incidents',
                    'short': False
                })
            
            slack_message = {
                'text': f"{template['emoji']} *Security Alert - {severity}*\n{len(incidents)} incidents detected",
                'attachments': [
                    {
                        'color': template['color'],
                        'fields': fields,
                        'footer': 'CloudTrail Security Monitor',
                        'ts': int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.slack_webhook_url,
                json=slack_message,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.debug("Slack batch alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack batch alert: {e}")
    
    def _should_suppress_alert(self, incident: Dict[str, Any]) -> bool:
        """Check if alert should be suppressed due to cooldown
        
        Args:
            incident: Incident to check
            
        Returns:
            True if alert should be suppressed
        """
        analysis = incident['analysis']
        
        # Create a unique key for this type of alert
        alert_key = f"{analysis['event_name']}:{analysis['username']}"
        
        # Check if we've sent this alert recently
        if alert_key in self.recent_alerts:
            last_alert_time = self.recent_alerts[alert_key]
            time_since_last = (datetime.utcnow() - last_alert_time).total_seconds() / 60
            
            if time_since_last < self.cooldown_minutes:
                return True
        
        return False
    
    def _track_alert(self, incident: Dict[str, Any]) -> None:
        """Track that we sent an alert
        
        Args:
            incident: Incident that was alerted on
        """
        analysis = incident['analysis']
        alert_key = f"{analysis['event_name']}:{analysis['username']}"
        self.recent_alerts[alert_key] = datetime.utcnow()