#!/usr/bin/env python3
"""
CloudTrail Security Monitor - Main Entry Point
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from dotenv import load_dotenv

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzers.event_analyzer import EventAnalyzer
from src.handlers.alert_handler import AlertHandler
from src.utils.logger import setup_logger
from src.utils.state_manager import StateManager
from src.utils.config_loader import ConfigLoader

# Load environment variables
load_dotenv()


class CloudTrailMonitor:
    """Main CloudTrail monitoring class"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the CloudTrail monitor
        
        Args:
            config_path: Path to configuration file
        """
        # Setup logging first
        self.logger = setup_logger(__name__)
        self.logger.info("Initializing CloudTrail Security Monitor")
        
        # Load configuration
        self.config = ConfigLoader(config_path)
        
        # Initialize AWS clients - FORCE region to us-east-2
        self.region = os.getenv('AWS_DEFAULT_REGION') or os.getenv('AWS_REGION') or 'us-east-2'
        self.account_id = os.getenv('AWS_ACCOUNT_ID')
        
        # DEBUG: Log what region we're using
        self.logger.info(f"Using AWS Region: {self.region}")
        self.logger.info(f"DynamoDB Table: {os.getenv('DYNAMODB_TABLE')}")
        
        try:
            # Explicitly set region for all clients
            self.cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-2')
            self.sns_client = boto3.client('sns', region_name='us-east-2')
            self.dynamodb_client = boto3.client('dynamodb', region_name='us-east-2')
            
            self.logger.info(f"AWS clients initialized in region: {self.region}")
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS clients: {e}")
            raise
        
        # Initialize components
        self.event_analyzer = EventAnalyzer(self.config)
        self.alert_handler = AlertHandler(
            self.sns_client,
            os.getenv('SNS_TOPIC_ARN'),
            self.config
        )
        self.state_manager = StateManager(
            self.dynamodb_client,
            os.getenv('DYNAMODB_TABLE', 'cloudtrail-monitor-state')
        )
        
        # Monitoring parameters
        self.lookback_minutes = int(os.getenv('LOOKBACK_MINUTES', '15'))
        
        self.logger.info("CloudTrail Security Monitor initialized successfully")
    
    def get_cloudtrail_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Retrieve CloudTrail events within time range
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of CloudTrail events
        """
        self.logger.info(f"Retrieving CloudTrail events from {start_time} to {end_time}")
        
        events = []
        next_token = None
        max_results = 50
        
        try:
            while True:
                params = {
                    'StartTime': start_time,
                    'EndTime': end_time,
                    'MaxResults': max_results
                }
                
                if next_token:
                    params['NextToken'] = next_token
                
                response = self.cloudtrail_client.lookup_events(**params)
                
                batch_events = response.get('Events', [])
                events.extend(batch_events)
                
                self.logger.debug(f"Retrieved {len(batch_events)} events in this batch")
                
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            self.logger.info(f"Retrieved total of {len(events)} events")
            return events
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(f"AWS API error retrieving events: {error_code} - {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving events: {e}")
            raise
    
    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and analyze CloudTrail events
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of security incidents detected
        """
        self.logger.info(f"Processing {len(events)} events")
        
        incidents = []
        processed_count = 0
        skipped_count = 0
        
# ... inside process_events method ...
        for event in events:
            try:
                # Extract event ID
                event_id = event.get('EventId')
                
                # Check if we've already processed this event
                if self.state_manager.is_processed(event_id):
                    skipped_count += 1
                    continue
                
                # Analyze event for security issues
                analysis_result = self.event_analyzer.analyze_event(event)

                # DEBUG: Log what we're analyzing <--- CORRECTED INDENTATION
                self.logger.debug(
                    f"Analyzed {event.get('EventName')}: suspicious={analysis_result['is_suspicious']}, severity={analysis_result.get('severity', 'N/A')}"
                )
               
                if analysis_result['is_suspicious']:
                    incidents.append({
                        'event': event,
                        'analysis': analysis_result
                    })
                    self.logger.warning(
                        f"Security incident detected: {analysis_result['severity']} - "
                        f"{analysis_result['description']}"
                    )
                
                # Mark event as processed
                self.state_manager.mark_processed(event_id, event.get('EventTime'))
                processed_count += 1
                
            except Exception as e:
                self.logger.error(f"Error processing event {event.get('EventId')}: {e}")
                continue
        
        self.logger.info(
            f"Processing complete: {processed_count} processed, "
            f"{skipped_count} skipped, {len(incidents)} incidents found"
        )
        
        return incidents
    
    def send_alerts(self, incidents: List[Dict[str, Any]]) -> None:
        """Send alerts for detected incidents
        
        Args:
            incidents: List of security incidents
        """
        if not incidents:
            self.logger.info("No incidents to alert on")
            return
        
        self.logger.info(f"Sending alerts for {len(incidents)} incidents")
        
        # Group incidents by severity
        critical_incidents = [i for i in incidents if i['analysis']['severity'] == 'CRITICAL']
        high_incidents = [i for i in incidents if i['analysis']['severity'] == 'HIGH']
        medium_incidents = [i for i in incidents if i['analysis']['severity'] == 'MEDIUM']
        
        # Send critical incidents immediately
        for incident in critical_incidents:
            try:
                self.alert_handler.send_alert(incident)
            except Exception as e:
                self.logger.error(f"Failed to send critical alert: {e}")
        
        # Batch high and medium severity alerts
        if high_incidents:
            try:
                self.alert_handler.send_batch_alert(high_incidents, 'HIGH')
            except Exception as e:
                self.logger.error(f"Failed to send high severity batch alert: {e}")
        
        if medium_incidents:
            try:
                self.alert_handler.send_batch_alert(medium_incidents, 'MEDIUM')
            except Exception as e:
                self.logger.error(f"Failed to send medium severity batch alert: {e}")
        
        self.logger.info("Alert sending complete")
    
    def run(self) -> Dict[str, Any]:
        """Main execution method
        
        Returns:
            Execution summary
        """
        start_execution = datetime.now(timezone.utc)
        self.logger.info("=" * 80)
        self.logger.info("Starting CloudTrail Security Monitor execution")
        self.logger.info("=" * 80)
        
        try:
            # Calculate time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=self.lookback_minutes)
            
            # Retrieve events
            events = self.get_cloudtrail_events(start_time, end_time)
            
            # Process events
            incidents = self.process_events(events)
            
            # Send alerts
            self.send_alerts(incidents)
            
            # Calculate execution time
            execution_time = (datetime.now(timezone.utc) - start_execution).total_seconds()
            
            # Create summary
            summary = {
                'status': 'SUCCESS',
                'execution_time_seconds': execution_time,
                'events_retrieved': len(events),
                'incidents_detected': len(incidents),
                'critical_incidents': len([i for i in incidents if i['analysis']['severity'] == 'CRITICAL']),
                'high_incidents': len([i for i in incidents if i['analysis']['severity'] == 'HIGH']),
                'medium_incidents': len([i for i in incidents if i['analysis']['severity'] == 'MEDIUM']),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
            self.logger.info("=" * 80)
            self.logger.info("Execution Summary:")
            self.logger.info(f"  Status: {summary['status']}")
            self.logger.info(f"  Execution Time: {summary['execution_time_seconds']:.2f}s")
            self.logger.info(f"  Events Retrieved: {summary['events_retrieved']}")
            self.logger.info(f"  Incidents Detected: {summary['incidents_detected']}")
            self.logger.info(f"    - Critical: {summary['critical_incidents']}")
            self.logger.info(f"    - High: {summary['high_incidents']}")
            self.logger.info(f"    - Medium: {summary['medium_incidents']}")
            self.logger.info("=" * 80)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Execution failed: {e}", exc_info=True)
            return {
                'status': 'FAILED',
                'error': str(e),
                'execution_time_seconds': (datetime.now(timezone.utc) - start_execution).total_seconds()
            }


def main():
    """Main entry point"""
    try:
        # Initialize monitor
        config_path = os.getenv('CONFIG_PATH', 'config/config.yaml')
        monitor = CloudTrailMonitor(config_path)
        
        # Run monitoring
        summary = monitor.run()
        
        # Exit with appropriate code
        if summary['status'] == 'SUCCESS':
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

def lambda_handler(event, context):
    """AWS Lambda handler function"""
    try:
        # Initialize monitor
        config_path = os.getenv('CONFIG_PATH', 'config/config.yaml')
        monitor = CloudTrailMonitor(config_path)
        
        # Run monitoring
        summary = monitor.run()
        
        return {
            'statusCode': 200 if summary['status'] == 'SUCCESS' else 500,
            'body': json.dumps(summary)
        }
            
    except Exception as e:
        print(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

if __name__ == '__main__':
    main()