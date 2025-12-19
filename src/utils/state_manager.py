"""
State Manager - Tracks processed events using DynamoDB
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from botocore.exceptions import ClientError


class StateManager:
    """Manages event processing state in DynamoDB"""
    
    def __init__(self, dynamodb_client, table_name: str):
        """Initialize state manager
        
        Args:
            dynamodb_client: Boto3 DynamoDB client
            table_name: Name of DynamoDB table
        """
        self.dynamodb = dynamodb_client
        self.table_name = table_name
        self.logger = logging.getLogger(__name__)
        
        # Cache of processed event IDs (in-memory for this session)
        self.processed_cache = set()
        
        # Verify table exists
        self._verify_table()
    
    def _verify_table(self) -> None:
        """Verify DynamoDB table exists"""
        try:
            self.dynamodb.describe_table(TableName=self.table_name)
            self.logger.debug(f"DynamoDB table {self.table_name} verified")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.logger.error(
                    f"DynamoDB table {self.table_name} not found. "
                    "Please create it first."
                )
                raise
            else:
                self.logger.error(f"Error verifying DynamoDB table: {e}")
                raise
    
    def is_processed(self, event_id: str) -> bool:
        """Check if an event has already been processed
        
        Args:
            event_id: CloudTrail event ID
            
        Returns:
            True if event has been processed
        """
        # Check in-memory cache first (for this session)
        if event_id in self.processed_cache:
            self.logger.debug(f"Event {event_id} found in cache")
            return True
        
        # Query DynamoDB to see if event exists
        try:
            response = self.dynamodb.query(
                TableName=self.table_name,
                KeyConditionExpression='event_id = :event_id',
                ExpressionAttributeValues={
                    ':event_id': {'S': event_id}
                },
                Limit=1
            )
            
            exists = response.get('Count', 0) > 0
            
            if exists:
                self.logger.debug(f"Event {event_id} already processed")
                self.processed_cache.add(event_id)
            
            return exists
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(
                f"Error checking if event processed: {error_code} - {e}"
            )
            # On error, assume not processed to avoid missing events
            return False
    
    def mark_processed(self, event_id: str, event_time) -> bool:
        """Mark an event as processed
        
        Args:
            event_id: CloudTrail event ID
            event_time: Event timestamp (datetime object)
            
        Returns:
            True if successfully marked
        """
        try:
            # Convert datetime to timestamp
            if isinstance(event_time, datetime):
                timestamp = int(event_time.timestamp())
            elif isinstance(event_time, (int, float)):
                timestamp = int(event_time)
            else:
                # Fallback: use current time
                timestamp = int(datetime.now(timezone.utc).timestamp())
            
            self.dynamodb.put_item(
                TableName=self.table_name,
                Item={
                    'event_id': {'S': event_id},
                    'timestamp': {'N': str(timestamp)},
                    'processed': {'S': 'true'},
                    'processed_at': {'N': str(int(datetime.now(timezone.utc).timestamp()))}
                }
            )
            
            # Add to cache
            self.processed_cache.add(event_id)
            
            self.logger.debug(f"Marked event {event_id} as processed")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(
                f"Error marking event as processed: {error_code} - {e}"
            )
            return False
    
    def get_last_processed_time(self) -> Optional[datetime]:
        """Get timestamp of most recently processed event
        
        Returns:
            Datetime of last processed event, or None
        """
        try:
            # Query using the GSI
            response = self.dynamodb.query(
                TableName=self.table_name,
                IndexName='processed-time-index',
                KeyConditionExpression='processed = :proc',
                ExpressionAttributeValues={
                    ':proc': {'S': 'true'}
                },
                ScanIndexForward=False,  # Descending order
                Limit=1
            )
            
            if 'Items' in response and len(response['Items']) > 0:
                item = response['Items'][0]
                timestamp = int(item['timestamp']['N'])
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            
            return None
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(
                f"Error getting last processed time: {error_code} - {e}"
            )
            return None