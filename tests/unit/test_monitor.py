"""
Unit tests for CloudTrail Monitor
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
from moto import mock_cloudtrail, mock_sns, mock_dynamodb

# Import modules to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.event_analyzer import EventAnalyzer
from src.handlers.alert_handler import AlertHandler
from src.utils.state_manager import StateManager
from src.utils.config_loader import ConfigLoader


class TestEventAnalyzer:
    """Tests for EventAnalyzer"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return ConfigLoader()
    
    @pytest.fixture
    def analyzer(self, config):
        """Create EventAnalyzer instance"""
        return EventAnalyzer(config)
    
    def test_analyze_critical_event_delete_trail(self, analyzer):
        """Test detection of CloudTrail deletion"""
        event = {
            'EventName': 'DeleteTrail',
            'Username': 'test-user',
            'SourceIPAddress': '192.168.1.1',
            'EventTime': datetime.utcnow(),
            'EventId': 'test-event-123',
            'AwsRegion': 'us-east-1',
            'UserIdentity': {
                'Type': 'IAMUser',
                'PrincipalId': 'AIDACKCEVSQ6C2EXAMPLE',
                'Arn': 'arn:aws:iam::123456789012:user/test-user'
            }
        }
        
        result = analyzer.analyze_event(event)
        
        assert result['is_suspicious'] is True
        assert result['severity'] == 'CRITICAL'
        assert result['event_name'] == 'DeleteTrail'
        assert 'disabled or deleted' in result['description']
    
    def test_analyze_high_priority_create_user(self, analyzer):
        """Test detection of new IAM user creation"""
        event = {
            'EventName': 'CreateUser',
            'Username': 'admin-user',
            'SourceIPAddress': '10.0.0.1',
            'EventTime': datetime.utcnow(),
            'EventId': 'test-event-456',
            'AwsRegion': 'us-west-2',
            'UserIdentity': {
                'Type': 'IAMUser',
                'Arn': 'arn:aws:iam::123456789012:user/admin-user'
            },
            'RequestParameters': {
                'userName': 'new-test-user'
            }
        }
        
        result = analyzer.analyze_event(event)
        
        assert result['is_suspicious'] is True
        assert result['severity'] == 'HIGH'
        assert result['event_name'] == 'CreateUser'
    
    def test_analyze_root_login(self, analyzer):
        """Test detection of root account login"""
        event = {
            'EventName': 'ConsoleLogin',
            'Username': 'root',
            'SourceIPAddress': '203.0.113.10',
            'EventTime': datetime.utcnow(),
            'EventId': 'test-event-789',
            'AwsRegion': 'us-east-1',
            'UserIdentity': {
                'Type': 'Root',
                'PrincipalId': 'root',
                'Arn': 'arn:aws:iam::123456789012:root'
            }
        }
        
        result = analyzer.analyze_event(event)
        
        assert result['is_suspicious'] is True
        assert result['severity'] == 'CRITICAL'
        assert 'Root account' in result['description']
    
    def test_analyze_open_security_group(self, analyzer):
        """Test detection of overly permissive security group"""
        event = {
            'EventName': 'AuthorizeSecurityGroupIngress',
            'Username': 'developer',
            'SourceIPAddress': '172.16.0.1',
            'EventTime': datetime.utcnow(),
            'EventId': 'test-event-sg-123',
            'AwsRegion': 'us-east-1',
            'UserIdentity': {
                'Type': 'IAMUser'
            },
            'RequestParameters': {
                'groupId': 'sg-12345678',
                'ipPermissions': {
                    'items': [
                        {
                            'fromPort': 22,
                            'toPort': 22,
                            'ipProtocol': 'tcp',
                            'ipRanges': {
                                'items': [
                                    {'cidrIp': '0.0.0.0/0'}
                                ]
                            }
                        }
                    ]
                }
            }
        }
        
        result = analyzer.analyze_event(event)
        
        assert result['is_suspicious'] is True
        assert result['severity'] == 'HIGH'
    
    def test_analyze_safe_event(self, analyzer):
        """Test that safe events are not flagged"""
        event = {
            'EventName': 'DescribeInstances',
            'Username': 'readonly-user',
            'SourceIPAddress': '192.168.1.100',
            'EventTime': datetime.utcnow(),
            'EventId': 'test-event-safe',
            'AwsRegion': 'us-east-1',
            'UserIdentity': {
                'Type': 'IAMUser'
            }
        }
        
        result = analyzer.analyze_event(event)
        
        assert result['is_suspicious'] is False
        assert result['severity'] == 'INFO'
    
    def test_failed_login_brute_force_detection(self, analyzer):
        """Test detection of brute force login attempts"""
        # Simulate multiple failed logins
        for i in range(4):
            event = {
                'EventName': 'ConsoleLogin',
                'Username': 'attacker',
                'SourceIPAddress': '198.51.100.1',
                'EventTime': datetime.utcnow(),
                'EventId': f'test-event-login-{i}',
                'AwsRegion': 'us-east-1',
                'ErrorCode': 'Failed authentication',
                'UserIdentity': {
                    'Type': 'IAMUser'
                }
            }
            
            result = analyzer.analyze_event(event)
            
            if i >= 2:  # 3rd failed attempt should trigger
                assert result['is_suspicious'] is True
                assert result['severity'] == 'HIGH'
                assert 'Multiple failed login attempts' in result['description']


class TestAlertHandler:
    """Tests for AlertHandler"""
    
    @pytest.fixture
    def mock_sns_client(self):
        """Create mock SNS client"""
        client = Mock()
        client.publish = Mock(return_value={'MessageId': 'test-msg-id'})
        return client
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return ConfigLoader()
    
    @pytest.fixture
    def alert_handler(self, mock_sns_client, config):
        """Create AlertHandler instance"""
        return AlertHandler(
            mock_sns_client,
            'arn:aws:sns:us-east-1:123456789012:test-topic',
            config
        )
    
    def test_send_critical_alert(self, alert_handler, mock_sns_client):
        """Test sending critical alert"""
        incident = {
            'event': {
                'EventName': 'DeleteTrail',
                'Username': 'test-user'
            },
            'analysis': {
                'is_suspicious': True,
                'severity': 'CRITICAL',
                'description': 'CloudTrail deleted',
                'remediation': 'Investigate immediately',
                'event_name': 'DeleteTrail',
                'username': 'test-user',
                'source_ip': '192.168.1.1',
                'event_time': '2024-01-01T12:00:00Z',
                'event_id': 'test-123',
                'aws_region': 'us-east-1',
                'details': {}
            }
        }
        
        result = alert_handler.send_alert(incident)
        
        assert result is True
        mock_sns_client.publish.assert_called_once()
        
        # Verify SNS call parameters
        call_args = mock_sns_client.publish.call_args
        assert 'Subject' in call_args[1]
        assert '[CRITICAL]' in call_args[1]['Subject']
        assert 'Message' in call_args[1]
    
    def test_send_batch_alert(self, alert_handler, mock_sns_client):
        """Test sending batch alert"""
        incidents = []
        for i in range(3):
            incidents.append({
                'event': {'EventName': f'TestEvent{i}'},
                'analysis': {
                    'severity': 'HIGH',
                    'description': f'Test incident {i}',
                    'remediation': 'Test action',
                    'event_name': f'TestEvent{i}',
                    'username': 'test-user',
                    'source_ip': '192.168.1.1',
                    'event_time': '2024-01-01T12:00:00Z'
                }
            })
        
        result = alert_handler.send_batch_alert(incidents, 'HIGH')
        
        assert result is True
        mock_sns_client.publish.assert_called_once()
    
    def test_alert_cooldown(self, alert_handler):
        """Test alert cooldown mechanism"""
        incident = {
            'event': {'EventName': 'CreateUser'},
            'analysis': {
                'severity': 'HIGH',
                'description': 'User created',
                'remediation': 'Verify',
                'event_name': 'CreateUser',
                'username': 'test-user',
                'source_ip': '192.168.1.1',
                'event_time': '2024-01-01T12:00:00Z',
                'event_id': 'test-456',
                'aws_region': 'us-east-1',
                'details': {}
            }
        }
        
        # First alert should succeed
        result1 = alert_handler.send_alert(incident)
        assert result1 is True
        
        # Second alert should be suppressed (cooldown)
        result2 = alert_handler.send_alert(incident)
        assert result2 is False


@mock_dynamodb
class TestStateManager:
    """Tests for StateManager"""
    
    @pytest.fixture
    def dynamodb_client(self):
        """Create mock DynamoDB client"""
        import boto3
        client = boto3.client('dynamodb', region_name='us-east-1')
        
        # Create test table
        client.create_table(
            TableName='test-state-table',
            KeySchema=[
                {'AttributeName': 'event_id', 'KeyType': 'HASH'},
                {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'event_id', 'AttributeType': 'S'},
                {'AttributeName': 'timestamp', 'AttributeType': 'N'},
                {'AttributeName': 'processed', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'processed-time-index',
                    'KeySchema': [
                        {'AttributeName': 'processed', 'KeyType': 'HASH'},
                        {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            BillingMode='PROVISIONED',
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        
        return client
    
    @pytest.fixture
    def state_manager(self, dynamodb_client):
        """Create StateManager instance"""
        return StateManager(dynamodb_client, 'test-state-table')
    
    def test_mark_and_check_processed(self, state_manager):
        """Test marking events as processed and checking"""
        event_id = 'test-event-123'
        event_time = datetime.utcnow()
        
        # Initially should not be processed
        assert state_manager.is_processed(event_id) is False
        
        # Mark as processed
        result = state_manager.mark_processed(event_id, event_time)
        assert result is True
        
        # Now should be processed
        assert state_manager.is_processed(event_id) is True
    
    def test_get_last_processed_time(self, state_manager):
        """Test retrieving last processed time"""
        # Mark several events
        for i in range(3):
            event_time = datetime.utcnow() - timedelta(minutes=i)
            state_manager.mark_processed(f'event-{i}', event_time)
        
        # Get last processed time
        last_time = state_manager.get_last_processed_time()
        assert last_time is not None


class TestConfigLoader:
    """Tests for ConfigLoader"""
    
    def test_default_config(self):
        """Test loading default configuration"""
        config = ConfigLoader()
        
        assert config.get('monitoring.lookback_minutes') == 15
        assert config.get('alerts.cooldown_minutes') == 60
        assert config.get('logging.level') == 'INFO'
    
    def test_get_nested_config(self):
        """Test getting nested configuration values"""
        config = ConfigLoader()
        
        value = config.get('monitoring.lookback_minutes')
        assert value == 15
        
        default_value = config.get('nonexistent.key', 'default')
        assert default_value == 'default'
    
    def test_set_config_value(self):
        """Test setting configuration values"""
        config = ConfigLoader()
        
        config.set('monitoring.lookback_minutes', 30)
        assert config.get('monitoring.lookback_minutes') == 30
    
    def test_config_validation(self):
        """Test configuration validation"""
        config = ConfigLoader()
        
        # Invalid lookback minutes should raise error
        with pytest.raises(ValueError):
            config.set('monitoring.lookback_minutes', 2000)
            config._validate_config()


# Integration test
class TestIntegration:
    """Integration tests"""
    
    @patch('boto3.client')
    def test_end_to_end_flow(self, mock_boto_client):
        """Test complete monitoring flow"""
        # This would test the full flow from event retrieval to alerting
        # Keeping it simple for now
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])