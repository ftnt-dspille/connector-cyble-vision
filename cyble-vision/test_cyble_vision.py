import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from connectors.core.connector import ConnectorError

# Add the parent directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
connector_dir = os.path.dirname(current_dir)
if connector_dir not in sys.path:
    sys.path.append(connector_dir)

# Import operations using importlib
operations = importlib.import_module('cyble-vision.operations')
fetch_services = operations.fetch_services
fetch_indicators = operations.fetch_indicators
fetch_alerts = operations.fetch_alerts

# Mock data for different operations
MOCK_DATA = {
    'services': {
        'success': True,
        'data': [
            {'name': 'compromised_endpoints_cookies', 'displayName': 'Compromised Cookies'},
            {'name': 'stealer_logs', 'displayName': 'Compromised Endpoints'},
            {'name': 'cyber_crime_forums', 'displayName': 'Cybercrime Forum Mentions'},
            {'name': 'cyble_research_labs', 'displayName': 'Cyble Research Labs'},
            {'name': 'advisory', 'displayName': 'Cyble Research Labs Advisory'},
            {'name': 'darkweb_marketplaces', 'displayName': 'Darkweb Marketplaces'},
            {'name': 'darkweb_data_breaches', 'displayName': 'Data Exposures'},
            {'name': 'discord', 'displayName': 'Discord'},
            {'name': 'i2p', 'displayName': 'I2P Links'},
            {'name': 'flash_report', 'displayName': 'News Flash'},
            {'name': 'darkweb_ransomware', 'displayName': 'Ransomware Leaks'},
            {'name': 'ransomware_updates', 'displayName': 'Ransomware Incidents'},
            {'name': 'report_management', 'displayName': 'Report Management'},
            {'name': 'spotlight_search', 'displayName': 'Spotlight Search'},
            {'name': 'telegram_mentions', 'displayName': 'Telegram Mentions'},
            {'name': 'tor_links', 'displayName': 'Tor Links'},
            {'name': 'keyword_management', 'displayName': 'Keyword Management'},
            {'name': 'leaked_credentials', 'displayName': 'Leaked Credentials'},
            {'name': 'botnet', 'displayName': 'BotShield'},
            {'name': 'incident_management', 'displayName': 'Incident Management'}
        ],
        'meta': {}
    },
    'advisories': {
        'success': True,
        'data': {
            'pagination': {
                'page': '1',
                'items_per_page': '1',
                'total': 4
            },
            'reports': [
                {
                    'id': 5623,
                    'title': 'MacOS Under Attack: The Banshee Stealer Threat',
                    'risk_score': 'high',
                    'publish_date': '2025-01-10',
                    'status': 'published',
                    'tlp_rating': 'TLP:GREEN',
                    'classified': 0,
                    'tags': {
                        'countries': ['Worldwide'],
                        'regions': ['Worldwide'],
                        'industries': ['Technology'],
                        'vulnerabilities': [],
                        'customTags': ['Malware', 'Phishing', 'Infostealer', 'Cryptominer', 'Banshee']
                    }
                }
            ]
        }
    }
    # 'indicators': {
    #     'success': True,
    #     'data': [
    #         {
    #             'ioc': 'example.com',
    #             'ioc_type': 'domain',
    #             'first_seen': '2024-01-01T00:00:00Z',
    #             'last_seen': '2024-01-02T00:00:00Z',
    #             'risk_score': 80,
    #             'confidence_rating': 'high'
    #         }
    #     ]
    # },
    # 'alerts': {
    #     'success': True,
    #     'data': [
    #         {
    #             'id': '123',
    #             'alert_group_id': 'group1',
    #             'severity': 'HIGH',
    #             'status': 'UNREVIEWED',
    #             'service': 'darkweb_data_breaches',
    #             'created_at': '2024-01-01T00:00:00Z'
    #         }
    #     ]
    # }
}

# Test configuration
TEST_CONFIG = {
    'server_url': 'https://api.cyble.test',
    'token': 'test_token',
    'verify_ssl': True
}


class TestCybleVisionConnector(unittest.TestCase):
    @patch('requests.request')
    def test_fetch_services(self, mock_request):
        # Configure the mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(MOCK_DATA['services'])
        mock_response.json.return_value = MOCK_DATA['services']
        mock_request.return_value = mock_response

        # Test the fetch_services operation
        result = fetch_services(TEST_CONFIG, {})

        # Verify the result
        self.assertEqual(result, MOCK_DATA['services'])
        mock_request.assert_called_once()

        # Verify the request was made with correct parameters
        call_args = mock_request.call_args
        self.assertEqual(call_args[1]['method'], 'GET')
        self.assertEqual(call_args[1]['url'], 'https://api.cyble.test/apollo/api/v1/y/services')
        self.assertEqual(call_args[1]['headers']['Authorization'], 'Bearer test_token')

    @patch('requests.request')
    def test_fetch_services_error(self, mock_request):
        # Configure the mock to simulate an error
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = 'Unauthorized'
        mock_request.return_value = mock_response

        # Test error handling
        with self.assertRaises(ConnectorError) as context:
            fetch_services(TEST_CONFIG, {})

        self.assertTrue('Invalid credentials were provided' in str(context.exception))

    @patch('requests.request')
    def test_list_advisories(self, mock_request):
        # Configure the mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(MOCK_DATA['advisories'])
        mock_response.json.return_value = MOCK_DATA['advisories']
        mock_request.return_value = mock_response

        # Test parameters
        params = {
            'customTags': '',
            'limit': '1',
            'vulnerabilities': '',
            'from': '2025-01-10T09:00:00.000000Z',
            'to': '2025-01-11T09:00:00.000000Z',
            'sortBy': 'publish_date',
            'page': '1',
            'countries': '',
            'order': 'asc'
        }

        # Execute the function
        result = operations.list_advisories(TEST_CONFIG, params)

        # Verify the result
        self.assertEqual(result, MOCK_DATA['advisories'])

        # Verify the API call was made correctly
        mock_request.assert_called_once()
        call_args = mock_request.call_args

        # Verify URL and method
        self.assertEqual(call_args[1]['method'], 'GET')
        self.assertTrue(call_args[1]['url'].endswith('/engine/api/v1/y/advisory'))

        # Verify headers
        self.assertEqual(
            call_args[1]['headers']['Authorization'],
            'Bearer test_token'
        )

    @patch('requests.request')
    def test_list_advisories_error(self, mock_request):
        # Configure the mock to simulate an error
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = 'Invalid credentials'
        mock_request.return_value = mock_response

        # Test parameters
        params = {
            'from': '2025-01-10T09:00:00.000000Z',
            'to': '2025-01-11T09:00:00.000000Z'
        }

        # Test error handling
        with self.assertRaises(ConnectorError) as context:
            operations.list_advisories(TEST_CONFIG, params)

        self.assertTrue('Invalid credentials were provided' in str(context.exception))
    # @patch('requests.request')
    # def test_fetch_indicators(self, mock_request):
    #     # Configure the mock
    #     mock_response = MagicMock()
    #     mock_response.status_code = 200
    #     mock_response.text = json.dumps(MOCK_DATA['indicators'])
    #     mock_response.json.return_value = MOCK_DATA['indicators']
    #     mock_request.return_value = mock_response
    #
    #     # Import the operations module
    #     from .operations import fetch_indicators
    #
    #     # Test parameters
    #     params = {
    #         'ioc_type': 'domain',
    #         'limit': 10,
    #         'start_date': '2024-01-01T00:00:00.000Z',
    #         'end_date': '2024-01-02T00:00:00.000Z'
    #     }
    #
    #     result = fetch_indicators(TEST_CONFIG, params)
    #
    #     # Verify the result
    #     self.assertEqual(result, MOCK_DATA['indicators'])
    #     mock_request.assert_called_once()
    #
    # @patch('requests.request')
    # def test_fetch_alerts(self, mock_request):
    #     # Configure the mock
    #     mock_response = MagicMock()
    #     mock_response.status_code = 200
    #     mock_response.text = json.dumps(MOCK_DATA['alerts'])
    #     mock_response.json.return_value = MOCK_DATA['alerts']
    #     mock_request.return_value = mock_response
    #
    #     # Import the operations module
    #     from .operations import fetch_alerts
    #
    #     # Test parameters
    #     params = {
    #         'companyID': 'test-company',
    #         'sortBy': 'desc',
    #         'begin': '2024-01-01T00:00:00.000Z',
    #         'end': '2024-01-02T00:00:00.000Z',
    #         'severity': ['HIGH'],
    #         'service': 'Data Breaches'
    #     }
    #
    #     result = fetch_alerts(TEST_CONFIG, params)
    #
    #     # Verify the result
    #     self.assertEqual(result, MOCK_DATA['alerts'])
    #     mock_request.assert_called_once()


if __name__ == '__main__':
    unittest.main()
