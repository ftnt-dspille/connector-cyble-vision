"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
from connectors.core.connector import get_logger, ConnectorError

# from .alertdata import Alertdata

logger = get_logger('cyble-vision')


class CybleVision(object):
    def __init__(self, config):
        self.base_url = config.get("server_url")
        if self.base_url.startswith('https://') or self.base_url.startswith('http://'):
            self.base_url = self.base_url.strip('/')
        else:
            self.base_url = 'https://{0}'.format(self.base_url.strip('/'))
        self.token = config.get("token")
        self.verify_ssl = config.get("verify_ssl")
        self.error_msg = {
            400: 'The parameters are invalid.',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            404: 'The requested resource was not found',
            409: 'The requested settings conflict with the current settings',
            410: 'Cannot find the specified object',
            422: 'Unable to process the request because system lockdown is currently disabled, or some file fingerprint lists or file names were already assigned',
            423: 'The resource to update is locked and cannot be updated',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'}

    def make_request(self, endpoint, method='GET', params=None, data=None, headers=None):
        try:
            if headers is None:
                headers = {}
            headers.update({
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            })

            url = f'{self.base_url}{endpoint}'
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data if data else None,
                verify=self.verify_ssl
            )

            if response.status_code in [200, 201, 206]:
                return response.json() if response.text else {}

            error_msg = self.error_msg.get(
                response.status_code,
                f'Unexpected response (HTTP {response.status_code})'
            )
            raise ConnectorError(f'{error_msg}: {response.text}')

        except requests.exceptions.SSLError as e:
            raise ConnectorError(f'SSL Certificate Validation Failed: {str(e)}')
        except requests.exceptions.RequestException as e:
            raise ConnectorError(f'Request Failed: {str(e)}')
        except Exception as e:
            raise ConnectorError(f'Error: {str(e)}')

    def build_payload(self, params):
        result = {k: v for k, v in params.items() if v is not None and v != ''}
        return result


def format_datetime(dt: datetime) -> str:
    """
    Format datetime to specific format: YYYY-MM-DDThh:mm:ss.fffZ
    """
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def handle_datetime(date_ts: str) -> str:
    """Convert datetime string to required format"""
    try:
        return datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%d")
    except ValueError as e:
        logger.error(f"Error parsing datetime: {str(e)}")
        raise ConnectorError(f"Invalid datetime format: {date_ts}")


def remove_empty_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Remove empty parameters from the dictionary"""
    return {k: v for k, v in params.items() if v}


def get_service_mapping(config) -> Dict[str, str]:
    """Get service mapping"""
    services = fetch_services(config, {})
    return {item['displayName']: item['name'] for item in services['data']}


def build_ioc_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build parameters for IOC request"""
    ioc_params = {
        'ioc': params.get('ioc', ''),
        'page': params.get('page', ''),
        'limit': params.get('limit', ''),
        'sortBy': params.get('sortBy', ''),
        'order': params.get('order', '')
    }

    # Add optional parameters
    if params.get('type'):
        ioc_params['iocType'] = params['type']
    if params.get('begin'):
        ioc_params['startDate'] = handle_datetime(params['begin'])
    if params.get('end'):
        ioc_params['endDate'] = handle_datetime(params['end'])
    if params.get('tags'):
        ioc_params['tags'] = params['tags']

    return {k: v for k, v in ioc_params.items() if v}


def process_ioc_response(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process IOC response and format the data"""
    if not response.get('iocs'):
        return []

    processed_iocs = []
    for ioc in response['iocs']:
        processed_ioc = {
            'ioc': str(ioc.get('ioc', '')),
            'ioc_type': str(ioc.get('ioc_type', '')),
            'first_seen': str(ioc.get('first_seen', '')),
            'last_seen': str(ioc.get('last_seen', '')),
            'risk_score': str(ioc.get('risk_score', '')),
            'confidence_rating': str(ioc.get('confidence_rating', '')),
            'sources': str(ioc.get('sources', [])),
            'behaviour_tags': str(ioc.get('behaviour_tags', [])),
            'target_countries': str(ioc.get('target_countries', [])),
            'target_regions': str(ioc.get('target_regions', [])),
            'target_industries': str(ioc.get('target_industries', [])),
            'related_malware': str(ioc.get('related_malware', [])),
            'related_threat_actors': str(ioc.get('related_threat_actors', []))
        }
        processed_iocs.append(processed_ioc)

    return processed_iocs


def fetch_indicators(config: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch indicators from Cyble Vision"""
    try:
        api = CybleVision(config)

        # Build and validate parameters
        ioc_params = build_ioc_params(params)
        logger.debug(f"Fetching indicators with params: {ioc_params}")
        print(f"Fetching indicators with params: {ioc_params}")
        # Make API request
        response = api.make_request(
            endpoint='/engine/api/v2/y/iocs',
            method='GET',
            params=ioc_params
        )

        # Process response
        processed_iocs = process_ioc_response(response)
        return {'iocs': processed_iocs}

    except Exception as e:
        logger.error(f"Error fetching indicators: {str(e)}")
        raise ConnectorError(f"Failed to fetch indicators: {str(e)}")


def build_alert_params(input_params: Dict[str, Any]) -> Dict[str, Any]:
    """Build the alert request structure

    Args:
        input_params (Dict[str, Any]): Dictionary containing alert parameter options

    Returns:
        Dict[str, Any]: Structured alert parameters
    """
    input_params = remove_empty_params(input_params)

    # Define default values and extract parameters
    sort_direction = input_params.get('sortBy', 'asc')
    page_limit = int(input_params.get('limit', 100))
    date_begin = input_params.get('begin', '')
    date_end = input_params.get('end', '')

    # Define default status options
    default_status = [
        "VIEWED",
        "UNREVIEWED",
        "CONFIRMED_INCIDENT",
        "UNDER_REVIEW",
        "INFORMATIONAL"
    ]
    status_options = input_params.get("status", default_status)

    # Define default severity levels
    default_severity = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]
    severity_levels = input_params.get("severity", default_severity)

    # Define default services
    default_services = []
    service_options = input_params.get("service", default_services)
    if not service_options:

    # Define fields to select
    select_fields = {
        "alert_group_id": True,
        "archive_date": True,
        "archived": True,
        "assignee_id": True,
        "assignment_date": True,
        "created_at": True,
        "data_id": True,
        "deleted_at": True,
        "description": True,
        "hash": True,
        "id": True,
        "metadata": True,
        "risk_score": True,
        "service": True,
        "severity": True,
        "status": True,
        "tags": True,
        "updated_at": True,
        "user_severity": True
    }

    # Build and return the complete structure
    return {
        "orderBy": [{"created_at": sort_direction}],
        "select": select_fields,
        "skip": 0,
        "take": page_limit,
        "withDataMessage": True,
        "where": {
            "created_at": {
                "gte": date_begin,
                "lte": date_end
            },
            "status": {
                "in": status_options,
            },
            "severity": {
                "in": severity_levels,
            },
            "service": {
                "in": service_options,
            },
        }
    }


def fetch_alerts(config: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch alerts from Cyble Vision"""
    try:
        api = CybleVision(config)

        # Handle date parameters
        for date_field in ['begin', 'end']:
            if date_str := params.get(date_field):
                try:
                    dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    dt_utc = dt.replace(tzinfo=timezone.utc)
                    params[date_field] = format_datetime(dt_utc)
                except ValueError as e:
                    logger.error(f"Error parsing {date_field}: {str(e)}")
                    raise ConnectorError(f"Invalid date format for {date_field}: {date_str}")

        # Build alert parameters
        alert_params = build_alert_params(params)

        print(f"Fetching alerts with params: {alert_params}")
        # Make API request
        response = api.make_request(
            endpoint="/apollo/api/v1/y/alerts",
            method='POST',
            data=alert_params,
            headers={"Content-Type": "application/json"}
        )
        print(f"Fetched {len(response['data'])} alerts")
        return response

    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        raise ConnectorError(f"Failed to fetch alerts: {str(e)}")


def add_comment_to_alert(config, params):
    obj = CybleVision(config)
    endpoint = "/apollo/api/v1/y/alerts/{}/comments".format(params['alertID'])
    data = {"content": params['comment']}
    response = obj.make_request(endpoint=endpoint, method='POST', data=data)
    return response


def list_advisories(config, params):
    obj = CybleVision(config)
    date1_obj = datetime.strptime(params['from'], "%Y-%m-%dT%H:%M:%S.%fZ")
    date_from = date1_obj.strftime("%Y-%m-%d")
    date2_obj = datetime.strptime(params['to'], "%Y-%m-%dT%H:%M:%S.%fZ")
    date_to = date2_obj.strftime("%Y-%m-%d")
    dateRange = date_from + "," + date_to
    params = obj.build_payload(params)
    params.update({"dateRange": dateRange})
    del params['to']
    del params['from']
    response = obj.make_request(endpoint="/engine/api/v1/y/advisory", params=params)
    return response


def get_advisory_details(config, params):
    obj = CybleVision(config)
    endpoint = "/engine/api/v1/y/advisory/{}".format(params['advisoryID'])
    headers = {"accept": "application/pdf"}
    response = obj.make_request(endpoint=endpoint, headers=headers)
    return response


def fetch_companies(config, params):
    obj = CybleVision(config)
    print("config", config)
    response = obj.make_request(endpoint="/apollo/api/v1/y/companies")
    return response


def fetch_ip_details(config, params):
    obj = CybleVision(config)
    endpoint = "/engine/api/v1/y/asm/details/{companyId}/ip/{ip}".format(companyId=params['companyId'],
                                                                         ip=params['addressIP'])
    response = obj.make_request(endpoint=endpoint)
    return response


def fetch_cve_details(config, params):
    obj = CybleVision(config)
    endpoint = "/engine/api/v1/y/vulnerability/cve/{cve}".format(cve=params['cve'])
    response = obj.make_request(endpoint=endpoint)
    return response


def fetch_services(config, params):
    obj = CybleVision(config)
    response = obj.make_request(endpoint="/apollo/api/v1/y/services")
    return response


def make_generic_request(config, params):
    """Generic action to make custom API requests"""
    api = CybleVision(config)

    endpoint = params.get('endpoint')
    if not endpoint:
        raise ConnectorError('Endpoint parameter is required')

    method = params.get('method', 'GET').upper()
    if method not in ['GET', 'POST', 'PUT', 'DELETE']:
        raise ConnectorError(f'Unsupported HTTP method: {method}')

    request_params = params.get('params')
    if not request_params:
        request_params = {}
    data = params.get('data')
    if not data:
        data = {}
    headers = params.get('headers')
    if not headers:
        headers = {}

    print(
        f"Making request with endpoint: {endpoint}, method: {method}, params: {request_params}, data: {data}, headers: {headers}")
    return api.make_request(
        endpoint=endpoint,
        method=method,
        params=request_params,
        data=data,
        headers=headers
    )


def check_health_ext(config):
    try:
        obj = CybleVision(config)
        params = {"limit": "1"}
        server_response = obj.make_request(endpoint='/apollo/api/v1/y/services', params=params)
        if server_response:
            return True
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError(str(err))


operations = {
    'fetch_indicators': fetch_indicators,
    'fetch_alerts': fetch_alerts,
    'fetch_services': fetch_services,
    'add_comment_to_alert': add_comment_to_alert,
    'list_advisories': list_advisories,
    'get_advisory_details': get_advisory_details,
    'fetch_companies': fetch_companies,
    'fetch_ip_details': fetch_ip_details,
    'fetch_cve_details': fetch_cve_details,
    'make_generic_request': make_generic_request
}
