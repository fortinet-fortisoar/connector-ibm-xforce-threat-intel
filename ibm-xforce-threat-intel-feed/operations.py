""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
"""

import requests

from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import create_file_from_string

logger = get_logger('ibm-xforce-threat-intel-feed')


class TaxiiClient(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.api_password = config.get('api_password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request_taxii(self, endpoint=None, method='GET', data=None, params=None, files=None, headers=None):
        try:
            if endpoint:
                url = self.server_url + 'taxii2/' + endpoint
            else:
                url = self.server_url + 'taxii2'
            default_header = {'Content-Type': 'application/json'}
            headers = {**default_header, **headers} if headers is not None and headers != '' else default_header
            response = requests.request(method, url, auth=(self.api_key, self.api_password), params=params, files=files,
                                        data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_output_schema(config, params, *args, **kwargs):
    if params.get('file_response'):
        return ({
            "md5": "",
            "sha1": "",
            "sha256": "",
            "filename": "",
            "content_length": "",
            "content_type": ""
        })
    else:
        return ({
            "spec_version": "",
            "type": "",
            "objects": [
                {
                    "id": "",
                    "type": "",
                    "created": "",
                    "modified": "",
                    "labels": [
                    ],
                    "name": "",
                    "description": "",
                    "pattern": "",
                    "valid_from": ""
                }
            ]
        })


def get_api_root_information(config, params):
    taxii = TaxiiClient(config)
    params = get_params(params)
    return taxii.make_request_taxii(params=params, headers={'Accept': 'application/vnd.oasis.taxii+json'})


def get_collections(config, params):
    taxii = TaxiiClient(config)
    params = get_params(params)
    if params:
        response = taxii.make_request_taxii(endpoint='collections/' + str(params['collectionID']),
                                            headers={'Accept': 'application/vnd.oasis.taxii+json'})
    else:
        response = taxii.make_request_taxii(endpoint='collections',
                                            headers={'Accept': 'application/vnd.oasis.taxii+json'})
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params):
    taxii = TaxiiClient(config)
    params = get_params(params)
    wanted_keys = set(['added_after', 'added_before'])
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    response = taxii.make_request_taxii(endpoint='collections/' + str(params['collectionID']) + '/objects',
                                        params=query_params, headers={'Accept': 'application/vnd.oasis.stix+json'})
    response = response.get("objects", [])
    try:
        # dedup
        filtered_indicators = [indicator for indicator in response if indicator["type"] == "indicator"]
        seen = set()
        deduped_indicators = [x for x in filtered_indicators if
                              [x["pattern"].replace(" ", "") not in seen, seen.add(x["pattern"].replace(" ", ""))][0]]
    except Exception as e:
        logger.exception("Import Failed")
        raise ConnectorError('Ingestion Failed with error: ' + str(e))
    mode = params.get('output_mode')
    if mode == 'Save to File':
        return create_file_from_string(contents=deduped_indicators, filename=params.get('filename'))
    else:
        return deduped_indicators


def get_manifest_by_collection_id(config, params):
    taxii = TaxiiClient(config)
    params = get_params(params)
    wanted_keys = set(['added_after', 'added_before'])
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    return taxii.make_request_taxii(endpoint='collections/' + str(params['collectionID']) + '/manifest',
                                    params=query_params, headers={'Accept': 'application/vnd.oasis.taxii+json'})


def get_objects_by_object_id(config, params):
    taxii = TaxiiClient(config)
    params = get_params(params)
    return taxii.make_request_taxii(headers={'Accept': 'application/vnd.oasis.stix+json'},
                                    endpoint='collections/' + str(params['collectionID']) + '/objects/' + params[
                                        'objectID'])


def _check_health(config):
    try:
        params = {}
        res = get_api_root_information(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_api_root_information': get_api_root_information,
    'get_collections': get_collections,
    'get_objects_by_collection_id': get_objects_by_collection_id,
    'get_objects_by_object_id': get_objects_by_object_id,
    'get_manifest_by_collection_id': get_manifest_by_collection_id,
    'get_output_schema': get_output_schema
}
