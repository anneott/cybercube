import requests
import json

BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def make_request(params) -> json:
    """
    Make request to NVD endpoint
    :rtype: json
    """
    response = requests.get(BASE_URL, params=params)
    if response.status_code != 200:
        raise Exception(f"Request to {BASE_URL} failed with status code {response.status_code}")
    return response.json()
