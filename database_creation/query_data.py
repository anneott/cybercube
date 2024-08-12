import requests
import json

BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def make_request(start_index, results_per_page) -> json:
    """
    Make request to CVE endpoint
    :param page_number: number of page
    :type page_number: int
    :return: endpoint respons
    :rtype: json
    """
    response = requests.get(BASE_URL, params={'startIndex': start_index, 'resultsPerPage': results_per_page})
    if response.status_code != 200:
        raise Exception(f"Request to {BASE_URL} failed with status code {response.status_code}")
    return response.json()

