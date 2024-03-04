import urllib.request
import urllib.parse
import json

from django.conf import settings

URL = 'https://mb-api.abuse.ch/api/v1/'
HEADERS = {
    'API-KEY': settings.ABUSECH_API_KEY
}

def request(data):
    data = data.encode('ascii')
    req = urllib.request.Request(URL, data, HEADERS)
    response = urllib.request.urlopen(req)
    return json.load(response)

def get_report_by_hash(hash):
    data = urllib.parse.urlencode({'query': 'get_info', 'hash': f'{hash}'})
    result = request(data)
    if result['query_status'] == 'ok':
        return result["data"][0]
    else:
        return ""
    
def get_by_certificate_serial(certificate):
    if certificate:
        try:
            search = "Serial Number: "
            start_index =certificate['certificate_info'].find(search) + len(search)
            end_index = certificate['certificate_info'].find("\n", start_index)
            serial_number = certificate['certificate_info'][start_index:end_index].split("0x")[1]
            data = urllib.parse.urlencode({'query': 'get_certificate', 'serial_number': f'{serial_number}'})
            result = request(data)
            if result['query_status'] == 'ok':
                return result["data"][0]
        except Exception:
            return ""
    else:
        return ""