import json
from urllib import request

from bs4 import BeautifulSoup

URL = ['https://apkpure.com/', 'search?q=', '/download/']
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'apkpure__lang': 'en',
}
HASHES = 'mobsf/customscripts/apkpure/files/knownhashes.json'


def make_request(url):
    req = request.Request(url, headers=HEADERS)
    response = request.urlopen(req)
    bs = BeautifulSoup(response, 'html.parser')
    return bs


def get_signature(packagename, versioncode):
    resp = make_request(f'{URL[0]}{URL[1]}{packagename}')
    try:
        package = resp.select('a.first-info')[0]['href'] \
            .split('apkpure.com/')[-1]
        if packagename != package.split('/')[-1]:
            return None
        else:
            resp = make_request(f'{URL[0]}{package}{URL[2]}{versioncode}')
            try:
                signature = resp \
                    .select('li.sign > div > div.value.double-lines')[0].text
            except IndexError:
                return None
    except IndexError:
        return None
    return signature


def check_fromfile(packagename):
    with open(f'{HASHES}', 'r') as file:
        data = json.load(file)
    hashes = data.get(packagename, {}).get('hashes', [])
    if len(hashes) == 0:
        return []
    else:
        return hashes


def add_to_file(packagename, signature):
    with open(f'{HASHES}', 'r+') as file:
        data = json.load(file)
        if packagename not in data:
            data[packagename] = {'hashes': []}
        if signature not in data[packagename]['hashes']:
            data[packagename]['hashes'].append(signature)
    with open(f'{HASHES}', 'w') as file:
        json.dump(data, file, indent=4)


def is_valid_hash(packagename, versioncode, certificateinfo):
    search = 'sha1: '
    start_index = certificateinfo.find(search) + len(search)
    end_index = certificateinfo.find('\n', start_index)
    sha1 = certificateinfo[start_index:end_index]
    hash_from_file = check_fromfile(packagename)
    if sha1 in hash_from_file:
        return True
    else:
        signature = get_signature(packagename, versioncode)
        if signature is not None:
            add_to_file(packagename, signature)
        if signature == sha1:
            return True
        else:
            return False
