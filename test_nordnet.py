import time
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import json
import urllib.parse
import requests


def print_json(j, prefix=''):
    for key, value in j.items():
        if isinstance(value, dict):
            print('%s%s' % (prefix, key))
            print_json(value, prefix + '  ')
        else:
            print('%s%s:%s' % (prefix, key, value))


USERNAME = 'hanssonb'
PASSWORD = 'kallle01'
SERVICE = 'NEXTAPI'
URL = 'https://api.test.nordnet.se'
API_VERSION = '2'


def get_hash(username, password):
    timestamp = int(round(time.time() * 1000))
    timestamp = str(timestamp).encode('ascii')

    username_b64 = base64.b64encode(username.encode('ascii'))
    password_b64 = base64.b64encode(password.encode('ascii'))
    timestamp_b64 = base64.b64encode(timestamp)

    auth_val = username_b64 + b':' + password_b64 + b':' + timestamp_b64
    rsa_key = RSA.importKey(open('NEXTAPI_TEST_public.pem').read())
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_hash = cipher_rsa.encrypt(auth_val)
    encoded_hash = base64.b64encode(encrypted_hash)
    return encoded_hash


def main():
    auth_hash = get_hash(USERNAME, PASSWORD)
    headers = {"Accept": "application/json"}

    # GET server status
    response = requests.get(
        URL + '/next/' + API_VERSION + '/',
        headers=headers
    )
    j = json.loads(response.text)
    print_json(j)

    # POST login
    print("Begin LOGIN")
    data = {'service': 'NEXTAPI', 'auth': auth_hash}
    response = requests.post(
        URL + '/next/' + API_VERSION + '/login',
        data=data,
        headers=headers
    )
    j = json.loads(response.text)
    print_json(j)
    print(response, response.reason)
    print("END Login")
    # get a list of all accounts
    for i in range(2):
        keydata = '%s:%s' % (j['session_key'], j['session_key'])
        keydata.strip()
        headers['Authorization'] = 'Basic ' + urllib.parse.quote(base64.b64encode(keydata.encode('ascii')))
        print(headers)
        response = requests.get(
            URL + '/next/' + API_VERSION + '/accounts',
            headers=headers
        )
        print(response.text)

        # set seconds to sleep each iteration
        time.sleep(2)


if __name__ == "__main__":
    main()
