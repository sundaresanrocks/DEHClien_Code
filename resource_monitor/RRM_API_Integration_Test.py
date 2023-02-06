from lib import API
import json
from app import app

'''
url = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"

payload = {"name": "gianluca.isgro@eng.it","password": "1dmPassw0rd"}
headers = {
    'content-type': "application/json"
    }

response = requests.request("POST", url, data=json.dumps(payload), headers=headers, verify= False)
print(response.text)
print(response.headers)
'''
'''
# Get Token:
url = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"
payload = {"name": "gianluca.isgro@eng.it", "password": "1dmPassw0rd"}
headers = {'content-type': "application/json"}
client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
status_code, response = client.post(verify=False)
if status_code in (200, 201):
    print(response.text)
    print(response.headers)
    subject_token = response.headers['X-Subject-Token']
    print("#####################################################################")
    print("Proceeding for securing Capability token from ACS Capability Manger")
    print("#####################################################################")
    url = "https://acs.bse.h2020-demeter-cloud.eu:3030/"
    payload = {"token": subject_token, "ac": "POST",
               "de": "https://acs.bse.h2020-demeter-cloud.eu:1029", "re": "/api/v1/resources"}
    headers = {'content-type': "application/json"}
    client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
    status_code, response = client.post(verify=False)
    #client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
    #status_code, response = client.post(verify=False, amend_headers=False)
    if status_code in (200, 201):
        print(response)
        print(type(response.text))
        print(response.json()['su'])
        capacity_token = response.text
        print("####################")
        print("Save DEH Resource")
        print("####################")
        url = "https://acs.bse.h2020-demeter-cloud.eu:1029/api/v1/resources"
        payload = capacity_token
        client = API.APIWrapper(url=url, payload=json.dumps(capacity_token), headers=headers)
        #status_code, response = client.post(verify=False, amend_headers=False)
        #print(app.config['RRM_SaveDEH_Resource_Format'])
else:
    print(response)
'''
import re
s = "/test1//////test"
t = re.sub("^/","",s)
print(t)
