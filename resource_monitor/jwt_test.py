import jwt
from datetime import timedelta, datetime

def request_token():
    token = jwt.encode({'user': 'sundar', 'exp': datetime.utcnow() + timedelta(minutes=30)},"secret")
    return token.decode('UTF-8')


def validate(token):
    try:
        data = jwt.decode(token, "secret")
        # data = Pyjwt.decode(token, "demeter")
        print(data)
    except:
        #return jsonify({'message': 'Token is invalid!'}), 403
        print("Not valid")
"""
test = request_token()
print(test)
t = validate(test)
"""

d1 = 				{
			"eventTimestamp" : "2021-04-21 11:29:23 UTC+0000",
			"description" : "container went down",
			"namespace" : "ResourceMonitor",
			"severity" : "Major",
			"event" : "stop",
			"time" : 1619004563,
			"status" : "stop",
			"Action" : "stop",
			"exitCode" : "NA"
		}



d2 = 				{
			"eventTimestamp" : "2021-04-21 11:29:23 UTC+0000",
			"description" : "container went down",
			"namespace" : "ResourceMonitor",
			"severity" : "Major",
			"event" : "stop",
			"time" : 1619004563,
			"status" : "stop",
			"Action" : "stop",
			"exitCode" : "NA"
		}


if d1 == d2 :
    print(2)


s = "Communication with docker socket failed or Docker Image not found. " \
	"Error response : 404 Client Error for http://10.0.10.132:2375/v1.41/images/create?tag=candidate1&fromImage=demeterengteam%2Fpilot4.2-traslator: Not Found (\"manifest for demeterengteam/pilot4.2-traslator:candidate1 not found: manifest unknown: manifest unknown\") "
import re
if re.findall("manifest unknown: manifest unknown", s):
	print("match founc")