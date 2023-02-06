from flask import Flask, jsonify, make_response
import socket

app = Flask(__name__)
app.config['SECRET_KEY'] = "demeterenablerclient"
app.config['docker_host'] = socket.gethostname().upper()
app.config['docker_host'] = "https://10.0.10.132:2375/"
app.config['docker_hostname'] = "10.0.10.132"
app.config['tls_cert_path'] = "/home/svenkatesan/docker_test"

## Interval Config: Options - db & instance
app.config['check_rrm_bse_info_from'] = "db"

## DEH Client & Docker communication : True/ False
## Auto-registration options : True/ False /Manual
app.config['secure_connection'] = False
app.config['auto_register'] = "Manual"
app.config['auto_register_rrm'] = False
app.config['auto_register_bse'] = True

# DEH BSE Config
app.config['DEH_BSE_Host'] = 'https://vm1.test.h2020-demeter-cloud.eu'
app.config['DEH_BSE_GET_SERVICES'] = '/api/BSE/services'
app.config['DEH_BSE_GET_SERVICE'] = '/api/BSE/service'
app.config['DEH_BSE_GET_SERVICE_BY_DEH_ID'] = '/api/BSE/service/deh'
app.config['DEH_BSE_Register_Service'] = '/api/BSE/register'
app.config['DEH_BSE_ACS_Token_Request_Url'] = 'https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens'
app.config['DEH_BSE_Capability_Token_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:3030"
app.config['DEH_BSE_Proxy_URL'] = "https://vm1.test.h2020-demeter-cloud.eu:443"


# Metrics internal DB - MongoDB
app.config['mongo_host'] = "10.0.10.131"
app.config['mongo_port'] = 27018
app.config['mongo_db'] = "DEHClient"
app.config['mongo_collection_metrics'] = "metrics"
app.config['mongo_collection_events'] = "events"

# DEH Enabler Hub Config : Test
# app.config['DEHEnablerHub_Host'] = "https://deh-demeter.eng.it"
# app.config['DEHEnablerHub_Resource'] = '/api/v1/resources'
# app.config['DEHEnablerHub_Search_Resource'] = '/api/v1/resources/search'
# app.config['DEH_ACCOUNT_MAIL'] = "sundaresanrocks@gmail.com"
# app.config['DEH_ACCOUNT_PASS'] = "Brain@123"
# app.config['ACS_Token_Request_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"
# app.config['Capability_Token_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:3030"
# app.config['DEH_RRM_Proxy_URL'] = "https://deh-demeter.eng.it/pep-proxy"
# app.config['DEH_RRM_Search_Resource'] = "/api/v1/resources/search"
# app.config['DEH_Save_Resource_Url'] = "/api/v1/resources"
# app.config['user-id'] = "32194dbf-03de-4ac5-a91b-c959ceb97358"
# app.config['DEH_BSE_Request_Header'] = {"content-type": "application/json"}
# app.config['DEH_RRM_Request_Header'] = {"content-type": "application/json"}
#
# # DEH Enabler metrics-api
# app.config['ACS_Token_Request_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"
# app.config['Capability_Token_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:3030"
# app.config['DEH_RRM_Metrics'] = "/api/v1/metrics"
# app.config['DEH_RRM_Proxy_URL'] = "https://deh-demeter.eng.it/pep-proxy"

# DEH Enabler Hub Config : Production
app.config['DEHEnablerHub_Host'] = "https://deh.h2020-demeter-cloud.eu/"
app.config['DEHEnablerHub_Resource'] = '/api/v1/resources'
app.config['DEHEnablerHub_Search_Resource'] = '/api/v1/resources/search'
app.config['DEH_ACCOUNT_MAIL'] = "sundaresanrocks@gmail.com"
app.config['DEH_ACCOUNT_PASS'] = "Brain@123"
app.config['ACS_Token_Request_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"
app.config['Capability_Token_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:3030"
app.config['DEH_RRM_Proxy_URL'] = "https://acs.bse.h2020-demeter-cloud.eu:1029"
app.config['DEH_RRM_Search_Resource'] = "/api/v1/resources/search"
app.config['DEH_Save_Resource_Url'] = "/api/v1/resources"
#app.config['user-id'] = "32194dbf-03de-4ac5-a91b-c959ceb97358" # Not need reomove
app.config['DEH_BSE_Request_Header'] = {"content-type": "application/json"}
app.config['DEH_RRM_Request_Header'] = {"content-type": "application/json"}

# DEH Enabler metrics-api
app.config['ACS_Token_Request_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens"
app.config['Capability_Token_Url'] = "https://acs.bse.h2020-demeter-cloud.eu:3030"
app.config['DEH_RRM_Metrics'] = "/api/v1/metrics"


"""This flag end_to_end will determine if the Client has to automate to entire flow ie
> Pull images to Docker Host, if not already
> Create / start a resource.
> Register created resource against RRM.
"""
app.config['end_to_end'] = True

#TODO: The request and response templates to be defined in a config file and dediceted parser service to parse for use,
# Under development
app.config['Request_Capability_Token_Format'] = {"token": "$X-Subject-Token", "ac": "$RequestMethod",
                                                 "de": "$ProxyURL", "re": "$Resource"}
app.config['DEH_Save_Resource_Format'] = {
  "name": "string",
  "type": "string",
  "category": ["string"],
  "description": "DEH Client Enabler Test Registration",
  "endpoint": "Test",
  "status": "string",
  "version": "string",
  "maturityLevel": 0,
  "owner": "$USER_ID",
  "tags": ["DEHCl:latest"],
  "attachment": [],
  "localisation": [
    {
      "coordinates": [
        0,0
      ],
      "type": "string"
    }
  ],
  "accessibility": 0,
  "dependencies": ["string"],
  "accessControlPolicies": ["string"],
  "url": "https://DEHClientTestURL.ie"
}

app.config['DEH_Save_Resource_Format'] = {
    "name": "string",
    "type": "string",
    "category": [
        "string"
    ],
    "description": "string",
    "endpoint": "string",
    "status": 1,
    "version": "string",
    "maturityLevel": 1,
    "owner": "sundaresanrocks@gmail.com",
    "tags": [
        "string"
    ],
    "rating": 0,
    "localisation": [
        {
            "x": 0,
            "y": 0,
            "coordinates": [
                0,
                0
            ],
            "type": "Point"
        }
    ],
    "accessibility": 0,
    "dependencies": [
        "string"
    ],
    "accessControlPolicies": [
        "string"
    ],
    "url": "string",
    "billingInformation": [],
    "downloadsHistory": {}
}

# BSE Register Resource Fields , schema:
# To add Labels to Image at run time locally
"""
$ echo "FROM demeterengteam/estimate-animal-welfare-condition:candidate" 
| sudo docker build --label Features="Algorithm Training, Testing and Metrics calculation.
Predict health condition" --label Endpoint="http://[HOST]:[HOST_PORT]/EstimateAnimalWelfareConditionModule/ENDPOINT" 
-t "demeterengteam/estimate-animal-welfare-condition:candidate" -

$ docker inspect -f "{{json .Config.Labels }}" demeterengteam/estimate-animal-welfare-condition:candidate

Image : Adding Labels @ runtime 
It's not possible to add a label to an existing image bcz adding a label will change the images checksum and id, 
thus it's no longer the same image.
But we can build an image based on our existing image with a label added, 
then tag this image with the name of the previously existing image. 
Technically it adds a layer on top of your existing image and thus just "overrides" previous labels
"""
meta = {
  "applicationCategory": "string",
  "description": "container_obj['Config']['Labels'] or image_obj['ContainerConfig']['Labels']",
  "version": 0,
  "deh_id": "rrm_obj['id']",
  "featureList": [
    "string"
  ],
  "dataEncryption": False,
  "authentication": False,
  "conditionsOfAccess": "string",
  "timeRequired": 0,# max seconds between when a user makes a request and system response(Performance Measure)
  "quota": "string",
  "offers": 0,
  "TermsOfService": "string",
  "usageInfo": "string",
  "provider": "string",
  "spatial": "string",
  "aggregateRating": 0,
  "apiModel": [
    {
      "dataProtocol": "string",
      "baseUrl": "string",
      "relativePath": "string",
      "method": "string",
      "URLRequiredParams": {},
      "URLOptionalParams": {},
      "dataParams": {},
      "successResponse": [
        0
      ],
      "errorResponse": [
        0
      ],
      "sampleCall": "string",
      "topic": "string",
      "payloadFormat": "string",
      "payloadRepresentation": {}
    }
  ]
}


# Not found
@app.errorhandler(404)
def handle_resource_not_found(_unused):
    return make_response(jsonify({'error': 'Resource not found'}), 404)


# Request timeout
@app.errorhandler(408)
def handle_overloaded_server(_unused):
    return make_response(jsonify({'error': 'The server is overloaded. Try later.'}), 408)


# Internal server error
@app.errorhandler(500)
def handler_server_internal_error(_unused):
    return make_response(jsonify({'error': 'The server encountered an internal '
                                           'error and was unable to complete your request.'}), 500)


# Internal server error
@app.errorhandler(500)
def handler_server_internal_error(_unused):
    return make_response(jsonify({'error': 'The server encountered an internal '
                                           'error and was unable to complete your request.'}), 410)

