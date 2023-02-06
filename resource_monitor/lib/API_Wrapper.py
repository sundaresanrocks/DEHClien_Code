import pytz
import requests
import logging
import os
import json
import inspect
from app import app
import lib.API as API
import mongodb_wrapper
# To Suppress InsecureRequestWarning: Unverified HTTPS request
import urllib3
import traceback
import calendar, time
from datetime import datetime, timezone, timedelta
from time import mktime
from dateutil import tz
import metric_handler
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_LEVEL = logging.DEBUG  # DEBUG, INFO, WARNING, ERROR, CRITICAL
common_formatter = logging.Formatter('%(asctime)s [%(levelname)-7s][ln-%(lineno)-3d]: %(message)s',
                                     datefmt='%Y-%m-%d %I:%M:%S')

# root_path is parent folder of Scripts folder (one level up)
root_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def setup_logger(log_file, level=logging.INFO, name='', formatter=common_formatter):
    """Function setup as many loggers as you want."""
    handler = logging.FileHandler(log_file, mode='w')  # default mode is append
    # Or use a rotating file handler
    # handler = RotatingFileHandler(log_file,maxBytes=1023, backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


# default debug logger
debug_log_filename = '../debug.log'
log = setup_logger(debug_log_filename, LOG_LEVEL, 'log')

api_formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%Y-%m-%d %I:%M:%S')
api_outputs_filename = '../api_outputs.log'
log_api = setup_logger(api_outputs_filename, LOG_LEVEL, 'log_api', formatter=api_formatter)


def pretty_print_request(request):
    """
    Pay attention at the formatting used in this function because it is programmed to be pretty printed and may differ from the actual request.
    """
    log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
        '-----------Request----------->',
        request.method + ' ' + request.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in request.headers.items()),
        request.body)
    )


# pretty print Restful response to API log
# argument is response object
# def pretty_print_response(response):
#     log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
#         '<-----------Response-----------',
#         'Status code:' + str(response.status_code),
#         '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
#         response.text
#     ))


# argument is response object
# display body in json format explicitly with expected indent. Actually most of the time it is not very necessary because body is formatted in pretty print way.
# def pretty_print_response_json(response):
#     """ pretty print response in json format.
#         If failing to parse body in json format, print in text.
#     """
#     try:
#         resp_data = response.json()
#         resp_body = json.dumps(resp_data, indent=3)
#     # if .json() fails, ValueError is raised.
#     except ValueError:
#         resp_body = response.text
#     log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
#         '<-----------Response-----------',
#         'Status code:' + str(response.status_code),
#         '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
#         resp_body
#     ))


def parse_prefix(line, fmt):
    try:
        t = time.strptime(line, fmt)
    except ValueError as v:
        # To handle ValueError: unconverted data remains: Z
        if len(v.args) > 0 and v.args[0].startswith('unconverted data remains: '):
            line = line[:-(len(v.args[0]) - 26)]
            t = time.strptime(line, fmt)
        else:
            raise
    return datetime.fromtimestamp(mktime(t))


def convert_gmt_to_other_timezone_datetime_obj(datetime_obj, time_zone='CET'):
    # datetime_str = "2021-04-02T12:32:34.467Z"
    to_zone = tz.gettz(time_zone)
    datetime_obj = datetime_obj.astimezone(to_zone)
    return datetime_obj


def cached_token(jsonfile):
    def has_valid_token(data):
        return 'token' in data

    def get_token_info_from_file(get="token"):
        with open(jsonfile) as f:
            data = json.load(f)
            # if has_valid_token(data):
            return data

    def save_token_to_file(token, generated_date, expiry_date):
        with open(jsonfile, 'w') as f:
            json.dump({'token': token, 'generated_date': generated_date, 'expiry_date': expiry_date}, f)

    def decorator(fn):
        def wrapped(*args, **kwargs):
            if os.path.exists(jsonfile):
                token_info = get_token_info_from_file()
                token = token_info.get('token')
                expiry_date = token_info.get('expiry_date')
                date_format = '%Y-%m-%dT%H:%M:%S.%f'
                expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
                cet_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
                                                                                          time_zone="CET")
                local_datetime_obj = datetime.now()
                local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
                utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
                token_expired = (cet_expiry_date_datetime_obj.replace(tzinfo=None) <=
                                 utc_now_datetime_obj.replace(tzinfo=None))
                if not token_expired:
                    print("ACS Token Still Valid / Not-Expired.")
                    return f'{token} (cached!!)'
                else:
                    print("ACS Token Expired, attempting to generate new Token.")
            token, generated_data, expiry_date = fn(*args, **kwargs)
            save_token_to_file(token, generated_data, expiry_date)
            # return token, generated_data, expiry_date
            return token

        return wrapped

    return decorator


class DEHAPIWrapper:
    """
    Test Restful HTTP API examples.
    """
    acs_token = None
    acs_token_status_code = None
    acs_token_response = None
    acs_token_expiry_date = None

    capability_token_status_code = None
    capability_token_response = None
    capability_token_expiry_date = None

    def __init__(self, url=None, method=None, payload=None, headers=None):
        self.url = url
        self.method = method
        self.payload = payload
        self.headers = headers
        self.__logger = logging.getLogger('DEHClientEnabler.APIWrapper')
        self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config["mongo_host"],
                                                     port=app.config["mongo_port"],
                                                     database=app.config["mongo_db"],
                                                     collection=app.config["mongo_collection_metrics"])

    def get(self, url, auth=None, params=None, verify=False, headers=None):
        """
        common request get function with below features, which you only need to take care of url:
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.get

        verify: False - Disable SSL certificate verification
        """
        resp = None
        try:
            s = requests.Session()
            if auth == None:
                if params is not None:
                    resp = s.get(url, params=params, verify=verify, headers=headers)
                else:
                    resp = s.get(url, verify=verify, headers=headers)
            else:
                resp = requests.get(url, auth=auth, verify=verify, headers=headers)
                if params is not None:
                    resp = requests.get(url, auth=auth, verify=verify, headers=headers)
                else:
                    resp = requests.get(url, auth=auth, params=params, verify=verify, headers=headers)
        except Exception as ex:
            return None

        # pretty request and response into API log file
        # pretty_print_request(resp.request)
        # pretty_print_response_json(resp)

        # This return caller function's name, not this function post.
        caller_func_name = inspect.stack()[1][3]
        if resp.status_code != 200:
            self.__logger.error('%s failed with response code %s.' % (caller_func_name, resp.status_code))
        return resp.status_code, resp.json()

    def post(self, url, data, headers={}, verify=False, amend_headers=False):
        """
        common request post function with below features, which you only need to take care of url and body data:
            - append common headers
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.post, except amend_headers.

        verify: False - Disable SSL certificate verification
        """

        # append common headers if none
        headers_new = headers
        if amend_headers:
            if 'Content-Type' not in headers_new:
                headers_new['Content-Type'] = r'application/json'
            if 'User-Agent' not in headers_new:
                headers_new['User-Agent'] = 'Python Requests'

        # send post request
        resp = requests.post(url, data=data, headers=headers_new, verify=verify)

        # pretty request and response into API log file
        # Note: request print is common instead of checking if it is JSON body.
        # So pass pretty formatted json string as argument to the request for pretty logging.
        # pretty_print_request(resp.request)
        # pretty_print_response_json(resp)

        # This return caller function's name, not this function post.
        caller_func_name = inspect.stack()[1][3]
        if resp.status_code != 200:
            self.__logger.error('%s failed with response code %s.' % (caller_func_name, resp.status_code))
        return resp.status_code, resp.json()

    """ DEH Enabler Hub Wrapper"""
    def deh_enabler_hub_resource_search_by_uid(self, parameter):
        """
        Get DEH RRM registered resource by uid,
        parameter can be {"uid":<value>>}
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        deh_resource_search_url = app.config['DEH_RRM_Proxy_URL']
        headers = {"Content-Type": "application/json"}
        headers = headers
        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'],
                             "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']

        # Step 3 Attributes
        capability_token_request_resource = app.config['DEHEnablerHub_Resource']
        capability_token_request_resource += '/' + str(parameter['uid'])
        self.__logger.info("DEH RRM search resource by UID, capability_token_request_resource: "
                           "" + capability_token_request_resource)
        deh_resource_search_url = deh_resource_search_url + capability_token_request_resource
        self.__logger.info("DEH RRM search resource by UID, "
                           "deh_resource_search_url: " + deh_resource_search_url)
        headers = {"Content-Type": "application/json"}
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, headers)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_resource
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  headers)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                headers = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                headers['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                headers['x-subject-token'] = auth_token
                client = API.APIWrapper(url=deh_resource_search_url, headers=headers)
                status_code, response = client.get(verify=False)
                # self.__logger.info(response.json())
                if status_code == 200 and response.json()["data"] is not None:
                    self.__logger.info("Step 3 : DEH RRM search resource by UID, "
                                       "resource search result returned success, "
                                       "Resource matching UID {}.".format(parameter['uid']))
                    # self.__logger.info(response.json())

                if status_code == 200 and response.json()["data"] is None:
                    self.__logger.info("Step 3 : DEH RRM search resource by UID,"
                                       "resource search result returned success, "
                                       "but no resource found/ registered with UID {}.".format(parameter['uid']))
                elif status_code != 200:
                    self.__logger.error("Step 3 : DEH RRM search resource by UID, "
                                        "resource search result returned failed with response code {}. "
                                        .format(status_code))
            else:
                self.__logger.error("Step 2 : DEH RRM search resource by UID, "
                                    "Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Step 1 : DEH RRM search resource by UID, "
                                "Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_enabler_hub_resource_search(self, url=None, payload=None, headers=None, method=None):
        """
        Search DEH Resources by filters (name)
        #TODO:Make this method more dynamic, ie accept search by multiple parameters ?p1=v1&p2=v2
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        """
        if url is None:
            url = app.config['DEH_RRM_Proxy_URL']
        if headers is None:
            headers = {"Content-Type": "application/json"}
        headers = headers
        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']

        # Step 3 Attributes
        deh_resource_search_url = url
        capability_token_request_resource = app.config['DEH_RRM_Search_Resource']
        if method:
            for key in payload:
                capability_token_request_resource = method + "?" + key + "=" + payload[key]
            deh_resource_search_url = deh_resource_search_url + capability_token_request_resource
        headers = {"Content-Type": "application/json"}
        # Generate ACS token
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, headers)
        if status_code in (200, 201):
            log.info("Successfully generated ACS token, proceeding to generate capability token.")
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_resource
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  headers)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                headers = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                headers['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                headers['x-subject-token'] = auth_token
                client = API.APIWrapper(url=deh_resource_search_url, headers=headers)
                status_code, response = client.get(verify=False)
                if status_code == 200:
                    self.__logger.info("Successfully fetched all resource registration details from DEH RRM.")
                else:
                    self.__logger.error("Failed to List DEH with response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def validate_acs_token_re_usability(self):
        """ Implemented to validate if the acs token for POST metrics call can be reused. """
        status_code, response = None, None
        acs_token_expired = True
        self.__logger.info("Step 1 : Attempting to generate new ACS token. "
                           "Flow is to Reuse previously generated token if any generated and "
                           "not expiated.")
        self.__logger.debug("Validate ACS Token Re-Usability. "
                            "Response before ACS token validation {}.".format(DEHAPIWrapper.acs_token_response))
        self.__logger.debug("Validate ACS Token Re-Usability. "
                            "Status code before ACS token validation {}.".format(DEHAPIWrapper.acs_token_status_code))
        if DEHAPIWrapper.acs_token_status_code is not None and \
                DEHAPIWrapper.acs_token_response is not None and not isinstance(DEHAPIWrapper.acs_token_response, str):
            self.__logger.info("ACS token exists, validating if the token is not expired. ")
            token_info = DEHAPIWrapper.acs_token_response.json()['token']
            expiry_date = token_info['expires_at']
            date_format = '%Y-%m-%dT%H:%M:%S.%f'
            expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
            utc_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
                                                                                      time_zone="UTC")
            utc_expiry_date_datetime_obj = utc_expiry_date_datetime_obj.replace(second=0) - timedelta(minutes=10)
            local_datetime_obj = datetime.utcnow()
            # local_datetime_obj = datetime.fromtimestamp(utc_expiry_date_datetime_obj, cet)
            local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
            utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
            self.__logger.info("utc_expiry_date_datetime_obj    :   {}.".format(utc_expiry_date_datetime_obj))
            self.__logger.info("utc_now_datetime_obj            :   {}.".format(utc_now_datetime_obj))
            token_expired = (utc_expiry_date_datetime_obj.replace(tzinfo=None) <=
                             utc_now_datetime_obj.replace(tzinfo=None))
            if not token_expired:
                acs_token_expired = False
                self.__logger.info("Previous generated ACS token still valid / not-expired attempting to reuse. ")
                status_code, response = DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response
            else:
                acs_token_expired = True
                self.__logger.info("previously generated ACS token is expired. Attempting to generate new token.")
                status_code, response = None, None

        return status_code, response, acs_token_expired

    def validate_capability_token_re_usability(self):
        """ Implemented to validate if the capacity token for POST metrics call can be reused. """
        status_code, response = None, None
        capability_token_expired = True
        self.__logger.info("Step 2 : Attempting to generate new capability token. "
                           "Flow is to Reuse previously generated token if any generated & not expiated.")
        if DEHAPIWrapper.capability_token_status_code is not None and \
                DEHAPIWrapper.capability_token_response is not None:
            self.__logger.info("Capacity token exists, validating if the token is not expired. ")
            date_format = '%Y-%m-%dT%H:%M:%S.%f'
            expiry_date_epoch = DEHAPIWrapper.capability_token_response.json().get(["na"])
            dt = datetime.fromtimestamp(expiry_date_epoch, pytz.timezone('UTC'))
            expiry_date_str = dt.strftime(date_format)
            utc_expiry_date_datetime_obj = datetime.strptime(expiry_date_str, date_format)  # 2021-09-28 15:58:47
            utc_expiry_date_datetime_obj = utc_expiry_date_datetime_obj.replace(second=0) - timedelta(minutes=165)
            local_datetime_obj = datetime.utcnow()
            local_datetime_str = local_datetime_obj.strftime(date_format)
            utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
            self.__logger.info("utc_expiry_date_datetime_obj    :   {}.".format(utc_expiry_date_datetime_obj))
            self.__logger.info("utc_now_datetime_obj            :   {}.".format(utc_now_datetime_obj))
            # utc_now_datetime_str = utc_now_datetime_obj.strftime(date_format)
            token_expired = (utc_expiry_date_datetime_obj <=
                             utc_now_datetime_obj)
            if not token_expired:
                capability_token_expired = False
                self.__logger.info("Capability Token Still Valid / Not-Expired, attempting to reuse.")
                status_code, response = DEHAPIWrapper.capability_token_status_code, \
                                        DEHAPIWrapper.capability_token_response
            else:
                capability_token_expired = True
                self.__logger.info("Capability Token Expired, attempting to generate new Token.")
                status_code, response = None, None
        return status_code, response, capability_token_expired

    # def request_acs_token(self, url, payload, headers, method=None):
    #     """ Method to Get Authentication Token"""
    #     subject_token = None
    #     self.__logger.info("Step 1 : Attempting to generate new ACS token. "
    #                        "Flow is to, Reuse previously generated token if any & not expiated.")
    #     if DEHAPIWrapper.acs_token_status_code is not None and \
    #             DEHAPIWrapper.acs_token_response is not None:
    #         self.__logger.info("Validating ACS token reuse criteria.")
    #         token_info = DEHAPIWrapper.acs_token_response.json()['token']
    #         local_datetime_obj = datetime.now()
    #         local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
    #         # expiry_date = token_info['expires_at']
    #         status_code = DEHAPIWrapper.acs_token_response.status_code
    #         response = token_info.get('response')
    #         # acs_token_expiry_date = token_info.get('expires_at')
    #         date_format = '%Y-%m-%dT%H:%M:%S.%f'
    #         expiry_date_datetime_obj = parse_prefix(DEHAPIWrapper.acs_token_expiry_date, date_format)
    #         cet_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
    #                                                                                   time_zone="CET")
    #         local_datetime_obj = datetime.now()
    #         local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
    #         utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
    #         token_expired = (cet_expiry_date_datetime_obj.replace(tzinfo=None) <=
    #                          utc_now_datetime_obj.replace(tzinfo=None))
    #         if not token_expired:
    #             self.__logger.info("GET ACS token success. "
    #                                "Previous generated token still valid / not-expired so reusing.")
    #             # return f'{token} (cached!!)'
    #             status_code, response = DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response
    #             return status_code, response
    #     else:
    #         self.__logger.info("Attempting to generate new ACS token as, "
    #                            "no previously generated token exists or expiated.")
    #         if method:
    #             url = url + "/" + method + "/"
    #         client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
    #         status_code, response = client.post(verify=False)
    #         # Status code 201 --> Created
    #         if status_code in (200, 201):
    #             self.__logger.info("GET ACS token success, generated new token as, "
    #                                "no previously generated token exists or expiated. ")
    #             token_info = response.json()['token']
    #             expiry_date = token_info.get('expires_at')
    #             DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response, \
    #             DEHAPIWrapper.acs_token_expiry_date = status_code, response, expiry_date
    #         else:
    #             self.__logger.error("Failed to Get Authentication Token with response code "
    #                                 "{}".format(status_code))
    #     self.__logger.info("status_code : {} , acs_token_response : {} ."
    #                        .format(DEHAPIWrapper.acs_token_status_code,
    #                                DEHAPIWrapper.acs_token_response))
    #     return status_code, response

    def request_acs_token(self, url, payload, headers, method=None):
        """ Method to Get Authentication Token"""
        subject_token = None
        status_code = None
        response = None
        self.__logger.debug("Inside method : request_acs_token")
        if method:
            url = url + "/" + method + "/"
        client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
        status_code, response, acs_token_expired = self.validate_acs_token_re_usability()
        if response is None or acs_token_expired == True:
            self.__logger.info("Request ACS Token. Previous failed attempt to create ACS toke, "
                               "attempting to create new token. ")
            status_code, response = client.post(verify=False)
            self.__logger.debug("Request ACS Token. GET method request_acs_token, Response {}. ".format(response))
            self.__logger.debug("Request ACS Token. GET method request_acs_token, status_code {}. ".format(status_code))
            DEHAPIWrapper.acs_token_status_code, \
            DEHAPIWrapper.acs_token_response = status_code, response
        # Status code 201 --> Created
        if status_code in (200, 201):
            if acs_token_expired:
                self.__logger.info("Step 1 : Request ACS Token. "
                                   "GET ACS token success, no existing token or expired, generated new one. ")
            else:
                self.__logger.info("Step 1 : Request ACS Token. "
                                   "GET ACS token success, reusing already generated token. ")
        elif status_code == 401:
            if response is not None and not isinstance(response, str):
                self.__logger.error("Request ACS Token. Failed to Get Authentication Token with response code: "
                                    "{} and response: {} . Possibly Authentication ERROR. "
                                    "Please check the DEH Account used and access privileges.".format(status_code,
                                                                                                  response.json))
            else:
                self.__logger.error("Request ACS Token. Failed to Get Authentication Token with response code "
                                    "{} and response: {} . Possibly Authentication ERROR. "
                                    "Please check the DEH Account used and access privileges.".format(status_code,
                                                                                                  response))
        else:
            if response is not None and not isinstance(response, str):
                self.__logger.error("Request ACS Token. Failed to Get Authentication Token with response code: "
                                    "{} and response : {} . ".format(status_code, response.json))

            else:
                self.__logger.error("Request ACS Token. Failed to Get Authentication Token with response code: "
                                    "{} and response : {} . ".format(status_code, response))

        return status_code, response

    def request_capability_token(self, url, payload, headers, method=None):
        """ Method to Get the Capability token from ACS Capability Manger.
        using x-subject-token received in header from method request_acs_token (Get Authentication Token) """
        subject_token = None
        status_code = None
        response = None
        try:
            if method:
                url = url + "/" + method + "/"
            self.__logger.info("Step 2 : GET Capability Token success")
            client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
            status_code, response = client.post(verify=False)
            if status_code in [200, 201]:
                capability_token = response.text
                self.__logger.info("Step 2 : GET Capability Token success")
                self.__logger.info("Request Capability Token, "
                                   "Get Capability Token success with status code {} and response {}. "
                                    .format(status_code, self.response_format(response)))
            else:
                self.__logger.error("Request Capability Token, "
                                    "Failed to Get Capability Token with status code {} and response {}. "
                                    .format(status_code, self.response_format(response)))
        except Exception as ERROR:
            # if response is not None and not isinstance(response, str):
            #     self.__logger.error("Request Capability Token. Failed to Get Capability Token with response code: "
            #                         "{} and response : {} . ".format(status_code, response.json))
            #
            # else:
            #     self.__logger.error("Request Capability Token. Failed to Get Capability Token with response code: "
            #                         "{} and response : {} . ".format(status_code, response))

            self.__logger.error("Request Capability Token. Failed to Get Capability Token with response code: "
                                "{} and response : {} . ".format(status_code, self.response_format(response)))

        return status_code, response

    def save_deh_resource(self, resource_data, request_type="POST"):
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        """
        header = {"content-type": "application/json"}

        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']
        capability_token_request_resource = app.config['DEH_Save_Resource_Url']

        # Step 3 Attributes
        deh_save_resource_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
        deh_save_resource_payload = resource_data

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            if request_type:
                if request_type.upper() == "POST":
                    capability_token_payload['re'] = capability_token_request_resource
                    capability_token_payload['ac'] = request_type.upper()
                elif request_type.upper() == "PUT":
                    """#TODO: Right now PUT updates over criteria uid, future make available for others"""
                    capability_token_request_resource += "/" + resource_data['uid']
                    capability_token_payload['re'] = capability_token_request_resource
                    capability_token_payload['ac'] = request_type.upper()
                    deh_save_resource_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
                    # Remove ir-relevant keys from resource data, in case of PUT request
                    keys_to_remove = ["uid", "createAt", "lastUpdate", "downloadsHistory", "billingInformation",
                                      "rating", "attachment"]
                    for key in keys_to_remove:
                        try:
                            del deh_save_resource_payload[key]
                        except KeyError:
                            continue
                    # Hardcoded the value of  localisation as its creating problems while put
                    deh_save_resource_payload["localisation"] = [
                        {
                            "type": "Point",
                            "coordinates": [
                                0,
                                0
                            ]
                        }
                    ]
            capability_token_payload['de'] = capability_token_proxy_url
            status_code, response = self.request_capability_token(capability_token_url, capability_token_payload,
                                                                  header)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                header = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                header['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                header['x-subject-token'] = auth_token
                payload = deh_save_resource_payload
                client = API.APIWrapper(url=deh_save_resource_url, payload=json.dumps(payload), headers=header)
                if request_type.upper() == "POST":
                    status_code, response = client.post(verify=False)
                elif request_type.upper() == "PUT":
                    """#TODO: Use common lib for PUT"""
                    status_code, response = client.put(verify=False)
                    response = requests.request("PUT", deh_save_resource_url, data=json.dumps(payload), headers=header)
                    status_code = response.status_code
                if status_code == 200:
                    self.__logger.info("Successfully registered/ save resource with DEH RRM")
                else:
                    self.__logger.error("Failed to register/save DEH resource : {}".format(resource_data['name']))
                    self.__logger.error("Failed to register/save DEH resource response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    """ DEH RRM Metrics APIs"""

    def response_format(self, response):
        if response is not None and not isinstance(response, str):
            response = response.json()
        elif response is not None and isinstance(response, str):
            response = response
        elif response is None:
            response = response
        return response

    def post_deh_metrics(self, resource_data, request_type="POST"):
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Post Metrics Data to DEH
        """
        # Read Metric Data from MongoDB

        try:
            resource_list = [data["_id"] for data in resource_data]
            payload = resource_data
            self.__logger.info("Post metrics, Attempting to post metrics for resource/s {}.".format(resource_list))
            header = {"content-type": "application/json"}

            # Step 1 Attributes:
            asc_token_url = app.config['ACS_Token_Request_Url']
            asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
            self.__logger.debug("POST metrics, acs token payload {}.".format(asc_token_payload))

            # Step 2 Attributes:
            capability_token_url = app.config['Capability_Token_Url']
            capability_token_payload = app.config['Request_Capability_Token_Format']
            '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
                "de": "$ProxyURL", "re": "$Resource"}'''
            capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']
            capability_token_request_resource = app.config['DEH_RRM_Metrics']
            self.__logger.debug("POST metrics, capability token payload {}."
                                .format(capability_token_payload))

            # Step 3 Attributes
            self.__logger.info("Step 1: POST metrics, Attempting to generate ACS token.")
            deh_metrics_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
            status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
            # if response is not None and not isinstance(response, str):
            #     self.__logger.info("POST metrics, ACS token status code: {} and response: {}. "
            #                        .format(status_code, response.json()))
            # else:
            #     self.__logger.debug("POST metrics, ACS token status code: {} and response: {}. "
            #                         .format(status_code, response))

            self.__logger.debug("POST metrics, ACS token status code: {} and response: {}. "
                                .format(status_code, self.response_format(response)))

            if status_code in (200, 201):
                self.__logger.info("Step 1 : POST metrics, ACS token success. ")
                self.__logger.info("Step 2: POST metrics, Attempting to generate capability token.")
                auth_token = response.headers['X-Subject-Token']
                capability_token_payload['token'] = auth_token
                if request_type:
                    if request_type.upper() == "POST":
                        capability_token_payload['re'] = capability_token_request_resource
                        capability_token_payload['ac'] = request_type.upper()
                capability_token_payload['de'] = capability_token_proxy_url

                status_code, response = self.request_capability_token(capability_token_url,
                                                                      capability_token_payload,
                                                                      header)

                if status_code in (200, 201):
                    self.__logger.info("Step 2 : POST metrics, GET capability token success. ")

                    # Adding the entire capacity token request's response as x-auth-token header for saving resource
                    header = app.config['DEH_RRM_Request_Header']
                    capability_token_response = response
                    header['x-auth-token'] = capability_token_response.text
                    # As per new RRM change, x-subject-token needs to be included in all RRM API request
                    header['x-subject-token'] = auth_token
                    header['Accept'] = "application/json"
                    # client = API.APIWrapper(url=deh_metrics_url, payload=json.dumps(payload), headers=header)
                    if request_type.upper() == "POST":
                        # status_code, response = client.post(verify=False)
                        response = requests.request("POST", deh_metrics_url, data=json.dumps(payload), headers=header)
                        if status_code == 200 and response.json()['success'] == True:
                            self.__logger.info("Successfully Post metrics data with DEH RRM for container id : {} "
                                               .format(resource_list))
                        else:
                            try:
                                if response is not None and not isinstance(response, str):
                                    self.__logger.error("POST metrics to RRM. Failed to Post metrics data for "
                                                        "container id {}, with status code {} and "
                                                        "response : {}. "
                                                        .format(resource_list, status_code, response.json()))
                                else:
                                    self.__logger.error("POST metrics to RRM. Failed to Post metrics data for "
                                                        "container id {}, with status code {} and "
                                                        "response : {}. "
                                                        .format(resource_list, status_code, response))
                            except Exception as error:
                                pass

                            # To handle exception "TypeError: list indices must be integers or slices, not str"
                            try:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for uid : {}".
                                                    format(resource_list))

                            except TypeError as error:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for "
                                                    "Container id : {} with error : {}.".format(resource_list,
                                                                                                error))
                            except Exception as error:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for Container id : {} "
                                                    "with exception : {}".format(resource_list, error))

                    else:
                        self.__logger.error("Invalid request_type selected for method post_deh_metrics.")
                else:
                    if response is not None and not isinstance(response, str):
                        self.__logger.error("POST metrics to RRM. "
                                            "Failed to Get Capability Token with status code: {} and "
                                            "response: {}. ".format(status_code, response.json()))
                    else:
                        self.__logger.error("POST metrics to RRM. "
                                            "Failed to Get Capability Token with status code: {} and "
                                            "response: {}. ".format(status_code, response))
            else:
                if response is not None and not isinstance(response, str):
                    self.__logger.error("POST metrics to RRM. "
                                        "Failed to Get Authentication Token with status code: {} and "
                                        "response: {}. ".format(status_code, response.json()))
                else:
                    self.__logger.error("POST metrics to RRM. "
                                        "Failed to Get Authentication Token with status code: {} and "
                                        "response: {}. ".format(status_code, response))
            return status_code, response

        except KeyError as error:
            self.__logger.error("POST metrics to RRM. "
                                "Exception encountered posting metrics data to RRM with error: {}. Possibly "
                                "missing keyword in the resource data. ".format(error))
        except Exception as error:
            self.__logger.error("POST metrics to RRM. "
                                "Exception encountered posting metrics data to RRM with error: {}.".format(error))

    def delete_local_db_records(self, query):
        """ Module to delete metrics records in local DB which are not posted to RRM"""
        remove_document = self.mongo_client.delete_filter(query)
        self.__logger.info("Delete/Purging old records. Status: {} ".format(remove_document))

    def initiate_post_deh_metrics_request(self, record):
        self.__logger.info("Inside initiate POST Metrics to RRM.")
        if record:
            if record != {} or record is not None:
                try:
                    self.__logger.info("Attempting to update metrics to RRM for container id : {} . "
                                       .format([data["_id"] for data in record]))
                    status_code, response = self.post_deh_metrics(record, request_type="POST")
                    if status_code == 200 and response.json()["success"] is True:
                        # Once metrics is successfully posted clear mongoDB metrics collection for the specific container
                        # If failed post, the record/s will be retained till next successful attempt
                        #   TODO : Future implementation, retain historic data
                        self.__logger.info("Successfully posted metrics to RRM with response {} .".format(response.json()))
                        for document in record:
                            self.__logger.info("Deleting record for container ID {} "
                                               "from internal DB after metrics result successfully posted to RRM."
                                               .format(document['_id']))
                            remove_document = self.mongo_client.delete_one({"_id": document['_id']})
                    else:
                        try:
                            self.__logger.error("Initiate POST Metrics to RRM. "
                                                "Failed to post metrics to RRM with status code {} and response {}."
                                                .format(status_code, response))
                            if response is not None and not isinstance(response, str):
                                self.__logger.error("Initiate POST Metrics to RRM. "
                                                    "Failed to post metrics to RRM with response {}, "
                                                    "will be reattempted later. ".format(response.json()))
                            else:
                                self.__logger.error("Initiate POST Metrics to RRM. "
                                                    "Failed to post metrics to RRM with response {}, "
                                                    "will be reattempted later. ".format(response))

                        except Exception as error:
                            pass
                except Exception as error:
                    self.__logger.warning("Initiate POST Metrics to RRM. "
                                          "Exception encountered Possibly missing keyword.")
                    self.__logger.warning("ERROR : {}".format(traceback.print_exc()))

            else:
                self.__logger.warning("Initiate POST Metrics to RRM. record: {} is None or not a dictionary"
                                      .format(record))
        else:
            self.__logger.warning("Initiate POST Metrics to RRM. "
                                  "No metrics records found in local DB to be post to RRM. ")
            return

    """ DEH BSE API Wrapper"""
    def deh_bse_get_running_services(self):
        """ BSE endpoint that returns a list of the running services """
        status_code = response = None
        global validate_by
        header = app.config['DEH_RRM_Request_Header']
        self.__logger.info("GET BSE get all running services. ")
        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        # Condition to switch if the request is to get all services or get service by name
        if self.payload is None:
            bse_get_running_services_url = self.url + self.method
            capability_token_request_services = app.config['DEH_BSE_GET_SERVICES']
        elif self.payload is not None:
            if 'service_name' in self.payload:
                self.__logger.info("Get BSE service by name is enabled")
                validate_by = "Service Name"
                bse_get_running_services_url = self.url + self.method + "/" + self.payload['service_name']
                # For search by service name, capacity token request format:
                '''{"token": "3d0782f4-3d57-4bed-b8a1-324a8d3aebb4","ac": "GET", 
                "de": "https://vm1.test.h2020-demeter-cloud.eu:443", "re": "/api/BSE/service/<<service name>>"}'''
                capability_token_request_services = self.method + "/" + self.payload['service_name']
            if 'deh_id' in self.payload:
                self.__logger.info("Get BSE service by deh_id is enabled")
                validate_by = "UID"
                bse_get_running_services_url = self.url + self.method + "/" + self.payload['deh_id']
                # For search by service name, capacity token request format:
                '''{"token": "3d0782f4-3d57-4bed-b8a1-324a8d3aebb4","ac": "GET", 
                "de": "https://vm1.test.h2020-demeter-cloud.eu:443", "re": "/api/BSE/service/<<service name>>"}'''
                capability_token_request_services = self.method + "/" + self.payload['deh_id']

        status_code = response = capability_token_response = None
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services

            capability_token_status_code, capability_token_response = self.request_capability_token(
                                                                    capability_token_url,
                                                                    capability_token_payload,
                                                                    header)
            if capability_token_status_code in (200, 201):
                # self.__logger.info("#### Inside capability loop, ACS token created success {} & {}."
                #                    .format(status_code, auth_token))
                # Adding the entire capability token request's response as x-auth-token header for saving resource
                capability_token_response = capability_token_response
                header['x-auth-token'] = capability_token_response.text
                # client = API.APIWrapper(url=bse_get_running_services_url, headers=header)
                # status_code, response = client.get(verify=False)
                try:
                    # response = requests.request("GET", bse_get_running_services_url, headers=header, verify=False)

                    self.__logger.info("Inside capability loop, ACS token created success {} & {} & {} & {}."
                                       .format(status_code, auth_token, bse_get_running_services_url,
                                               capability_token_response.text))
                    # response = requests.get(bse_get_running_services_url,
                    #                         verify=False,
                    #                         headers=header)
                    # status_code = response.status_code
                    client = API.APIWrapper(url=bse_get_running_services_url, headers=header)
                    status_code, response = client.get(verify=False)
                    if status_code == 200:
                        if response is not None and not isinstance(response, str):
                            self.__logger.info("Step 3 : Successfully authorized, "
                                               "BSE list of running resources  with status code: {} and "
                                               "response: {}."
                                               .format(status_code, response.json()))
                        elif response is not None and isinstance(response, str):
                            self.__logger.info("Step 3 : Successfully authorized, "
                                               "BSE list of running resources  with status code: {}."
                                               .format(status_code, response))
                    else:
                        if response is not None and not isinstance(response, str):
                            self.__logger.warning("Step 3 : BSE. Successfully authorized, "
                                                  "But failed to get services list response code {} and "
                                                  "response: {}."
                                                  .format(status_code, response.json()))
                        elif response is not None and isinstance(response, str):
                            self.__logger.warning("Step 3 : BSE. Successfully authorized, "
                                                  "But failed to get services list response code {} and "
                                                  "response: {}."
                                                  .format(status_code, response))
                except Exception as ERROR:
                    if response is not None and not isinstance(response, str):
                        self.__logger.warning("Step 3 : BSE. Successful generated Capability token, "
                                              "But failed to list of running services with error: {}, "
                                              "status code: {} and response: {}.".format(ERROR,
                                                                                         status_code,
                                                                                         response.json()))

                    elif response is not None and isinstance(response, str):
                        self.__logger.warning("Step 3 : BSE. Successful generated Capability token, "
                                              "But failed to list of running services with error: {}, "
                                              "status code: {} and response: {}.".format(ERROR,
                                                                                         status_code,
                                                                                         response))
                    elif response is None:
                        self.__logger.warning("Step 3 : BSE. Successful generated Capability token, "
                                              "But failed to list of running services with error: {}, "
                                              "status code: {} and response: {}.".format(ERROR,
                                                                                         status_code,
                                                                                         response))

            else:
                self.__logger.warning("Failed to Get Capability Token with response code {}"
                                      .format(status_code))
                if capability_token_response is not None and not isinstance(capability_token_response,str):
                    self.__logger.warning("Get running Services that are registered with BSE, Validate by {}. "
                                          "Failed to generate capability token."
                                          "Status Code : {} and Response {}"
                                          .format(validate_by,
                                                  status_code,capability_token_response.json()))

                else:
                    self.__logger.warning("Get running Services that are registered with BSE, Validate by {}. "
                                          "Failed to generate capability token with ."
                                          "Status Code : {} and Response {}."
                                          .format(validate_by,
                                                  status_code,
                                                  capability_token_response))

        else:
            self.__logger.warning("Failed to Get Authentication Token with response code {}".format(status_code))
            self.__logger.warning("Get running Services that are registered with BSE, Validate by {}. "
                                  "Failed to generate ACS token."
                                  .format(validate_by))

        return status_code, response

    def deh_bse_get_bse_register_service_payload(self, parameter):
        if 'id' in parameter:
            service_name = parameter['id']
        elif 'name' in parameter:
            service_name = parameter['name']
        return

    def deh_bse_get_service_by_parameter(self, parameter):
        """TODO : Not used ,in-corporate ed search by name functionality in method deh_bse_get_running_services"""
        """ BSE endpoint that returns a list of the running services """
        header = app.config['DEH_BSE_Request_Header']

        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        capability_token_request_services = app.config['DEH_BSE_GET_SERVICE']

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  header)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                capability_token_response = response
                header['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                header['x-subject-token'] = auth_token
                bse_get_service_by_name_url = self.url + self.method + "/" + self.payload['service_name']
                self.__logger.info("BSE list all services : " + bse_get_service_by_name_url)
                client = API.APIWrapper(url=bse_get_service_by_name_url, headers=header)
                status_code, response = client.get(verify=False)
                if status_code == 200:
                    self.__logger.info("Step 3 : Successfully authorized, BSE list of running resources")
                else:
                    self.__logger.warning("Failed to get service by name with response code {}".format(status_code))
            else:
                self.__logger.warning("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.warning("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_bse_post_register_service(self):
        """ BSE endpoint that returns a list of the running services """
        status_code = None
        response = None
        service_name = self.payload['service_name']
        self.__logger.info("DEH POST BSE Register Service. Attempting to register service name: {} to BSE. "
                           .format(service_name))
        header = app.config['DEH_BSE_Request_Header']
        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        capability_token_request_services = app.config['DEH_BSE_Register_Service']

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            self.__logger.info("Step 1 : DEH POST BSE Register Service. Successfully generated ACS token. ")
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "POST"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services
            status_code, capability_token_response = self.request_capability_token(capability_token_url,
                                                                                   capability_token_payload, header)
            if 'tag' not in self.payload:
                self.payload['tags'] = ["Test"]
            if status_code == 200:
                self.__logger.info("Step 2 : DEH POST BSE Register Service. Successfully generated Capability token. ")
                # Step 3 Register service with BSE:
                bse_service_register_url = self.url + self.method
                header['x-auth-token'] = capability_token_response.text
                deh_id = None
                deh_id = self.payload['uid']
                # if 'uid' not in self.payload:
                #     # GET RRM info
                #     method = app.config['DEHEnablerHub_Search_Resource']
                #     # deh_enabler_hub_obj = DEHAPIWrapper()
                #     parameters = {"name": self.payload['service_name']}
                #     status_code, response = self.deh_enabler_hub_resource_search(payload=parameters,
                #                                                                  method=method)
                #     if status_code == 200 and response.json()[
                #         "message"] != "Bad request." and "data" in response.json():
                #         contents = response.json()["data"]
                #         if len(contents) == 0:
                #             self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                #                                "Now attempt to register.".format(self.payload['service_name']))
                #         else:
                #             """#TODO: Handle multiple resources with same name in future"""
                #             for resource in contents:
                #                 deh_id = resource['uid']
                #                 break
                #             # name = response.json()['name']
                # payload = {"service_name": self.payload['service_name'],
                #            "name": self.payload['service_name'],
                #            "tags": self.payload['tags'],
                #            "meta": {
                #                "deh_id": deh_id,
                #                "featureList": ["NEW TEST FEATURE LIST"],
                #                "applicationCategory": "NEW applicationCategory LIST",
                #                "apiModel": {
                #                    "dataProtocol": "REST",
                #                    "baseUrl": "GOOGLE.COM",
                #                    "relativePath": "/path",
                #                    "method": "GET",
                #                    "successResponse": [200],
                #                    "errorResponse": [500],
                #                    "topic": "TEST",
                #                    "payloadFormat": "JSON"}
                #            },
                #            "port": 0,
                #            "address": "string"}
                #
                # payload = {"service_name": self.payload['service_name'],
                #            "name": self.payload['service_name'],
                #            "tags": self.payload['tags'],
                #            "meta": {"deh_id": deh_id,
                #                     "featureList": ["NEW TEST FEATURE LIST"],
                #                     "applicationCategory": "NEW applicationCategory LIST",
                #                     "apiModel": {
                #                         "dataProtocol": "REST",
                #                         "baseUrl": "GOOGLE.COM",
                #                         "relativePath": "path",
                #                         "method": "GET",
                #                         "successResponse": [200],
                #                         "errorResponse": [500],
                #                         "topic": "DDDDDD",
                #                         "payloadFormat": "JSON"}
                #                     },
                #            "port": 0,
                #            "address": "string"}
                #
                # payload = {
                #         "Service_name": self.payload['service_name'],
                #         "name": self.payload['service_name'],
                #         "Tags": self.payload['tags'],
                #         "Meta": {
                #             "URLOptionalParams": "{}",
                #             "URLRequiredParams": "{}",
                #             "applicationCategory": "algorithm",
                #             "authentication": "False",
                #             "baseUrl": "http://161.27.206.132:9380",
                #             "dataEncryption": "False",
                #             "dataParams": "{}",
                #             "dataProtocol": "REST",
                #             "deh_id": deh_id,
                #             "errorResponse": "[0]",
                #             "featureList": "['feature1']",
                #             "method": "GET/POST",
                #             "payloadFormat": "JSON-LD",
                #             "payloadRepresentation": "{}",
                #             "provider": "Engineering",
                #             "relativePath": "TEST",
                #             "sampleCall": "",
                #             "successResponse": "[0]",
                #             "topic": "string",
                #             "version": "1"
                #         },
                #         "Port": 9380,
                #         "Address": self.payload['IPAddress']
                #     }
                # payload = {"service_name": self.payload['service_name'],
                #              "tags": ["latest"],
                #              "name": self.payload['service_name'],
                #              "meta": {"deh_id": deh_id,
                #                       "featureList": ["NEW TEST FEATURE LIST"],
                #                       "applicationCategory": "NEW applicationCategory LIST",
                #                       "apiModel": {
                #                           "deh_id": deh_id,
                #                           "dataProtocol": "REST",
                #                           "baseUrl": "GOOGLE.COM",
                #                           "relativePath": "path",
                #                           "method": "GET",
                #                           "successResponse": [200],
                #                           "errorResponse": [500],
                #                           "topic": "Test_Registration",
                #                           "payloadFormat": "JSON"}
                #                       },
                #              "port": 0,
                #              "address": self.payload['IPAddress']}

                # payload = {"name": self.payload['service_name'],
                #            "tags": ["latest"],
                #            "meta": {
                #                     "deh_id": deh_id,
                #                     "additionalProp1": "string",
                #                     "additionalProp2": "string",
                #                     "additionalProp3": "string"
                #                     },
                #            "port": 0,
                #            "address": self.payload['IPAddress']
                #            }

                payload = {
                          "service_name": self.payload['service_name'],
                          "deh_id": deh_id,
                          "address": "0.0.0.1",
                          "port": 0,
                          "tags": [
                            "latest"
                          ],
                          "meta": {
                            "applicationCategory": "string",
                            "description": "string",
                            "version": 0,
                            "featureList": [
                              "string"
                            ],
                            "dataEncryption": True,
                            "authentication": True,
                            "conditionsOfAccess": "string",
                            "timeRequired": 0,
                            "quota": "string",
                            "offers": 0,
                            "TermsOfService": "string",
                            "usageInfo": "string",
                            "provider": "string",
                            "spatial": "string",
                            "aggregateRating": 0,
                            "apiModel": {
                              "dataProtocol": "REST",
                              "baseUrl": "string",
                              "relativePath": "string",
                              "method": "GET",
                              "URLRequiredParams": {

                              },
                              "URLOptionalParams": {

                              },
                              "dataParams": {

                              },
                              "successResponse": [
                                0
                              ],
                              "errorResponse": [
                                0
                              ],
                              "sampleCall": "string",
                              "topic": "string",
                              "payloadFormat": "JSON",
                              "payloadRepresentation": {}
                            }
                          }
                        }
                self.__logger.info("DEH POST BSE Register Service. Attempting to register service name {}, with "
                                   "payload: {}. ".format(service_name, payload))
                client = API.APIWrapper(url=bse_service_register_url, payload=json.dumps(payload), headers=header)
                status_code, response = client.post(verify=False)
                #response = requests.post(bse_service_register_url, data=json.dumps(payload), headers=header)
                # response = requests.request("POST", bse_service_register_url, data=payload, headers=header)
                # status_code = response.status_code
                if status_code in [200, 201]:
                    self.__logger.info("Step 3: DEH POST BSE Register Service. Successfully registered service to BSE, "
                                       "with response: {} and status code: {}. ".format(self.response_format(response),
                                                                                        status_code))
                    return status_code, response
                    # try:
                    #     if response is not None and not isinstance(response, str):
                    #         self.__logger.info("Step 3: DEH POST BSE Register Service. "
                    #                            "Successfully registered service to BSE, "
                    #                            "with response: {} and status code: {}. "
                    #                            "".format(response.json(), status_code))
                    #     elif response is not None and isinstance(response, str):
                    #         self.__logger.info("Step 3: DEH POST BSE Register Service. "
                    #                            "Successfully registered service to BSE, "
                    #                            "with response: {} and status code: {}. "
                    #                            "".format(response, status_code))
                    #     else:
                    #         self.__logger.info("Step 3: DEH POST BSE Register Service. "
                    #                            "Successfully registered service to BSE, "
                    #                            "with response: {} and status code: {}. "
                    #                            "".format(response, status_code))
                    # except Exception as error:
                    #     self.__logger.info("Step 3: DEH POST BSE Register Service. "
                    #                        "Successfully registered service to BSE, "
                    #                        "with status code: {}. "
                    #                        "".format(status_code))
                    #     return status_code, response
                elif status_code not in [200, 201]:
                    self.__logger.warning("DEH BSE Registration failed with response text : {} and status code: {}. "
                                          .format(self.response_format(response), status_code))
                    return status_code, response
                    # try:
                    #     self.__logger.warning("DEH BSE Registration failed with response text : {} and "
                    #                           "status code: {}."
                    #                           .format(response, status_code))
                    # except:
                    #     self.__logger.warning("DEH BSE Registration failed with response json : {} and "
                    #                           "status code: {}."
                    #                           .format(response, status_code))
                    #
                    # try:
                    #     if response is not None and isinstance(response, str):
                    #         self.__logger.warning("Step 3 : DEH POST BSE Register Service. "
                    #                               "Failed to register services to BSE with response: {} and "
                    #                               "status code: {} ".format(response, status_code))
                    #     if response is not None and not isinstance(response, str):
                    #         self.__logger.warning("Step 3 : DEH POST BSE Register Service. "
                    #                               "Failed to register services to BSE with response: {} and "
                    #                               "status code: {} ".format(response.json(), status_code))
                    #     else:
                    #         self.__logger.warning("Step 3 : DEH POST BSE Register Service. "
                    #                               "Failed to register services to BSE with response: {} and "
                    #                               "status code: {} ".format(response, status_code))
                    #     return status_code, response
                    #
                    # except Exception as error:
                    #     self.__logger.warning("Step 3 : DEH POST BSE Register Service. "
                    #                           "Failed to register services to BSE "
                    #                           "status code: {} ".format(response, status_code))
                    #     return status_code, response
            else:
                self.__logger.warning("DEH POST BSE Register Service. "
                                      "Failed to Get Capability Token with response code {} and response {}. "
                                      .format(status_code, self.response_format(response)))
                return status_code, response
        else:
            self.__logger.warning("DEH POST BSE Register Service. "
                                  "Failed to Get Authentication Token with response code {} and response {}. "
                                  .format(status_code, self.response_format(response)))
            self.__logger.warning("DEH POST BSE Register Service. "
                                  "Failed to Get Authentication Token with response code {} and response {}. "
                                  .format(status_code, self.response_format(response)))
        return status_code, response

    def deh_bse_check_resource_registration(self, service_registration_payload):
        """TODO: May be this will be removed if DEH Client is not responsible for registering to BSE"""
        # Check if the service/ resource is registered to BSE, if not register
        response = None
        host = app.config['DEH_BSE_Proxy_URL']
        method = app.config['DEH_BSE_GET_SERVICE']
        """ Note : The service name is case sensitive"""
        service_name = service_registration_payload['service_name']
        self.__logger.info("BSE GET Check Registration by Name. Check if service by name {} "
                           "is already registered with BSE. ".format(service_name))
        deh_bse_obj = DEHAPIWrapper(host, method,
                                    payload={"service_name": service_name})
        status_code, response = deh_bse_obj.deh_bse_get_running_services()
        # if isinstance(response, str):
        #     self.__logger.warning("BSE GET Check Registration by Name. "
        #                           "Failed to validate if Service : {} is already registered with BSE. Response : {}. "
        #                           .format(service_name, response))
        #     return response
        if response is not None:
            if status_code == 200 and (response.json() == {} or response.json() == []):
                self.__logger.info("BSE GET Check Registration by Name. Service {} is not registered to BSE, "
                                   "Now attempt to register to BSE.".format(service_name))
                self.__logger.info("BSE GET Check Registration by Name. Service {} is not registered to BSE, "
                                   "Now attempt to register to BSE. Response: {} status code: {}."
                                   .format(service_name, response.text, status_code))
                method = app.config['DEH_BSE_Register_Service']

                deh_bse_obj = DEHAPIWrapper(host, method,
                                            payload=service_registration_payload)
                status_code, response = deh_bse_obj.deh_bse_post_register_service()
                if status_code == 200:
                    self.__logger.info("BSE GET Check Registration by Name. "
                                       "Successfully registered service: {} to BSE.".format(service_name))
                    try:
                        if response is not None and not isinstance(response, str):
                            self.__logger.info("BSE GET Check Registration by Name. "
                                               "Successfully registered service: {} to BSE with response: {} "
                                               "and status code: {} .".format(service_name, response.json(),
                                                                              status_code))
                        elif response is not None and isinstance(response, str):
                            self.__logger.info("BSE GET Check Registration by Name. "
                                               "Successfully registered service: {} to BSE with response: {} "
                                               "and status code: {} .".format(service_name, response,
                                                                              status_code))
                    except Exception as error:
                        self.__logger.debug("BSE GET Check Registration by Name. "
                                            "Service: {} already registered to BSE. BSE registration details: {} ."
                                            .format(service_name, response))
                        pass
                else:
                    self.__logger.warning("BSE GET Check Registration by Name. "
                                          "Registration service: {} to BSE failed with response code {} "
                                          "and response {}.".format(service_name, status_code, response))
            elif status_code == 200 and (response.json() != {} or response.json() != []):
                # self.__logger.info("BSE GET Check Registration by Name. "
                #                    "Service: {} already registered to BSE.".format(service_name))
                try:
                    if response is not None and not isinstance(response, str):
                        self.__logger.debug("BSE GET Check Registration by Name. "
                                            "Service: {} already registered to BSE. BSE registration details: {} ."
                                            .format(service_name, response.json()))
                    else:
                        self.__logger.debug("BSE GET Check Registration by Name. "
                                            "Service: {} already registered to BSE. BSE registration details: {} ."
                                            .format(service_name, response))

                except Exception as error:
                    self.__logger.debug("BSE GET Check Registration by Name. "
                                        "Service: {} already registered to BSE. BSE registration details: {} ."
                                        .format(service_name, response))
                    pass

        else:
            self.__logger.error("BSE GET Check Registration by Name. "
                                "Failed to validate if Service name: {} "
                                "is registered with BSE, with response: {} and status code: {}. "
                                .format(service_name, response, status_code))
        # else:
        #     try:
        #         if response is not None and not isinstance(response, str):
        #             self.__logger.error("BSE GET Check Registration by Name. "
        #                                 "Failed to validate if Service name: {} "
        #                                 "is registered with BSE, with response: {} and status code: {}. "
        #                                 .format(service_name, response.json(), status_code))
        #
        #         else:
        #             self.__logger.error("BSE GET Check Registration by Name. "
        #                                 "Failed to validate if Service name: {} "
        #                                 "is registered with BSE, with response: {} and status code: {}. "
        #                                 .format(service_name, response, status_code))
        #     except Exception as error:
        #         self.__logger.warning("BSE GET Check Registration by Name. "
        #                               "Failed to validate if Service name {} is already registered with BSE. "
        #                               "Status code: {}. "
        #                               .format(service_name, status_code))
        #         pass

        return response

    def deh_rrm_check_resource_registration(self, resource_name, resource_data):
        # Check if the service/ resource is registered to RRM, if not register
        self.__logger.info("Checking if the service/ resource is registered to RRM, if not set to register")
        method = app.config['DEHEnablerHub_Search_Resource']
        deh_enabler_hub_obj = DEHAPIWrapper()
        parameters = {"name": resource_name}
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=parameters,
                                                                                    method=method)
        if status_code == 200 and response.json()["message"] != "Bad request." and "data" in response.json():
            contents = response.json()["data"]
            if contents is not None:
                self.__logger.info("Resource Name Attempting To Register : ".format(resource_name))
                self.__logger.info("Resource Data For Resource Name Attempting To Register".format(resource_data))
                if len(contents) == 0:
                    self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                                       "Now attempt to register.".format(resource_name))
                    deh_enabler_hub_obj = DEHAPIWrapper()
                    self.__logger.info("Resource Registration Metadata :{} ".format(resource_data))
                    self.__logger.info("deh_rrm_check_resource_registration Resource Data {}".format(resource_data))
                    status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="POST")
                    if status_code == 200:
                        self.__logger.info("Successfully registered resource: {} "
                                           "to DEH Enabler Hub RRM with response:\n {}."
                                           .format(resource_name, response.text))
                    if status_code == 409:
                        # In case of attempting to register a resource, which is already registered with RRM,
                        # The RRM POST request response : Response Code
                        """
                        {
                        "httpStatus": "CONFLICT",
                        "message": "Resource with a name estimate-animal-welfare-condition-demo1 already exists",
                        "timestamp": "27-04-2021 03:19:39",
                        "path": "/api/v1/resources"
                        }
                        """
                        try:
                            self.__logger.info("Seems Resource/ Service: {} already registered to DEH Enabler Hub RRM."
                                               .format(resource_name))
                            self.__logger.info("Response : {}.".format(response.json()))
                        except Exception as error:
                            pass
                    else:
                        self.__logger.error("Failure to Register resource: {} to DEH Enabler Hub RRM."
                                            .format(resource_name))

        else:
            try:
                self.__logger.error("Failure to connect with RRM to DEH Enabler Hub RRM.")
                self.__logger.error("Response : {}.".format(response.json()))
            except Exception as error:
                pass
        return response
