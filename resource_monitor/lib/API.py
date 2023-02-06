import requests
import logging
import os
import inspect
import json 

LOG_LEVEL = logging.INFO #DEBUG, INFO, WARNING, ERROR, CRITICAL
common_formatter = logging.Formatter('%(asctime)s [%(levelname)-7s][ln-%(lineno)-3d]: %(message)s', datefmt='%Y-%m-%d %I:%M:%S')

# root_path is parent folder of Scripts folder (one level up)
root_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def setup_logger(log_file, level=logging.INFO, name='', formatter=common_formatter):
    """Function setup as many loggers as you want."""
    handler = logging.FileHandler(log_file, mode='w')#default mode is append
    # Or use a rotating file handler
    # handler = RotatingFileHandler(log_file,maxBytes=1023, backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger

# default debug logger
debug_log_filename = '../debug.log'
log = setup_logger(debug_log_filename, LOG_LEVEL,'log')

api_formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%Y-%m-%d %I:%M:%S')
api_outputs_filename = '../api_outputs.log'
log_api = setup_logger(api_outputs_filename, LOG_LEVEL,'log_api',formatter = api_formatter)


class APIWrapper:
    """
    Test Restful HTTP API examples.
    """
    def __init__(self, url=None, method=None, payload=None, headers=None):
        self.url = url
        self.method = method
        self.payload = payload
        self.headers = headers

    def get(self, auth=None, verify=False):
        """
        common request get function with below features, which you only need to take care of url:
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.get

        verify: False - Disable SSL certificate verification
        """
        try:
            s = requests.Session()
            if self.method:
                self.url = self.url + self.method + "/"
            if auth == None:
                if self.payload is not None:
                    response = s.get(self.url, params=self.payload, verify=verify, headers=self.headers)
                else:
                    response = s.get(self.url, verify=verify, headers=self.headers)
            else:
                response = requests.get(self.url, auth=auth, verify=verify, headers=self.headers)
                if self.payload is not None:
                    response = requests.get(self.url, auth=auth, verify=verify, headers=self.headers)
                else:
                    response = requests.get(self.url, auth=auth, params=self.payload, verify=verify, headers=self.headers)
            response.raise_for_status()
            # pretty request and response into API log file
            self.pretty_print_request(response.request)
            self.pretty_print_response_json(response)
            # This return caller function's name, not this function post.
            caller_func_name = inspect.stack()[1][3]
            if response.status_code != 200:
                log.error('%s failed with response code %s.' % (caller_func_name, response.status_code))
            #return response
        except requests.exceptions.HTTPError as err:
            return response.status_code, "An Http Error occurred:" + repr(err)
        except requests.exceptions.ConnectionError as err:
            return response.status_code, "An Error Connecting to the API occurred:" + repr(err)
        except requests.exceptions.Timeout as err:
            return response.status_code, "A Timeout Error occurred:" + repr(err)
        except requests.exceptions.RequestException as err:
            return response.status_code, "An Unknown Error occurred" + repr(err)
        return response.status_code, response

    def post(self, verify=False, amend_headers=False):
        """
        common request post function with below features, which you only need to take care of url and body data:
            - append common headers
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.post, except amend_headers.

        verify: False - Disable SSL certificate verification
        """
        err = None
        if self.method:
            self.url = self.url + "/" + self.method + "/"
        # append common headers if none
        headers_new = self.headers
        if amend_headers == True:
            if 'Content-Type' not in headers_new:
                headers_new['Content-Type'] = r'application/json'
            if 'User-Agent' not in headers_new:
                headers_new['User-Agent'] = 'Python Requests'
        try:
            # send post request
            response = requests.post(self.url, data=self.payload, headers=self.headers, verify=verify)
            response.raise_for_status()
            # pretty request and response into API log file
            # Note: request print is common instead of checking if it is JSON body. So pass pretty formatted json string as argument to the request for pretty logging.
            self.pretty_print_request(response.request)
            self.pretty_print_response_json(response)
            # This return caller function's name, not this function post.
            caller_func_name = inspect.stack()[1][3]
            if response.status_code != 200:
                log.error('%s failed with response code %s.' % (caller_func_name, response.status_code))
            return response.status_code, response
        except requests.exceptions.HTTPError as err:
            return response.status_code, "An Http Error occurred: {}.".format(err)
        except requests.exceptions.ConnectionError as err:
            return response.status_code, "An Error Connecting to the API occurred: {}.".format(err)
        except requests.exceptions.Timeout as err:
            return response.status_code, "A Timeout Error occurred: {}.".format(err)
        except requests.exceptions.RequestException as err:
            return response.status_code, "An Unknown Error occurred {}.".format(err)

    def put(self, verify=False, amend_headers=False):
        """Sends a PUT request."""
        if self.method:
            self.url = self.url + "/" + self.method + "/"
        print(self.url)
        # append common headers if none
        headers_new = self.headers
        if amend_headers == True:
            if 'Content-Type' not in headers_new:
                headers_new['Content-Type'] = r'application/json'
            if 'User-Agent' not in headers_new:
                headers_new['User-Agent'] = 'Python Requests'
        try:
            # send put request
            response = requests.put(self.url, data=self.payload, headers=self.headers, verify=verify)
            response.raise_for_status()
            # pretty request and response into API log file
            # Note: request print is common instead of checking if it is JSON body. So pass pretty formatted json string as argument to the request for pretty logging.
            self.pretty_print_request(response.request)
            self.pretty_print_response_json(response)
            # This return caller function's name, not this function post.
            caller_func_name = inspect.stack()[1][3]
            if response.status_code != 200:
                log.error('%s failed with response code %s.' % (caller_func_name, response.status_code))
            return response.status_code, response
        except requests.exceptions.HTTPError as err:
            return response.status_code, "An Http Error occurred:" + repr(err)
        except requests.exceptions.ConnectionError as err:
            return response.status_code, "An Error Connecting to the API occurred:" + repr(err)
        except requests.exceptions.Timeout as err:
            return response.status_code, "A Timeout Error occurred:" + repr(err)
        except requests.exceptions.RequestException as err:
            return response.status_code, "An Unknown Error occurred" + repr(err)

    def pretty_print_request(self, request):
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
    def pretty_print_response(self, response):
        log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
            '<-----------Response-----------',
            'Status code:' + str(response.status_code),
            '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
            response.text
        ))

    # argument is response object
    # display body in json format explicitly with expected indent. Actually most of the time it is not very necessary because body is formatted in pretty print way.
    def pretty_print_response_json(self, response):
        """ pretty print response in json format.
            If failing to parse body in json format, print in text.
        """
        try:
            resp_data = response.json()
            resp_body = json.dumps(resp_data, indent=3)
        # if .json() fails, ValueError is raised.
        except ValueError:
            resp_body = response.text
        log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
            '<-----------Response-----------',
            'Status code:' + str(response.status_code),
            '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
            resp_body
        ))