import os
import json
from collections import namedtuple

import pytz

import lib.API as API
from app import app
import calendar, time
from datetime import datetime, timezone, timedelta
from time import mktime
from dateutil import tz

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
    #datetime_str = "2021-04-02T12:32:34.467Z"
    to_zone = tz.gettz(time_zone)
    datetime_obj = datetime_obj.astimezone(to_zone)
    return datetime_obj


def request_acs_token(url, payload, headers, method=None):
    """ Method to Get Authentication Token"""
    subject_token = None
    if method:
        url = url + "/" + method + "/"
    client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
    status_code, response = client.post(verify=False)
    # Status code 201 --> Created
    if status_code in (200, 201):
        subject_token = response.headers['X-Subject-Token']
    else:
        print("Failed to Get Authentication Token with response code {}".format(status_code))
    return status_code, response


def cached_token(jsonfile):
    def has_valid_token(data):
        return 'token' in data

    def get_token_info_from_file(get="token"):
        with open(jsonfile) as f:
            data = json.load(f)
            #if has_valid_token(data):
            return data

    def save_token_to_file(token, generated_date, expiry_date, status_code, response):
        with open(jsonfile, 'w') as f:
            json.dump({'token': token, 'generated_date': generated_date, 'expiry_date': expiry_date,
                       'status_code': status_code, 'response': response.json()}, f)

    def decorator(fn):
        def wrapped(*args, **kwargs):
            status_code, response = None, None
            if os.path.exists(jsonfile):
                token_info = get_token_info_from_file()
                token = token_info.get('token')
                status_code = token_info.get('status_code')
                response = token_info.get('response')
                expiry_date = token_info.get('expiry_date')
                date_format = '%Y-%m-%dT%H:%M:%S.%f'
                expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
                utc_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
                                                                                          time_zone="UTC")
                print("Before delte utc_expiry_date_datetime_obj    :           {}".format(utc_expiry_date_datetime_obj))
                utc_expiry_date_datetime_obj = utc_expiry_date_datetime_obj.replace(second=0) - \
                                                    timedelta(minutes=57)
                local_datetime_obj = datetime.utcnow()
                # local_datetime_obj = datetime.fromtimestamp(utc_expiry_date_datetime_obj, cet)
                local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
                utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)

                print("utc_expiry_date_datetime_obj                 :           {}".format(utc_expiry_date_datetime_obj))
                print("utc_now_datetime_obj                         :           {}".format(utc_now_datetime_obj))
                token_expired = (utc_expiry_date_datetime_obj.replace(tzinfo=None) <=
                                 utc_now_datetime_obj.replace(tzinfo=None))
                if not token_expired:
                    print("ACS Token Still Valid / Not-Expired.")
                    # return f'{token} (cached!!)'
                    return status_code, response
                else:
                    print("ACS Token Expired, attempting to generate new Token.")
            status_code, response = fn(*args, **kwargs)
            token = response.headers['X-Subject-Token']
            token_info = response.json()['token']
            local_datetime_obj = datetime.now()
            local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
            generated_date = local_datetime_str
            expiry_date = token_info['expires_at']
            save_token_to_file(token, generated_date, expiry_date, status_code, response)
            return status_code, response
        return wrapped
    return decorator


@cached_token('token-cache.json')
def get_token():
    import time
    asc_token_url = app.config['ACS_Token_Request_Url']
    asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
    headers = {"Content-Type": "application/json"}
    status_code, response = request_acs_token(asc_token_url, asc_token_payload, headers)
    if status_code in (200, 201):
        print(response.json())
        auth_token = response.headers['X-Subject-Token']
        generated_date = response.headers['date']
        expiry_date = response.json()['token']['expires_at']
    else:
        pass
    return status_code, response

status_code, response = get_token()
print(response)


# def get_acs_token():
#     asc_token_url = app.config['ACS_Token_Request_Url']
#     asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
#     headers = {"Content-Type": "application/json"}
#     status_code, response = request_acs_token(asc_token_url, asc_token_payload, headers)
#     if status_code in (200, 201):
#         print(response.json())
#         auth_token = response.headers['X-Subject-Token']
#         generated_date = response.headers['date']
#         expiry_date = response.json()['token']['expires_at']
#         print(expiry_date)
#     else:
#         pass
#     return status_code, response
#
# def validate_token():
#     respon
#     status_code, response = get_acs_token()
#     response_json = response.json()
#     token = response_json['token']
#     expiry_date = token['expires_at']
#     print(token)
#     print(expiry_date)
#     date_format = '%Y-%m-%dT%H:%M:%S.%f'
#     expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
#     cet_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
#                                                                               time_zone="CET")
#     local_datetime_obj = datetime.now()
#     local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
#     utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
#     print("local_datetime_str: {}".format(local_datetime_str))
#     print("cet_expiry_date_datetime_obj: {}".format(cet_expiry_date_datetime_obj.replace(tzinfo=None)))
#     print("utc_now_datetime_obj {}".format(utc_now_datetime_obj.replace(tzinfo=None)))
#     token_expired = (cet_expiry_date_datetime_obj.replace(tzinfo=None) <=
#                      utc_now_datetime_obj.replace(tzinfo=None))
#     if not token_expired:
#         print("ACS Token Still Valid / Not-Expired.")
#         return f'{token} (cached!!)'
#     else:
#         print("ACS Token Expired, attempting to generate new Token.")
#
# print(validate_token())
