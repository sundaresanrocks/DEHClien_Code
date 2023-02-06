""" Docker event handler service.

This module implements an alarm/alert service for monitoring resources on a given docker host
Events like start, stop, restart, pause, unpause, die.
This handler can be configured to listen to other docker events : Future Development Scope
"""

import docker
import logging
import threading
import requests
import time
import json
from lib.API_Wrapper import DEHAPIWrapper

'''
from alarmlibrary.connection import RabbitMqClientConnection
from alarmlibrary.alarm import Alarm, AlarmSeverity
from alarmlibrary.exceptions import (AuthenticationError, ConnectionClosed,
                                     AlarmManagerException, InvalidAlarm)
'''
from lib.alarmlibrary.connection import RabbitMqClientConnection
from lib.alarmlibrary.alarm import Alarm, AlarmSeverity
from lib.alarmlibrary.exceptions import (AuthenticationError, ConnectionClosed,
                                         AlarmManagerException, InvalidAlarm)
import metric_handler
import mongodb_wrapper
from app import app
from datetime import datetime
import pytz
import re
from metric_handler import MetricHandler
import metric_updater
# To Suppress InsecureRequestWarning: Unverified HTTPS request
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AlarmHandler:
    """Handler for monitoring the status of the docker containers.
    """

    def __init__(self, host, port, user, password, docker_ca_cert,
                 docker_client_cert,
                 docker_client_key,
                 https_url,
                 container_name=None):

        self.DOCKER_CLIENT_TIMEOUT = 3
        self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config['mongo_host'],
                                                     port=app.config['mongo_port'],
                                                     database=app.config['mongo_db'],
                                                     collection=app.config['mongo_collection_events'])
        """Initializes the logger, docker client, and the background thread
        for the monitoring loop.
        """
        self.__logger = logging.getLogger('DEHClientEnabler.alarms')
        self.docker_ca_cert = docker_ca_cert
        self.docker_client_cert = docker_client_cert
        self.docker_client_key = docker_client_key
        self.https_url = https_url
        self.container_name = container_name
        # docker client
        self.tls_config = docker.tls.TLSConfig(ca_cert=self.docker_ca_cert,
                                               client_cert=(self.docker_client_cert,
                                                            self.docker_client_key))

        self.__docker_client = docker.DockerClient(base_url=self.https_url,
                                                   tls=self.tls_config,
                                                   timeout=self.DOCKER_CLIENT_TIMEOUT)

        self.__api_client = docker.APIClient(base_url=self.https_url, version='auto', tls=self.tls_config)
        # alarm client
        self.__alarm_client = RabbitMqClientConnection()
        self.deh_api_wrapper_client = DEHAPIWrapper()
        try:
            self.__logger.info("Connecting to %s:%s@%s:%s", user, password, host, port)
            self.__alarm_client.open(host, port, user, password)
        except AuthenticationError:
            self.__logger.error("Authentication error while connecting to RabbitMQ server. Exiting ...")
            raise SystemExit("Authentication error while connecting to RabbitMQ server.")
        except (ConnectionClosed, AlarmManagerException):
            self.__logger.error("Unexpected error while connecting to RabbitMQ server. Exiting ...")
            raise SystemExit("Unexpected error while connecting to RabbitMQ server.")

        self.metric_handler_client = metric_handler.MetricHandler(self.docker_ca_cert, self.docker_client_cert,
                                                                  self.docker_client_key,
                                                                  self.https_url,
                                                                  self.container_name)

        self.metric_updater_client = metric_updater.MetricsUpdater(self.docker_ca_cert, self.docker_client_cert,
                                                                   self.docker_client_key,
                                                                   self.https_url,
                                                                   self.container_name)


        # thread pool
        self.__thread = threading.Thread(target=self.run, args=())
        self.__thread.daemon = True
        self.__thread.start()


    def convert_posix_to_string(self, posix_timestamp):
        """
        localizing epoch-time with pytz in python
        """
        utc_dt = datetime.utcfromtimestamp(posix_timestamp).replace(tzinfo=pytz.utc)
        # convert it to tz
        tz = pytz.timezone('UTC')
        dt = utc_dt.astimezone(tz)
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z%z')

    def db_check_resource_registration(self, resource_id, check_for="ALL"):
        # Read DB if the resource data is already persisted. If exists update record
        documents = self.mongo_client.read({"_id": resource_id})
        uid = None
        bse_id = None
        if documents:
            for document in documents:
                bse_id = document['BSE_ID']
                uid = document['RRM_ID']
        else:
            self.__logger.info("No Resource/ Container with ID: {} deployed on this DockerHost. ".format(resource_id))
        return {"uid": uid, "bse_id": bse_id}

    def run(self):
        """Infinite loop for monitoring the status of the docker containers.
        It listen to the following container's events: die, stop, start, pause, and unpause.
        """
        # align alarms
        self.__logger.info("Aligning the current status of the alarms")
        since = 0
        until = time.time()
        self.__align_alarms(since, until)

        # start infinite loop
        self.__logger.info("Starting the infinite loop for handling docker events")
        since = until + 1
        while True:
            try:
                for event in self.__docker_client.events(filters={'Type': 'container'},
                                                         since=since,
                                                         decode=True):
                    since = event['time'] + 1
                    print(event)
                    alarm = self.__make_alarm(event)
                    if alarm is not None:
                        self.__logger.info("Sending alarm: %s", alarm.serialize())
                        try:
                            self.__alarm_client.send(alarm)
                        except (InvalidAlarm, ValueError):
                            self.__logger.error("Not well-formed alarm %s. Discarding ...",
                                                alarm.serialize())
                        except ConnectionClosed:
                            self.__logger.error("Connection to RabbitMQ server was closed. Exiting ...")
                            raise SystemExit("Connection to RabbitMQ server was closed.")

            except docker.errors.APIError:
                self.__logger.error('Communication with docker socket failed.')

    def __get_image_sha256(self, name):
        """Gets the image identifier (sha256) for a given docker image."""
        try:
            image = self.__docker_client.images.get(name)
            image_sha256 = image.id
        except docker.errors.ImageNotFound:
            self.__logger.error('Image %s not found.', name)
            image_sha256 = 'Unknown'
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            image_sha256 = 'Unknown'
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            image_sha256 = 'Unknown'
        except KeyError:
            self.__logger.error("Image id doesn't exists")
            image_sha256 = None
        return image_sha256

    def __make_alarm(self, event):
        """Makes an alarm to send to Alarm Manager"""
        self.__logger.debug("Making alarm from event %s", event)
        alarm = None
        if event['Action'] == 'die' \
                or event['Action'] == 'stop' \
                or event['Action'] == 'start' \
                or event['Action'] == 'restart' \
                or event['Action'] == 'pause' \
                or event['Action'] == 'create' \
                or event['Action'] == 'unpause':
            self.__logger.debug("Processing event.")
            resource_name = event['Actor']['Attributes']['name']
            # There a cases were the events doesnt have certain attributes
            if 'image' in event['Actor']['Attributes']:
                image_sha256 = self.__get_image_sha256(event['Actor']['Attributes']['image'])
            else:
                image_sha256 = None
            data = {'namespace': 'ResourceMonitor', 'domain': 'ContainerError', 'eventTimestamp': event['time'],
                    'id': event['Actor']['ID']}
            print("#############################################################")
            print("For event : {}".format(event['Action']))
            print("For Service Name  : {}".format(resource_name))
            print("Corresponding Event: {}".format(event))
            print("#############################################################")

            try:
                data['primarySubject'] = {'event': event['Action'], 'status': event['status'],
                                          'Action': event['Action'], 'type': event['Type'], 'time': event['time'],
                                          'scope': event['scope'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'id': data['id'], 'image': event['Actor']['Attributes']['image']}
            except KeyError as e:
                self.__logger.error("Key Error : {}".format(e))
                data['primarySubject'] = {'event': event['Action'], 'status': None,
                                          'Action': event['Action'], 'type': event['Type'], 'time': event['time'],
                                          'scope': event['scope'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'id': data['id'], 'image': None}
            # Container went dow
            if event['Action'] == 'die' or event['Action'] == 'stop':
                data['description'] = 'container went down'
                data['severity'] = 'Major'
                '''
                data['primarySubject'] = {'event': event['Action'], 'status': event['status'],
                                          'type': event['Type'], 'time': event['time'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'id': data['id'],
                                          'image': event['Actor']['Attributes']['image']}
                '''
            # Container Create
            elif event['Action'] == 'create':
                """ GET deh_id """
                data['description'] = 'container created'
                data['severity'] = 'Clear'

                # Check if the service/ resource is registered to RRM
                uid, bse_id = self.metric_handler_client. \
                    db_check_resource_registration(resource_id=event['Actor']['ID'])

                if app.config['auto_register'] or app.config['auto_register_rrm']:
                    if uid is None or uid == "":
                        # First generate resource registration data/ payload.
                        resource_data = self.metric_handler_client.\
                            deh_enabler_hub_rrm_save_resources_payload_generate(resource_name)
                        rrm_response = self.deh_api_wrapper_client.\
                            deh_rrm_check_resource_registration(resource_name, resource_data)
                        # status_code, response = self.deh_api_wrapper_client.\
                        #    save_deh_resource(resource_data, request_type="POST")
                        if rrm_response.status_code == 200:
                            self.__logger.info("Successfully fetched/ registered resource: {} "
                                               "registration info. from/to DEH RRM, with response:\n {}."
                                               .format(resource_name, rrm_response.text))
                        else:
                            self.__logger.error("Failed to fetch/ register resource: {} "
                                                "from/to DEH RRM,with response:\n {}."
                                                .format(resource_name, rrm_response.text))
                elif not app.config['auto_register_rrm']:
                    self.__logger.info("Skipping the auto registration for DEH RRM as flag auto_register_rrm"
                                       " is set to False")
            # Container went up
            elif event['Action'] == 'start' or event['Action'] == 'restart':
                data['description'] = 'container went up'
                data['severity'] = 'Clear'
                '''
                data['primarySubject'] = {'event': event['Action'], 'status': event['status'],
                                          'type': event['Type'], 'time': event['time'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'id': data['id'],
                                          'image': event['Actor']['Attributes']['image']}
                '''
                if event['Action'] == 'start':
                    # TODO: Handle exceptions in case of failed to write to DBs &
                    #  At the start of an resource, capture the initial metrics & write to DB

                    # Check from internal mongoDB if the resource/ container is registered to RRM & BSE
                    uid, bse_id = self.metric_handler_client. \
                        db_check_resource_registration(resource_id=event['Actor']['ID'])

                    if app.config['auto_register'] or app.config['auto_register_bse']:
                        # Check if the service/ resource is registered to BSE, if not register
                        if bse_id is None or bse_id == "":
                            bse_register = self.deh_api_wrapper_client.\
                                deh_bse_check_resource_registration(resource_name)

                    if not app.config['auto_register'] or not app.config['auto_register_bse']:
                        self.__logger.info("Skipping BSE auto registration as flag auto_register or auto_register_bse "
                                           "is set to False")
                    individual_metric = self.metric_handler_client.get_metrics_by_container({"name": resource_name})
                    metrics_updater_client = self.metric_updater_client.manage_write_metrics_to_db(individual_metric)
                    update_metrics_to_db = metrics_updater_client.manage_write_metrics_to_db(individual_metric)
                    """
                    '''
                    metrics_handler_client = MetricHandler(self.docker_ca_cert, self.docker_client_cert,
                                                                        self.docker_client_key, self.https_url,
                                                                        self.container_name)
                    individual_metric = metrics_handler_client.get_metrics_by_container({"name": resource_name})
                    metrics_updater_client = metrics_updater.MetricsUpdater()
                    update_metrics_to_db = metrics_updater_client.manage_write_metrics_to_db(individual_metric)
                    '''
                    # Stage 1: Check if the service/ resource is registered to BSE, if not register
                    #TODO: May be this will be removed if DEH Client is not responsible for registering to BSE
                    host = app.config['DEH_BSE_Proxy_URL']
                    method = app.config['DEH_BSE_GET_SERVICE']
                    #Note : The service name is case sensitive
                    deh_bse_obj = DEHAPIWrapper(host, method,
                                                payload={"resource_name": event['Actor']['Attributes']['name']})
                    status_code, response = deh_bse_obj.deh_bse_get_running_services()
                    if status_code == 200 and response.json() == {}:
                        self.__logger.info("Service {} not registered to BSE, "
                                           "Now attempt to register to BSE.".format(resource_name))
                        method = app.config['DEH_BSE_Register_Service']
                        deh_bse_obj = DEHAPIWrapper(host, method,
                                                    payload={"resource_name": event['Actor']['Attributes']['name'],
                                                             })
                        status_code, response = deh_bse_obj.deh_bse_post_register_service()
                        if status_code == 200:
                            self.__logger.info("Successfully registered service: {} to BSE.".format(resource_name))
                        else:
                            self.__logger.error("Registration service: {} to BSE failed.".format(resource_name))
                    else:
                        self.__logger.info("Service: {} already registered to BSE.".format(resource_name))

                    # Stage 2: Check if the service/ resource is registered to RRM, if not register
                    self.__logger.info("Checking if the service/ resource is registered to RRM, if not set to register")
                    method = app.config['DEHEnablerHub_Search_Resource']
                    deh_enabler_hub_obj = DEHAPIWrapper()
                    parameters = {"name": resource_name}
                    status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=parameters,
                                                                                                method=method)
                    contents = response.json()["content"]
                    if len(contents) == 0:
                        self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                                           "Now attempt to register.".format(resource_name))
                        '''
                        resource_data = {}
                        try:
                            resource_info = self.__api_client.inspect_container(id)
                            # Truncating the prefix / from the container name
                            resource_name = re.sub("^/", "", resource_info['Name'])
                            resource_data['name'] = resource_name
                            resource_data['status'] = resource_info['State']['Status']
                            resource_data['status'] = 1
                            resource_data["maturityLevel"] = 1
                        except docker.errors.APIError:
                            self.__logger.error("Failed to get data about the container : {} not found".format(id))
                        else:
                        '''
                        resource_data = {'name': resource_name}
                        deh_enabler_hub_obj = DEHAPIWrapper()
                        status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data)
                        if status_code == 200:
                            self.__logger.info("Successfully registered resource: {} "
                                               "to DEH Enabler Hub RRM with response:\n {}."
                                               .format(resource_name, response.text))
                        else:
                            self.__logger.error("Registration resource: {} to DEH Enabler Hub RRM failed."
                                                .format(resource_name))
                    else:
                        self.__logger.info("Service: {} already registered to DEH Enabler Hub RRM."
                                           .format(resource_name))
                    """
            # Processes were paused
            elif event['Action'] == 'pause':
                # data['id'] = event['Actor']['ID']
                data['description'] = 'container processes were paused'
                data['severity'] = 'Major'
                '''
                data['primarySubject'] = {'event': event['Action'], 'status': event['status'],
                                          'type': event['Type'], 'time': event['time'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'id': data['id'],
                                          'image': event['Actor']['Attributes']['image']}
                '''

            # Processes were unpaused
            elif event['Action'] == 'unpause':
                # data['id'] = event['Actor']['ID']
                data['description'] = 'container processes were unpaused'
                data['severity'] = 'Clear'
                '''
                data['primarySubject'] = {'event': event['Action'], 'status': event['status'],
                                          'type': event['Type'], 'time': event['time'],
                                          'timeNano': event['timeNano'],
                                          'container': event['Actor']['Attributes']['name'],
                                          'image': event['Actor']['Attributes']['image']}
                '''

            # additional data
            data['additional-field'] = {'exitCode': (event['Actor']['Attributes']).get('exitCode', 'NA'),
                                        'id': data['id'],
                                        'imageId': image_sha256}

            '''
            alarm = Alarm(data['domain'],
                          data['namespace'],
                          AlarmSeverity[data['severity']],
                          datetime.fromtimestamp(data['eventTimestamp']),
                          data['description'])
            '''
            alarm = Alarm(data['description'],
                          data['namespace'],
                          AlarmSeverity[data['severity']],
                          datetime.fromtimestamp(data['eventTimestamp']))

            # Primary data : Info. related to event
            # alarm.add_primary_subject('eventTimestamp', data['eventTimestamp'])
            alarm.add_primary_subject('eventTimestamp', self.convert_posix_to_string(data['eventTimestamp']))
            alarm.add_primary_subject('description', data['description'])
            alarm.add_primary_subject('namespace', data['namespace'])
            alarm.add_primary_subject('severity', data['severity'])
            alarm.add_primary_subject('event', data['primarySubject']['event'])
            alarm.add_primary_subject('time', data['primarySubject']['time'])
            alarm.add_primary_subject('timeNano', data['primarySubject']['timeNano'])
            alarm.add_primary_subject('status', data['primarySubject']['status'])
            alarm.add_primary_subject('Action', data['primarySubject']['Action'])
            alarm.add_primary_subject('exitCode', data['additional-field']['exitCode'])

            # Additional data : Info. related to Container & Image
            alarm.add_additional_data('container', data['primarySubject']['container']),
            alarm.add_additional_data('image', data['primarySubject']['image'])
            alarm.add_additional_data('type', data['primarySubject']['type'])
            alarm.add_additional_data('id', data['additional-field']['id'])
            alarm.add_additional_data('imageId', data['additional-field']['imageId'])

            # Format alarm data to write to mongodb
            alarm_json = alarm.serialize()
            alarm_json = json.loads(alarm_json)
            formatted_data = {'_id': alarm_json['additionalData']['id'], 'metadata': alarm_json['additionalData']}
            events_list = []
            event_data = alarm_json['primarySubject']
            '''
            event_data =   {'event': alarm_json["additionalData"]["event"],
                            'exitcode': alarm_json["additionalData"]["exitCode"],
                            'severity': alarm_json["severity"],
                            'eventTimestamp': alarm_json["eventTimestamp"],
                            'status': event['status'], 
                            'Action': event['Action'],
                            'type': event['Type'], 
                            'time': event[
                            'scope': event['scope'],
                            'timeNano': event['timeNano']
                            'status': 
                            }
            '''
            events_list.append(event_data)
            formatted_data['events'] = events_list

            # Read before writing to mongo
            document = self.mongo_client.read({'_id': formatted_data['_id']})

            # If resource already existing update the events tag in the mongoDB
            if document:
                update = self.mongo_client.update(formatted_data, '_id', 'events', event_data)
            # If new resource
            else:
                write = self.mongo_client.write(formatted_data)
        else:
            self.__logger.debug("Discarding event.")
        return alarm

    def __align_alarms(self, since, until):
        """Sends the last alarms that happened in the time window (since, until) """
        self.__logger.info("Aligning alarms since %s until %s", since, until)

        # keep the last alarm for each container
        alarms = {}
        try:
            for event in self.__docker_client.events(filters={'Type': 'container'},
                                                     since=since, until=until, decode=True):
                alarm = self.__make_alarm(event)
                if alarm is not None:
                    self.__logger.info("OK")
                    self.__logger.info(alarm.serialize())
                    alarms[event['Actor']['Attributes']['name']] = alarm
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed. Alarms cannot be aligned!')

        # send the last alarms
        for container in alarms:
            alarm = alarms[container]
            self.__logger.info("Sending alarm: %s", alarm.serialize())
            try:
                self.__alarm_client.send(alarm)
            except (InvalidAlarm, ValueError):
                self.__logger.error("Not well-formed alarm %s. Discarding ...", alarm.serialize())
            except ConnectionClosed:
                self.__logger.error("Connection to RabbitMQ server was closed. Exiting ...")
                raise SystemExit("Connection to RabbitMQ server was closed.")


''' Sample Event
{'status': 'create', 'id': 'e42985f2e85c3a371a3cc7b6064071e9910c67c0952de4a3803e50df56a2186c', 'from': 'ubuntu:latest', 
'Type': 'container', 'Action': 'create', 'Actor':   {
                                                'ID': 'e42985f2e85c3a371a3cc7b6064071e9910c67c0952de4a3803e50df56a2186c', 
                                                'Attributes': {'image': 'ubuntu:latest', 'name': 'test_ubunthu10'}
                                                    }, 
'scope': 'local', 'time': 1608754611, 'timeNano': 1608754611914871671}
'''
