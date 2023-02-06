""" Docker container metric service.
This module implements a REST service for getting statistic metrics
from docker containers.
"""
import logging
import os
import re
from collections import Counter
from datetime import timedelta, datetime
import pytz
from functools import wraps
from multiprocessing.pool import ThreadPool
from pprint import pprint, pformat
import json
import docker
import jwt
import requests
from flask import jsonify, request, make_response, abort
from lib.API_Wrapper import DEHAPIWrapper
from app import app
import pymongo
from io import BytesIO
# To Suppress InsecureRequestWarning: Unverified HTTPS request
import urllib3
from werkzeug.datastructures import ImmutableMultiDict
import OpenSSL
import traceback
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import mongodb_wrapper

class MetricHandler:
    """Handler for getting metrics from docker containers.
    """
    MAX_THREAD_POOL_SIZE = 5000
    """(int): maximum size of the thread pool for parallel call of docker client. 
    """
    DOCKER_CLIENT_TIMEOUT = 60  # Changing from the original value of 3
    """(int): timeout in seconds for calling docker client.
    """

    def __init__(self, docker_ca_cert=None,
                 docker_client_cert=None,
                 docker_client_key=None,
                 https_url=None,
                 container_name=None):
        """Initializes the logger and the docker client connection.
        """
        self.__logger = logging.getLogger('DEHClientEnabler.metrics_handler')
        # loglevel = app.config["LOGLEVEL"]
        # logging.basicConfig(level=loglevel)
        self.docker_ca_cert = docker_ca_cert
        self.docker_client_cert = docker_client_cert
        self.docker_client_key = docker_client_key
        self.https_url = https_url
        self.container_name = container_name

        if app.config['secure_connection'].lower().strip() == "true":
            self.__logger.info("DEH Client - "
                               "Attempting to establish communication with Docker Host over secured channel.")
            try:
                tls_certificates_list = [self.docker_ca_cert, self.docker_client_cert, self.docker_client_key]
                for cert in tls_certificates_list:
                    if os.path.isfile(cert):
                        self.tls_config = docker.tls.TLSConfig(ca_cert=self.docker_ca_cert,
                                                               client_cert=(self.docker_client_cert,
                                                                            self.docker_client_key))
                        self.__docker_client = docker.DockerClient(base_url=self.https_url,
                                                                   tls=self.tls_config,
                                                                   timeout=self.DOCKER_CLIENT_TIMEOUT)
                        self.__api_client = docker.APIClient(base_url=self.https_url, version='auto',
                                                             tls=self.tls_config)
                    else:
                        self.__logger.error("TLS certificate file : {} missing. "
                                            "Please check the instruction on how to copy certificate files to "
                                            "DEH Client container before starting the same. ".format(cert))
                        exit()

            except FileNotFoundError as error:
                self.__logger.error("TLS certificate file missing. ERROR{}. "
                                    "Please check the instruction on how to copy certificate files to "
                                    "DEH Client container before starting the same. ".format(error))
                exit()

            except Exception as error:
                self.__logger.error("ERROR while establishing secured communication with Docker Host. ")
                self.__logger.error("Docker Communication Error : {} .".format(error))
                self.__logger.error("Possible causes:")
                self.__logger.error("1) Docker Host: Docker daemon service on Docker Host is "
                                    "not-responding/ down/ not-running. or ")
                self.__logger.error("2) Docker Host: Docker daemon service on Docker Host is not configured properly "
                                    "to accept/ validate Client TLS certificates. ")
                self.__logger.error("3) Docker Host & DEH Client: "
                                    "Missing or Invalid or Expired TLS Server/ Client certificates used. ")
                self.__logger.error("Debugging Steps: ")
                self.__logger.error("1) Docker Host: Ensure Docker Daemon service on Docker Host is up and running. ")
                self.__logger.error("2) Docker Host: Ensure Docker Daemon Service i.e dockerd on Docker Host is "
                                    "exposed as Docker Engine API with --tlsverify. This is done with "
                                    "/lib/systemd/system/docker.service by updating/ setting "
                                    "ExecStart=dockerd --tlsverify --tlscacert == <<CertPath>>/ca.pem "
                                    "--tlscert == <<CertPath>>/server-cert.pem --tlskey == <<CertPath>>/server-key.pem "
                                    "-H=0.0.0.0:<<Port>>>. ")
                self.__logger.error("Please refer DEH Client documentation on how to generate and configure "
                                    "Server/ Client TLS certificates and establish communicate over secured channel "
                                    "between Docker Host & DEH Client. ")
                self.__logger.error("3) DEH Client: "
                                    "Ensure to configure appropriate Docker Host url & TCP post "
                                    "(same port over which Docker service dockerd is exposed as API) in DEH Client's "
                                    ".env file, attribute \"docker_host\" = http://DockerHost:<<Port>>. ")
                exit()

        if app.config['secure_connection'].lower().strip() == "false":
            self.__logger.warning("DEH Client - "
                                  "Attempting to establish open communication with Docker Host i.e. unsecured. ")
            try:
                self.http_url = re.sub("^https://", "http://", self.https_url)
                self.__docker_client = docker.DockerClient(base_url=self.http_url,
                                                           timeout=self.DOCKER_CLIENT_TIMEOUT, version='auto',
                                                           tls=False)
                self.__api_client = docker.APIClient(base_url=self.http_url, version='auto', tls=False)
                self.__logger.info(self.http_url)

            except Exception as error:
                self.__logger.error("ERROR while attempting to communicate with Docker Host. ")
                self.__logger.error("Docker Communication Error : {} .".format(error))
                self.__logger.error("Possible causes: ")
                self.__logger.error("1) Docker Host: Docker daemon service on Docker Host is "
                                    "not-responding/ down/ not-running. or ")
                self.__logger.error("2) Docker Host: Possibly Docker daemon service on Docker Host is configured with "
                                    "--tlsverify flag. Meaning its expecting TLS certificate to accept connection from "
                                    "DEH Client. ")
                self.__logger.error("Error Debug Steps: ")
                self.__logger.error("1) Docker Host: Ensure Docker Daemon service on Docker Host is up and running. ")
                self.__logger.error("2) Docker Host: If you don't want secured communication, "
                                    "disable --tlsverify described in 2nd cause above & enable dockerd as API like "
                                    "by setting ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:<<port>> "
                                    "in /lib/systemd/system/docker.service & restart services. ")
                self.__logger.error("3) DEH Client: "
                                    "Ensure to configure appropriate Docker Host url & TCP post "
                                    "(same port over which Docker service dockerd is exposed as API) in DEH Client's "
                                    ".env file, attribute \"docker_host\" = http://DockerHost:<<Port>>. ")
                exit()

        self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config['mongo_host'],
                                                     port=app.config['mongo_port'],
                                                     database=app.config['mongo_db'],
                                                     collection=app.config['mongo_collection_metrics'])

        self.deh_enabler_hub_obj = DEHAPIWrapper()

        def token_required(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                token = request.args.get('token')  # http://127.0.0.1:5000/route?token=alshfjfjdklsfj89549834ur
                if not token:
                    return jsonify({'message': 'Token is missing!'}), 403
                try:
                    data = jwt.decode(token, app.config['SECRET_KEY'])
                    # data = Pyjwt.decode(token, "demeter")
                except:
                    return jsonify({'message': 'Token is invalid!'}), 403
                return f(*args, **kwargs)

            return decorated

        # Get Test
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/home', methods=['GET'])
        def home_test():
            return 'Hello ! new tests are working as expected'

        # Gets metrics for all containers
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/metrics', methods=['GET'])
        def get_metrics_for_all():
            """
            Get metrics by status of containers:
            e.g. curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/metrics?status=running"
            or
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/metrics?status=all"
            or
            Get metrics by uid ie containers who are instance of resources uid
            e.g. curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/metrics?
            uid=[[uid of resource]]"
            """
            if request.method == 'GET':
                parameters = request.args
                return jsonify(self.get_metrics(parameters))

        # Gets metrics for all containers which are running and associated with uid
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/metrics_for_uid_container', methods=['GET'])
        def get_metrics_for_running_container_with_uid():
            """
            Get metrics by status of containers:
            e.g. curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/metrics_for_uid_container?status=running"
            """
            if request.method == 'GET':
                parameters = request.args
                return jsonify(self.get_metrics_by_status_only_with_uid(parameters))

        # Gets metrics for an individual container
        # @app.route('/DEHClientEnabler/api/v1/metrics/<string:container_name>', methods=['GET'])
        # def get_metrics_by_container_name(container_name):
        #    return jsonify(self.get_metrics_by_container(container_name))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/list_services', methods=['GET'])
        def list_service():
            return jsonify(self.list_services())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/list_processes', methods=['GET'])
        def list_processes_of_container():
            args = request.args
            return jsonify(self.list_processes(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics', methods=['GET'])
        # @token_required
        def get_metrics_by_container_name():
            """
            e.g.
            Get metrics by container name.
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?
            name=[[ContainerName]]"
            Get metrics by container ID
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?
            id=fde9c084db3a"
            """
            if request.method == 'GET':
                args = request.args
                return jsonify(self.get_metrics_by_container(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/running_containers', methods=['GET'])
        # @token_required
        def get_running_containers():
            """
            e.g.
            List of all running containers
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/running_containers"
            """
            return jsonify(self.__get_running_docker_container_names())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter', methods=['GET'])
        def get_containers_by_filter():
            """
            Filter by label :
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?
            label=uid=610411e8c56e160279440661" | json
            Filter by status :
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?
            status=running" | json
            """
            args = request.args
            return jsonify(self.get_containers_by_filter(args))

        # Get host info ie DOCKER DAEMON HOST info
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/host_info', methods=['GET'])
        # @token_required
        def get_docker_info():
            return jsonify(self.__get_docker_info())

        # Get all the container info (running or not)
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_all_resource_info', methods=['GET'])
        # @token_required
        def get_all_container_info():
            return jsonify(self.get_all_container_info())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_container_list', methods=['GET'])
        def get_all_container_list():
            return jsonify(self.get_all_docker_container_names())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs', methods=['GET'])
        def get_container_logs():
            """
            curl -X GET "http://localhost:5003/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs?
            container=0c23da3d692d1fa1b59e1c0f5a7dae874ea600b4af13d391bb16b3c9a1d6f1a0&tail=20&pattern=2021-08-23"
            """
            args = request.args
            return jsonify(self.get_container_logs(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_docker_events', methods=['GET'])
        def get_docker_events():
            args = request.args
            return jsonify(self.get_docker_events(args))

        # Get installation count
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/installation', methods=['GET'])
        # @token_required
        def get_installation_count():
            args = request.args
            return jsonify(self.get_installation_count(args))

        # Pull an docker image
        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/image/pull', methods=['POST'])
        def pull_docker_image():
            # Note :
            # Refer https://docs.docker.com/engine/reference/commandline/login/#credentials-store For credentials store
            """
            Example :
            curl -i -H "Content-Type: application/json" -X
            POST -d '{"image":"demeterengteam/pilot4.2-traslator","tag":"candidate"}'
            http://localhost:5003/api/v1/DEHClientEnabler/ResourceManagement/image/pull
            """
            if not request.json or 'image' not in request.json:
                abort(400)
            payload = request.json
            # return jsonify(self.pull_docker_image(payload))
            return jsonify(self.check_image_exists_locally_download_if_not(payload))

        # Adding labels to locally downloaded docker image
        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/image/set_label', methods=['POST'])
        def label_docker_image():
            """
            610411e8c56e160279440661 --> UID test instance in PROD RRM
            reference : https://forketyfork.medium.com/docker-labels-and-how-to-use-them-614ee1a4c190
            curl -i -H "Content-Type: application/json" -X
            POST -d '{"image":"centos","tag":"latest","labels":{"label1":"test1",
            "uid":"610411e8c56e160279440661"}}'
            http://localhost:5003/api/v1/DEHClientEnabler/ResourceManagement/image/set_label
            """
            payload = request.json
            return jsonify(self.set_label_docker_image(payload))

        # Run a docker container
        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/container/run', methods=['POST'])
        def run_docker_container():
            """
            curl -i -H "Content-Type: application/json" -X
            POST -d '{"image":"centos","tag":"latest","name":"test_centos_instance1"}'
            http://localhost:5003/api/v1/DEHClientEnabler/ResourceManagement/container/run
            """
            payload = request.json
            return jsonify(self.run_docker_container(payload))

        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/create_service', methods=['POST'])
        def create_service():
            # if not request.json or 'image' not in request.json:
            #    abort(400)
            payload = request.json
            return jsonify(self.create_service(payload))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/resource_stats', methods=['GET'])
        def get_resource_stats():
            args = request.args
            return jsonify(self.get_resource_stats(args))

        # # DEH Enabler Hub: RRM API
        # @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/resources/<string:uid>', methods=['GET'])
        # def request_deh_enabler_hub_get_resources():
        #     payload = request.json
        #     return jsonify(self.get_deh_enabler_hub_rrm_saved_resource(payload))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/get_image_info', methods=['GET'])
        def request_get_image_info():
            """ GET Image Info"""
            parameters = request.args
            return jsonify(self.get_image_info(parameters))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/update_deh_resource', methods=['PUT'])
        def request_put_deh_enabler_hub_rrm_save_resources():
            """ Update already registered RRM resource data
            parameters {"uid":<<RRM uid>>,"data":<<To Update ResourceData>>}"""
            payload = request.json
            return jsonify(self.put_deh_enabler_hub_rrm_saved_resource(payload))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/resources/search', methods=['GET'])
        def request_deh_enabler_hub_rrm_resource_search():
            """Search DEH Resources by filters (name, type, description, endpoint, status, version, owner, rating,
            url, accessibility, maturityLevel)
            e.g request:
            curl "http://localhost:5000/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/resources/search?name=Protractor\""""
            parameters = request.args
            return jsonify(self.get_deh_enabler_hub_rrm_resource_search(parameters))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/resources', methods=['GET'])
        def request_deh_enabler_hub_rrm_resource_search_uid():
            """Search DEH Resources by uid"""
            parameters = request.args
            return jsonify(self.get_deh_enabler_hub_rrm_resource_search_uid(parameters))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/save_deh_resource', methods=['POST'])
        def request_deh_enabler_hub_rrm_save_resources():
            """ Sample Request: curl -i -H "Content-Type: application/json" -X POST -d '{"name":"<<Resorce Name>>"}'
            http://localhost:5000/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/save_deh_resource"""
            # parameters = request.args
            payload = request.json
            return jsonify(self.request_deh_enabler_hub_rrm_save_resources(payload))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/end_to_end_flow', methods=['POST'])
        def request_end_to_end_flow_automation():
            payload = request.json
            return jsonify(self.end_to_end_flow_automation(payload))

        # BSE Integration:
        @app.route('/api/v1/DEHClientEnabler/DEHBSE/bse_register_services', methods=['POST'])
        def bse_register_services():
            """
            Parameter : service_name & tag
            """
            payload = request.json
            return jsonify(self.bse_register_services(payload))

        @app.route('/api/v1/DEHClientEnabler/DEHBSE/bse_get_running_services', methods=['GET'])
        def request_bse_get_running_services():
            if request.args:
                parameters = request.args
            else:
                parameters = None
            return jsonify(self.request_bse_get_running_services(parameters))

        @app.route('/request_token', methods=['GET'])
        def request_token():
            auth = request.args
            if auth and auth['password'] == 'secret':
                token = jwt.encode({'user': auth['user'],
                                    'exp': datetime.utcnow() + timedelta(minutes=30)},
                                   app.config['SECRET_KEY'])
                return jsonify({'token': token.decode('UTF-8')})
            return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="valid user only"'})

    def create_service(self, payload):
        """
        Run a container
        :param(str) image: image name to run
        :param(str) container_name: custom container name
        :return(str): If detach is True, a Container object is returned.
        """
        image_name = payload['image']
        run_command = payload['command']
        # attributes = payload['data']
        service_name = payload['name']
        label = payload['labels']
        # container_labels = {"TEST1:TEST1"}
        hostname = payload['host_name']
        mode = {"Replicated": {"Replicas": 1}}
        docker_service = self.__docker_client.services.create(image_name, run_command, name=service_name,
                                                              container_labels=label, mode=mode, hostname=hostname)
        # api_docker_client = self.__api_client.create_service()
        return docker_service.id

    def get_installation_count(self, args):
        resource_info_dict = self.get_all_container_info()
        installation_count = 0
        if 'id' in args:
            ImageID = args['id']
            for resource_id in resource_info_dict:
                if resource_info_dict[resource_id]['ImageID'] == ImageID:
                    installation_count += 1
        if 'name' in args:
            for resource_id in resource_info_dict:
                Image = args['name']
                if resource_info_dict[resource_id]['Image'] == Image:
                    installation_count += 1
        return installation_count

    def get_container_logs(self, arg):
        if 'tail' not in arg:
            tail = 10
        else:
            tail = arg['tail']
        logs = self.__api_client.logs(container=arg['container'],
                                      stream=False,
                                      tail=tail)
        match_lines_list = []
        ''' Convert byte object to string object '''
        for i in logs.decode("utf-8").split("\n"):
            if 'pattern' in arg:
                if re.findall(arg['pattern'], i, re.IGNORECASE):
                    match_lines_list.append(i.strip())
            else:
                match_lines_list.append(i.strip())
        return match_lines_list

    def get_docker_events(self, arg):
        until = None if 'until' not in arg else int(arg['until'])
        if until is not None:
            until = datetime.utcnow()
        since = None if 'since' not in arg else int(arg['since'])
        if since is not None and until is not None:
            since = until - timedelta(hours=int(arg['since']))
        event_data = []
        container = None if 'container' not in arg else arg['container']

        if until is not None:
            if since is not None:
                if container is not None:
                    event_list = self.__docker_client.events(since=since, until=until, filters={'container': container},
                                                             decode=True)
                else:
                    event_list = self.__docker_client.events(since=since, until=until, decode=True)
            else:
                event_list = self.__docker_client.events(until=until, decode=True)
        else:
            event_list = self.__docker_client.events(decode=True)

        for event in event_list:
            event_data.append(event)
        if event_data:
            message = ""
            message += "\n%d events\n" % len(event_data)
            message += pformat(Counter(row['Action'] for row in event_data))
            message += "\n"
            message += pformat(event_data)
            subject = "%d docker events\n" % len(event_data)
        return event_data

    def list_services(self):
        services = self.__api_client.services()
        return services

    def list_processes(self, args):
        process = self.__api_client.top(args['container'])
        return process

    def get_resource_stats(self, payload):
        try:
            stats = self.__api_client.stats(payload['id'], stream=False)
            return stats
        except docker.errors.APIError:
            self.__logger.error("Resource not found or Failed to connect : {}".format(payload['id']))
            response = make_response(jsonify(message="Resource {} not found or Failed to connect".format(payload['id']))
                                     , 501)
            abort(response)

    def pull_docker_image(self, payload):
        try:
            if 'image' not in payload:
                message = "Missing parameter"
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)
            if 'tag' not in payload:
                payload['tag'] = "latest"
            if 'all_tags' not in payload:
                payload['all_tags'] = False
            if 'auth_config' not in payload:
                payload['auth_config'] = {}
            image = self.__docker_client.images.pull(payload['image'], tag=payload['tag'],
                                                     all_tags=payload['all_tags'],
                                                     auth_config=payload['auth_config'])
        # TODO: Discuss on the appropriate status code for exceptions below
        except docker.errors.ImageNotFound:
            message = "Image : {} with tag : {} not found in registry or low disk space on local host, " \
                      "please check the image name & available disk space.".format(payload['image'],
                                                                                   payload['tag'])
            self.__logger.error(message)
            response = make_response(jsonify(message), 401)
            abort(response)
        except docker.errors.APIError as Error:
            message = "Docker Image not found, Check if the Image name & tag are correct or " \
                      "Communication with docker socket failed. Error response : {} ".format(Error)
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        except requests.exceptions.ReadTimeout:
            message = "Communication with docker timed out."
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        return image.id

    def check_image_exists_locally_download_if_not(self, payload):
        # Step1 : Check if the requested image is already downloaded to local host, if not download
        # if tag is None:
        #     tag = "latest"
        # full_image_name = image + ":" + tag
        images_dict = {}
        image = None
        tag = None
        full_image_name = None
        try:
            if 'image' not in payload:
                message = "Missing parameter image"
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)
            else:
                image = payload['image']
            if 'tag' not in payload:
                tag = "latest"
            else:
                tag = payload['tag']
            if 'all_tags' not in payload:
                payload['all_tags'] = False
            if 'auth_config' not in payload:
                payload['auth_config'] = {}
            full_image_name = image + ":" + tag
            image_obj_list = self.__docker_client.images.list(all=False)
            for image_obj in image_obj_list:
                if len(image_obj.tags) != 0:
                    images_dict[image_obj.tags[0]] = image_obj.id
            self.__logger.info("List of Docker Images downloaded on this Docker Host: {} ".format(images_dict))
        except Exception as error:
            message = "Unable to list locally downloaded images with error {}.".format(error)
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        except docker.errors.APIError as error:
            self.__logger.error(error)
            message = "Communication with docker socket failed or " \
                      "Docker Image not found. Error response : {} ".format(error)
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        if full_image_name.lower() in images_dict:
            self.__logger.info("Requested Docker Image : {} is already downloaded to this Docker Host. "
                               "Skipping pull.".format(full_image_name))
            return images_dict[full_image_name.lower()]
        else:
            self.__logger.info("Requested Docker Image : {} is not downloaded already, "
                               "So attempting to pull to this Docker Host. "
                               "Attempting to pull Docker Image."
                               .format(full_image_name))
            try:
                payload_pull_image = {'image': image, 'tag': tag}
                # image_id = self.pull_docker_image(payload_pull_image)
                image = self.__docker_client.images.pull(image, tag=tag,
                                                         all_tags=payload['all_tags'],
                                                         auth_config=payload['auth_config'])
                image_id = image.id
                if image_id:
                    self.__logger.info("Requested Docker Image : {} downloaded successfully to "
                                       "this Docker Host. Image ID : {}".format(full_image_name, image_id))
                    return image_id
            except docker.errors.ImageNotFound:
                message = "Image : {} with tag : {} not found in registry or low disk space on local host, " \
                          "please check the image name & available disk space.".format(payload['image'],
                                                                                       payload['tag'])
                self.__logger.error(message)
                response = make_response(jsonify(message), 401)
                abort(response)
            except docker.errors.APIError as Error:
                message = "Docker Image not found, or Image with specified tag not found. " \
                          "Please check Image & tag names, or " \
                          "Communication with docker socket failed. " \
                          "Error response : {} ".format(Error)
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)
            except requests.exceptions.ReadTimeout:
                message = "Communication with docker timed out."
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)
            except Exception as error:
                message = "Unable to pull image from registry with error {}. " \
                          "Check if the payload used is in correct format. ".format(error)
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)

    def set_label_docker_image(self, payload):
        """ Add Custom labels to already existing image, ie downloaded to Docker Host
        Note : Labels will be not exported to registry"""

        # If docker image tag not included in payload, set tag to default ie latest
        image = None
        tag = None
        if 'tag' in payload:
            tag = payload['tag']
        elif 'tag' not in payload:
            payload['tag'] = "latest"
            tag = payload['tag']
        if 'image' in payload:
            image = payload['image']
        elif 'image' not in payload:
            message = "Parameter \'image\' missing in the payload"
            self.__logger.error(message)
            response = make_response(jsonify(message), 401)
            abort(response)
        # Step1 : Check if the requested image is already downloaded to local host, if not download
        payload_pull_image = {'image': image, 'tag': tag}
        image_id = self.check_image_exists_locally_download_if_not(payload_pull_image)

        # Step2 : Add label to the downloaded docker image
        # TODO: Current implementation. If not valid uid,skips all labels.
        #  Future, If invalid uid skip only uid and proceed adding other other labels.
        if image_id:
            try:
                # If the label name is uid, validate if the given uid is valid ie registered with RRM
                if 'labels' in payload:
                    dockerfile = '''FROM {}:{} 
                    LABEL'''.format(payload['image'], payload['tag'])
                    dockerfile_label = ''''''
                    labels = payload['labels']
                    for label in labels:
                        if label.lower() == "uid":
                            self.__logger.info("Attempting to add uid as label")
                            self.__logger.info("Now validating the given uid ie if registered with RRM")
                            validate_uid = {'uid': labels[label]}
                            status_code, response = self.deh_enabler_hub_obj. \
                                deh_enabler_hub_resource_search_by_uid(validate_uid)
                            if status_code == 200 and response.json()["data"] is not None:
                                self.__logger.info("DEH RRM, resource search result returned success, "
                                                   "Resource matching UID {}."
                                                   "Proceeding to add uid as label.".format(validate_uid['uid']))
                                dockerfile_label = dockerfile_label + ''' {}={} '''.format(label, labels[label])

                            if status_code == 200 and response.json()["data"] is None:
                                message = "DEH RRM, resource search result returned success, " \
                                          "but no resource found/ registered with UID {}. " \
                                          "Skipping label. Check if the UID is registered against " \
                                          "a valid DEH resource".format(validate_uid['uid'])
                                self.__logger.error(message)
                                response = make_response(jsonify(message), 200)
                                abort(response)
                            elif status_code != 200:
                                self.__logger.error(
                                    "Failed to communicate with RRM with status code{}".format(status_code))
                        if label.lower() != "uid":
                            dockerfile_label = dockerfile_label + ''' {}={} '''.format(label, labels[label])
                    # Proceed to updated label only if there is any change in dockerfile_label initial value
                    if dockerfile_label != '''''':
                        dockerfile = dockerfile + dockerfile_label
                        f = BytesIO(dockerfile.encode('utf-8'))
                        target_image_name = "{}:{}".format(payload['image'], payload['tag'])
                        response = [line for line in self.__api_client.build(fileobj=f, rm=True, tag=target_image_name)]
                        self.__logger.info(response)
                    else:
                        message = "No meaningful label detected for docker image {}. Skipping docker build ".format(
                            image)
                        self.__logger.error(message)
                        response = make_response(jsonify(message), 200)
                        abort(response)
            except KeyError as error:
                message = "Missing key in the payload i.e., missing {}".format(error)
                self.__logger.error(message)
                response = make_response(jsonify(message), 401)
                abort(response)
            except docker.errors.APIError as error:
                self.__logger.error(error)
                message = "Communication with docker socket failed."
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)
            except requests.exceptions.ReadTimeout:
                message = "Communication with docker timed out."
                self.__logger.error(message)
                response = make_response(jsonify(message), 501)
                abort(response)

        else:
            message = "Communication with docker timed out."
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        return response

    def run_docker_container(self, payload):
        # TODO: Discuss on the appropriate status code for exceptions below
        # TODO : Implement - re-start resource if stopped, else if already running return container object
        """
        Run a container
        :param(str) image: image name to start as a container.
        :param(str) name: custom container name
        :return(obj): If detach is True, a Container object is returned.
        """
        # Get list of all containers deployed by name
        # containers = self.__get_running_docker_container_names()
        containers = self.get_all_docker_container_names()
        image = None
        tag = None
        command = None
        if "command" in payload:
            command = payload['command']
        elif "command" not in payload:
            command = None
        if "tag" in payload:
            tag = payload['tag']
        elif "tag" not in payload:
            tag = "latest"
        if "image" in payload:
            image = payload['image']
        elif "image" not in payload:
            message = "Parameter \'image\' i.e local docker image name missing in the payload."
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        else:
            image = payload["image"]
        if "name" not in payload:
            message = "Parameter \'name\' i.e docker container name missing in the payload."
            self.__logger.error(message)
            response = make_response(jsonify(message), 501)
            abort(response)
        """Check if Docker Image is already downloaded if not try to download """
        full_image_name = image + ":" + tag
        # Step1 : Check if the requested image is already downloaded to local host, if not download
        payload_pull_image = {'image': image, 'tag': tag}
        image_id = self.check_image_exists_locally_download_if_not(payload_pull_image)

        """Check if container by name already exists """
        if payload['name'].lower() not in containers:
            try:
                container = self.__docker_client.containers.run(full_image_name, command=command,
                                                                name=payload['name'], detach=True)
            except docker.errors.ContainerError:
                self.__logger.error('If detach=false, Container %s exits with a non-zero exit code.',
                                    payload['container'])
                response = make_response(jsonify(message="Image : {} not found.".format(full_image_name)), 501)
                abort(response)
            except docker.errors.ImageNotFound:
                response = make_response(jsonify(message="Image : {} not found.".format(full_image_name)), 501)
                abort(response)
            except docker.errors.APIError as Error:
                self.__logger.error('Error : {} .'.format(Error))
                response = make_response(jsonify(message="Communication with docker socket failed."), 501)
                abort(response)
            except requests.exceptions.ReadTimeout as Error:
                self.__logger.error('Error : {} .'.format(Error))
                response = make_response(jsonify(message="Communication with docker timed out."), 501)
                abort(response)
            return {"container_name": container.name, "container_id": container.id,
                    "Status": "Container started successfully !"}
        else:
            message = "The Container by name {} already exists/ used on this Docker Host, " \
                      "Please use a different Container name. ".format(payload['name'])
            self.__logger.error(message)
            response = make_response(jsonify(message), 200)
            abort(response)

    # DEH Enabler Hub : RRM Integration
    def get_deh_enabler_hub_resource_by_uid(self, parameter):
        # Parameter 'uid' RRM registration ID
        deh_enabler_hub_obj = DEHAPIWrapper(parameter)
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(parameter)
        if status_code == 200:
            self.__logger.info("Successfully fetched DEH resources")
            self.__logger.info(response.text)
        else:
            return response
        return response.text

    def end_to_end_flow_automation(self, parameters):
        """This Client method is to automate entire flow ie
        > Pull images to Docker Host, if not already
        > Create / start a resource.
        > Register created resource against RRM.
        Note : Post integration with BSE, the related steps will be added
        """
        # Request format {"image": <<str : image name, to be pulled from repo.>>}
        status_dict = {"Image_Pull": {"Status": False, "Comments": ""},
                       "Start_Resource": {"Status": False, "Comments": ""},
                       "RRM_Register": {"Status": False, "Comments": ""}}
        pull_image_payload = parameters['image']
        image_id = self.pull_docker_image(pull_image_payload)
        if image_id:
            status_dict['Image_Pull']['Status'] = True
            status_dict['Image_Pull']['Comments'] = "Image Pulled Success id:{}".format(image_id)
            self.__logger.info("Successfully pulled image: {} with image id: {}".format(pull_image_payload['image'],
                                                                                        image_id))
            print("Successfully pulled image: {} with image id: {}".format(pull_image_payload['image'], image_id))
        else:
            status_dict['Image_Pull']['Status'] = False
            status_dict['Image_Pull']['Comments'] = "Failed to pull image"
            print("Failed to pull image {} from Repo".format(pull_image_payload['image']))
            self.__logger.error("Failed to pull image {} from Repo".format(pull_image_payload['image']))
        start_resource_payload = parameters['start_resource']
        # Request format : {"image":<<str : image name downloaded>>, "name":<<str: preferred container name>>,
        # command:<<str: command to run inside container>>}
        resource_name, resource_id = self.run_docker_container(start_resource_payload)
        if resource_name:
            status_dict['Start_Resource']['Status'] = True
            status_dict['Start_Resource']['Comments'] = "Successfully started Resource with Name: {} and id: {}". \
                format(resource_name, resource_id)
            print("Successfully started Resource with Name: {} and id: {}".format(resource_name, resource_id))
            self.__logger.info("Successfully started Resource with Name: {} and id: {}".format(resource_name,
                                                                                               resource_id))
        else:
            status_dict['Start_Resource']['Status'] = False
            status_dict['Start_Resource']['Comments'] = "Failed to start resource"
            self.__logger.error("Failed to start resource")
        # Request format : {"id": <<str : container /resource name >>}
        register_resource_payload = parameters['register_resource']
        register_resource_rrm = self.request_deh_enabler_hub_rrm_save_resources(register_resource_payload)
        if register_resource_rrm:
            # The register_resource_rrm is of format response.text, converting to text to json
            rrm_response_json = json.loads(register_resource_rrm)
            status_dict['RRM_Register']['Status'] = True
            status_dict['RRM_Register']['Comments'] = "Successfully registered resource: {} with rrm uid: {}". \
                format(register_resource_payload['id'], rrm_response_json['uid'])
            self.__logger.info("Successfully registered resource: {} with rrm uid: {}".
                               format(register_resource_payload['id'], rrm_response_json['uid']))
        else:
            status_dict['RRM_Register']['Status'] = False
            status_dict['RRM_Register']['Comments'] = "Failed to register resource with rrm"
            self.__logger.info("Failed to register resource with rrm")
            self.__logger.error("Failed to register resource with rrm")
        print("Resource Register Response : {}".format(register_resource_rrm))
        return status_dict

    def get_deh_enabler_hub_rrm_resource_search(self, parameters):
        url = app.config['DEH_RRM_Proxy_URL']
        method = app.config['DEHEnablerHub_Search_Resource']
        headers = app.config['DEH_RRM_Request_Header']
        status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search(url, parameters, headers,
                                                                                         method=method)
        if status_code == 200:
            self.__logger.info(" Successfully fetched DEH resources")
            self.__logger.info(response.text)
        else:
            return response
        return response.text

    def get_deh_enabler_hub_rrm_resource_search_uid(self, parameters):
        uid = parameters['uid']
        status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid({"uid": uid})
        return response.text

    def put_deh_enabler_hub_rrm_saved_resource(self, parameters):
        uid = parameters['uid']
        to_update_data = parameters
        status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid({"uid": uid})
        if status_code == 200:
            resource_data = response.json()
            for key in resource_data:
                try:
                    resource_data[key] = to_update_data[key]
                except KeyError:
                    continue
            name = resource_data['name']
            self.__logger.info("Resource Name : {} registered with uid : {} in RRM".format(name, uid))
            status_code, response = self.deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="PUT")
            if status_code == 200:
                self.__logger.info("Updated, Resource Name : {} registered with uid : {} in RRM".format(name, uid))
            else:
                self.__logger.error("Update Failed, Resource UID : {} not registered with DEH RRM".format(uid))
        elif status_code == 404:
            error_message = "Reason1: Resource with uid/ deh_id :{} not registered with DEH RRM, " \
                            "Please register the resource via DEH dashboard or RRM APIs to generate metrics. \n" \
                            "Reason2: Possibly, failed to communicate with DEH RRM. Please check.".format(uid)
            self.__logger.error(error_message)
            response = make_response(jsonify(message=error_message), 404)
            abort(response)
        else:
            error_message = "Possibly, failed to communicate with DEH RRM. Please check"
            response = make_response(jsonify(message=error_message), 404)
            abort(response)
        '''
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(method=search_method)
        contents = response.json()["data"]
        if len(contents) >= 1:
            self.__logger.info("Service/ Resource with name {} already registered to DEH Enabler Hub RRM, "
                               "skipping register.".format(parameters['id']))
            print("Service/ Resource with name {} already registered to DEH Enabler Hub RRM, "
                  "skipping register.".format(parameters['id']))
            response = make_response(jsonify(message="Resource with name {} already registered to DEH Enabler Hub RRM"
                                             .format(resource_name)), 501)
            abort(response)
        else:
            self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                               "Now attempt to register.".format(parameters['id']))
            id = parameters['id']
            resource_data = app.config['DEH_Save_Resource_Format']
            try:
                resource_info = self.__api_client.inspect_container(id)
                print("Resource Info:")
                print(resource_info)
                # Truncating the prefix / from the container name
                resource_name = re.sub("^/", "", resource_info['Name'])
                resource_data['name'] = resource_name
                if "Labels" in resource_info['Config']:
                    labels_dict = resource_info['Config']['Labels']
                    print("labels_dict:")
                    print(labels_dict)
                    if 'category' in labels_dict:
                        resource_data['category'] = [labels_dict['category']]
                    if 'description' in labels_dict:
                        resource_data['description'] = labels_dict['description']
                    if 'endpoint' in labels_dict:
                        resource_data['endpoint'] = labels_dict['endpoint']
                    if 'version' in labels_dict:
                        resource_data['version'] = labels_dict['version']
                    if 'tags' in labels_dict:
                        resource_data['tags'] = [labels_dict['tags']]
                    if 'dependencies' in labels_dict:
                        resource_data['dependencies'] = labels_dict['dependencies']
            except docker.errors.APIError:
                print("Failed to get data about the container : {} not found".format(id))
                self.__logger.error("Failed to get data about the container : {} not found".format(id))
                return
            else:
                status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data)
                if status_code == 200:
                    print(" Successfully saved DEH resource")
                    print(response.text)
                else:
                    return response
                return response.text
        '''

    def deh_enabler_hub_rrm_save_resources_payload_generate(self, service_name):
        """
        Method to generate payload for POST rrm save resources.
        Note : Read metadata from container label
        """
        resource_data = app.config['DEH_Save_Resource_Format']
        resource_data['name'] = service_name
        resource_data['Status'] = None
        resource_data['IPAddress'] = None
        resource_data['category'] = None
        resource_data['description'] = None
        resource_data['endpoint'] = None
        resource_data['version'] = None
        resource_data['tags'] = None
        resource_data['dependencies'] = None
        resource_data['uid'] = None
        try:
            resource_info = self.__api_client.inspect_container(service_name)
            service_name = re.sub("^/", "", resource_info['Name'])
            resource_data['name'] = service_name
            if "State" in resource_info:
                if "Status" in resource_info['State']:
                    resource_data['Status'] = resource_info['State']['Status']
            if "NetworkSettings" in resource_info:
                resource_data['IPAddress'] = None
                try:
                    if 'bridge' in resource_info['NetworkSettings']['Networks']:
                        if 'IPAddress' in resource_info['NetworkSettings']['Networks']['bridge']:
                            resource_data['IPAddress'] = resource_info['NetworkSettings']['Networks']['bridge']['IPAddress']
                    elif 'IPAddress' in resource_info['NetworkSettings']:
                        resource_data['IPAddress'] = resource_info['NetworkSettings']['IPAddress']
                except KeyError as ERROR:
                    # self.__logger.warning("Failed to get IPAddress of the container : {}, with ERROR : {}"
                    #                     .format(service_name, ERROR))
                    resource_data['IPAddress'] = None
            if "Labels" in resource_info['Config']:
                labels_dict = resource_info['Config']['Labels']
                if 'category' in labels_dict:
                    resource_data['category'] = [labels_dict['category']]
                if 'description' in labels_dict:
                    resource_data['description'] = labels_dict['description']
                if 'endpoint' in labels_dict:
                    resource_data['endpoint'] = labels_dict['endpoint']
                if 'version' in labels_dict:
                    resource_data['version'] = labels_dict['version']
                if 'tags' in labels_dict:
                    resource_data['tags'] = [labels_dict['tags']]
                if 'dependencies' in labels_dict:
                    resource_data['dependencies'] = labels_dict['dependencies']
                # This attribute will be used to check if UID of the resource is updated manually and set as label
                if 'uid' in labels_dict:
                    resource_data['uid'] = labels_dict['uid']
                elif 'uid' not in labels_dict:
                    resource_data['uid'] = None
        except docker.errors.APIError:
            print("Failed to get data about the container : {} .".format(service_name))
            self.__logger.error("Failed to get data about the container : {} not found".format(service_name))

        return resource_data

    def deh_enabler_bse_register_service_payload_generate(self, service_name):
        """
        Method to generate payload for POST BSE service registration.
        """
        service_data = app.config['bse_register_service_format']
        service_data = {}
        try:
            service_data['name'] = service_name
            service_data['Status'] = None
            service_info = self.__api_client.inspect_container(service_name)
            service_name = re.sub("^/", "", service_info['Name'])
            service_data['service_name'] = service_name
            service_data['name'] = service_name
            service_data['ancestor_name'] = None
            service_data['IPAddress'] = None
            service_data['category'] = None
            service_data['description'] = None
            service_data['endpoint'] = None
            service_data['version'] = None
            service_data['tags'] = None
            service_data['dependencies'] = None
            service_data['uid'] = None
            if "State" in service_data:
                if "Status" in service_info['State']:
                    service_data['Status'] = service_info['State']['Status']
            if "NetworkSettings" in service_info:
                service_data['IPAddress'] = None
                try:
                    if 'bridge' in service_info['NetworkSettings']['Networks']:
                        if 'IPAddress' in service_info['NetworkSettings']['Networks']['bridge']:
                            service_data['IPAddress'] = service_info['NetworkSettings']['Networks']['bridge']['IPAddress']
                    elif 'IPAddress' in service_info['NetworkSettings']:
                        service_data['IPAddress'] = service_info['NetworkSettings']['IPAddress']
                except KeyError as ERROR:
                    # self.__logger.warning("Failed to get IPAddress of the container : {}, with ERROR : {}"
                    #                     .format(service_name, ERROR))
                    service_data['IPAddress'] = None
            if "Image" in service_info['Config']:
                service_data['ancestor_name'] = service_info['Config']['Image']
            if "Labels" in service_info['Config']:
                labels_dict = service_info['Config']['Labels']
                if 'category' in labels_dict:
                    service_data['category'] = [labels_dict['category']]
                if 'description' in labels_dict:
                    service_data['description'] = labels_dict['description']
                if 'endpoint' in labels_dict:
                    service_data['endpoint'] = labels_dict['endpoint']
                if 'version' in labels_dict:
                    service_data['version'] = labels_dict['version']
                if 'tags' in labels_dict:
                    service_data['tags'] = [labels_dict['tags']]
                if 'dependencies' in labels_dict:
                    service_data['dependencies'] = labels_dict['dependencies']
                # This attribute will be used to check if UID of the resource is updated manually and set as label
                if 'uid' in labels_dict:
                    service_data['uid'] = labels_dict['uid']
                if 'uid' not in labels_dict:
                    service_data['uid'] = None
        except docker.errors.APIError:
            print("Failed to get data about the container : {} .".format(service_name))
            self.__logger.error("Failed to get data about the container : {} not found".format(service_name))

        except KeyError as ERROR:
            self.__logger.error("Failed to get IPAddress of the container : {}, with ERROR : {}"
                                .format(service_name, ERROR))

        return service_data

    def request_deh_enabler_hub_rrm_save_resources(self, parameters):
        end_to_end = app.config['end_to_end']
        resource_name = parameters['name']
        self.__logger.info("Checking if the service/ resource is registered to RRM, if not set to register")
        search_method = app.config['DEHEnablerHub_Search_Resource']
        search_parameters = {"name": resource_name}
        status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=search_parameters,
                                                                                         method=search_method)
        contents = response.json()["data"]
        if len(contents) >= 1:
            self.__logger.info("Service/ Resource with name {} already registered to DEH Enabler Hub RRM, "
                               "skipping register.".format(parameters['name']))
            print("Service/ Resource with name {} already registered to DEH Enabler Hub RRM, "
                  "skipping register.".format(parameters['name']))
            response = make_response(jsonify(message="Resource with name {} already registered to DEH Enabler Hub RRM"
                                             .format(resource_name)), 200)
            abort(response)
        else:
            self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                               "Now attempt to register.".format(resource_name))
            try:
                resource_info = self.__api_client.inspect_container(resource_name)
                # Truncating the prefix / from the container name
                resource_name = re.sub("^/", "", resource_info['Name'])
                resource_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(resource_name)
            except docker.errors.APIError:
                error_message = "Failed to get data about the container : {} not found".format(resource_name)
                self.__logger.error(error_message)
                response = make_response(jsonify(message=error_message), 404)
                abort(response)
            else:
                status_code, response = self.deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="POST")
                if status_code == 200:
                    self.__logger.info("Successfully registered/ save resource with DEH RRM")
                else:
                    return response
                return response.text

    """ BSE API Integration """

    def request_bse_get_running_services(self, parameters):
        host = app.config['DEH_BSE_Proxy_URL']
        if parameters is None:
            """ Assuming that attempting to get service details by name"""
            method = app.config['DEH_BSE_GET_SERVICES']
            deh_bse_obj = DEHAPIWrapper(host, method)
        else:
            if 'service_name' in parameters:
                method = app.config['DEH_BSE_GET_SERVICE']
            if 'deh_id' in parameters:
                method = app.config['DEH_BSE_GET_SERVICE_BY_DEH_ID']
            deh_bse_obj = DEHAPIWrapper(host, method, payload=parameters)
        status_code, response = deh_bse_obj.deh_bse_get_running_services()
        if status_code == 200:
            return response.text
        elif status_code == 204:
            error_message = "No Matching resource registered with BSE for {}. ".format(parameters)
            self.__logger.error(error_message)
            response = make_response(jsonify(message=error_message), 404)
            abort(response)
        else:
            return response

    def get_image_info(self, parameters):
        image_info = self.__docker_client.images.get(parameters['name'])
        print("************************************************************")
        print(image_info.history())
        print("************************************************************")
        print(image_info.tags)
        print("************************************************************")
        print("************************************************************")
        print(image_info.id_attribute)
        print("************************************************************")
        print(image_info.attrs)
        '''
        service_info = self.__docker_client.services.list()
        for service in service_info:
            print("************************************************************")
            print(service.name)
            print(service.attrs)
            print(service.tasks())
            print("************************************************************")
        '''
        return

    def bse_register_services(self, parameters):
        """
        Parameter : service_name & tag
        """
        # host = app.config['DEH_BSE_Host']
        host = app.config['DEH_BSE_Proxy_URL']
        method = app.config['DEH_BSE_Register_Service']
        deh_bse_obj = DEHAPIWrapper(host, method, payload=parameters)
        status_code, response = deh_bse_obj.deh_bse_post_register_service()
        if status_code == 200:
            return response.text
        else:
            return response

    def get_container_id_or_name(self, parameter, get="name"):
        try:
            container = self.__docker_client.containers.get(parameter)
            if get == "name":
                return container.name
            if get == "id":
                return container.id
        except docker.errors.NotFound:
            error_message = "Resource/ Container with name : {} not hosted on Docker Host : {} " \
                .format(parameter, app.config['docker_hostname'])
            self.__logger.error(error_message)
            response = make_response(jsonify(message=error_message), 501)
            abort(response)

    # def deh_rrm_bse_registration_flow(self, resource_name=None, check_for=None):
    #     """ Helper method for get_metrics_by_container. Abstract method to determine the flow
    #     Note: resource_name represents container name."""
    #     rrm_response = None
    #     bse_response = None
    #     if check_for.upper() == "ALL" or check_for.upper() == "RRM":
    #         if app.config['auto_register'] or app.config['auto_register_rrm']:
    #             self.__logger.debug("RRM & BSE registration flow, flag set for auto_register : {} "
    #                                 "& auto_register_rrm : {}. "
    #                                 .format(app.config['auto_register'], app.config['auto_register_rrm']))
    #             resource_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(resource_name)
    #             self.__logger.debug("RRM & BSE registration flow, resource data generated for RRM registration "
    #                                 .format(resource_name, resource_data))
    #             self.__logger.info("RRM & BSE registration flow, "
    #                                "Check and Attempt to register DEH Enabler of the container : {} with DEH RRM"
    #                                .format(resource_name))
    #             rrm_response = self.deh_enabler_hub_obj.deh_rrm_check_resource_registration(resource_name,
    #                                                                                         resource_data)
    #         else:
    #             self.__logger.info("RRM & BSE registration flow, "
    #                                "Skipping DEH RRM auto registration as flag auto_register or "
    #                                "auto_register_rrm is set to False")
    #             self.__logger.info("RRM & BSE registration flow, Checking if DEH Enabler of the container : {} "
    #                                "is registered to RRM. ".format(resource_name))
    #             # Check if resource is already registered
    #             url = app.config['DEH_RRM_Proxy_URL']
    #             method = app.config['DEHEnablerHub_Search_Resource']
    #             headers = app.config['DEH_RRM_Request_Header']
    #             parameter = {"name": resource_name}
    #             try:
    #                 status_code, rrm_response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search(url, parameter,
    #                                                                                                      headers,
    #                                                                                                      method=method)
    #             except Exception as error:
    #                 self.__logger.warning("RRM & BSE registration flow, Failed to check if DEH Resource : {} "
    #                                       "is already registered with RRM with exception: {}. ".format(resource_name,
    #                                                                                                    error))
    #
    #     if check_for.upper() == "ALL" or check_for.upper() == "BSE":
    #         if app.config['auto_register'] or app.config['auto_register_bse']:
    #             self.__logger.info("RRM & BSE registration flow, flag set for auto_register : {} "
    #                                "& auto_register_bse : {}. "
    #                                .format(app.config['auto_register'], app.config['auto_register_bse']))
    #             self.__logger.info("RRM & BSE registration flow, Check is Service : {} is registered with BSE "
    #                                "If not register with BSE. ".format(resource_name))
    #             # TODO: Until a streamlined process of associating DEH resource with UID is defined,
    #             #  Temporary solution is to add uid as label
    #             #  Validate if UID associated with container/ service name is valid
    #             # status_code, response = self.deh_enabler_hub_resource_search(payload=parameters,
    #             #                                                              method=method)
    #             # Step 1: GET containers metadata:
    #
    #             service_name = resource_name
    #             service_registration_payload = self.deh_enabler_bse_register_service_payload_generate(service_name)
    #             self.__logger.debug("RRM & BSE registration flow, For Container/ Service : {} , generated "
    #                                 "service_registration_payload : {} . "
    #                                 "This is done to see if an UID is associated with the Container/Service. "
    #                                 .format(service_name, service_registration_payload))
    #             if 'uid' in service_registration_payload:
    #                 uid = service_registration_payload['uid']
    #                 if uid != None:
    #                     self.__logger.info("RRM & BSE registration flow, UID : {} "
    #                                        "associated with Container/ Service: {} ".format(uid, service_name))
    #                     self.__logger.info("RRM & BSE registration flow, Validate if UID : {} is actually registered "
    #                                        "against any DEH Resource in RRM. ".format(uid))
    #                     try:
    #                         status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(
    #                             {"uid": uid})
    #                         self.__logger.info("RRM & BSE registration flow, "
    #                                            "Status Code {} for the check if UID {} is registered with RRM. ".
    #                                            format(status_code, uid))
    #                         if status_code == 200:
    #                             registration_data = response.json()
    #                             self.__logger.info("RRM & BSE registration flow, "
    #                                                "Response {} for the check if UID {} is registered with RRM. ".
    #                                                format(registration_data, uid))
    #                             if registration_data['success'] == True and \
    #                                     registration_data['message'] == 'DEH Resource found':
    #                                 resource_data = registration_data['data']
    #                                 rrm_registered_name = resource_data['name']
    #                                 self.__logger.info("RRM & BSE registration flow, UID : {} found registered with "
    #                                                    "DEH Resource Name : {} registered RRM"
    #                                                    .format(uid, rrm_registered_name))
    #                                 try:
    #                                     # Check if the service/ resource is registered to BSE, if not register
    #                                     self.__logger.info("RRM & BSE registration flow, "
    #                                                        "Check if Service by name:  {} is already registered "
    #                                                        "with BSE and if not attempt auto-register."
    #                                                        .format(service_name))
    #                                     bse_response = self.deh_enabler_hub_obj. \
    #                                         deh_bse_check_resource_registration(service_registration_payload)
    #
    #                                 except Exception as error:
    #                                     bse_response = None
    #                                     self.__logger.warning("RRM & BSE registration flow, "
    #                                                           "Failed to check if service name: {} is already "
    #                                                           "registered with BSE with exception: {}."
    #                                                           .format(service_name, error))
    #
    #                             else:
    #                                 self.__logger.warning("RRM & BSE registration flow, Skipping BSE auto registration."
    #                                                       " The UID {} associated with the Container/ Service name "
    #                                                       "{} is not registered with any valid DEH Resource. "
    #                                                       "Please validate the UID before associating with any "
    #                                                       "service container. ".format(uid, service_name))
    #                         else:
    #                             self.__logger.warning("RRM & BSE registration flow, Skipping BSE auto registration. "
    #                                                   "Failed to communicate with RRM with status code {} "
    #                                                   "to validata if UID {} is registered with RRM. "
    #                                                   "Please ensure the DEH account you are using have "
    #                                                   "access to RRM & BSE, "
    #                                                   "or has required privileges (Provider).".format(status_code, uid))
    #                     except Exception as error:
    #                         bse_response = None
    #                         self.__logger.warning("RRM & BSE registration flow. Failed to fetch DEH Resource "
    #                                               "details for uid : {} from RRM,  with ERROR {} .".format(uid, error))
    #                 else:
    #                     self.__logger.warning("RRM & BSE registration flow. Skipping BSE auto registration, "
    #                                           "as no UID is associated with the container/ service name {} "
    #                                           "Please validate and associate an uid with "
    #                                           "service container.".format(service_name))
    #             else:
    #                 self.__logger.info("RRM & BSE registration flow. Skipping BSE auto registration, "
    #                                    "as no UID is associated with the container/ service name {} ."
    #                                    .format(service_name))
    #
    #         else:
    #             self.__logger.info("RRM & BSE registration flow. "
    #                                "Skipping BSE auto registration as flag auto_register or "
    #                                "auto_register_bse is set to False")
    #             self.__logger.info("RRM & BSE registration flow. "
    #                                "Checking if the Service/ Container with name {} is already registered to BSE."
    #                                .format(resource_name))
    #             # GET BSE info
    #             host = app.config['DEH_BSE_Proxy_URL']
    #             method = app.config['DEH_BSE_GET_SERVICE']
    #             deh_bse_obj = DEHAPIWrapper(host, method, payload={"service_name": resource_name})
    #             status_code, bse_response = deh_bse_obj.deh_bse_get_running_services()
    #     return rrm_response, bse_response

    def deh_rrm_bse_registration_flow(self, resource_name=None, check_for=None):
        """ Helper method for get_metrics_by_container. Abstract method to determine the flow
        Note: resource_name represents container name."""
        rrm_response = None
        bse_response = None
        if check_for.upper() == "ALL" or check_for.upper() == "RRM":
            if app.config['auto_register'] or app.config['auto_register_rrm']:
                self.__logger.debug("RRM & BSE registration flow, flag set for auto_register : {} "
                                    "& auto_register_rrm : {}. "
                                    .format(app.config['auto_register'], app.config['auto_register_rrm']))
                resource_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(resource_name)
                self.__logger.debug("RRM & BSE registration flow, resource data generated for RRM registration "
                                    .format(resource_name, resource_data))
                self.__logger.info("RRM & BSE registration flow, "
                                   "Check and Attempt to register DEH Enabler of the container : {} with DEH RRM"
                                   .format(resource_name))
                rrm_response = self.deh_enabler_hub_obj.deh_rrm_check_resource_registration(resource_name,
                                                                                            resource_data)
            else:
                self.__logger.info("RRM & BSE registration flow, "
                                   "Skipping DEH RRM auto registration as flag auto_register or "
                                   "auto_register_rrm is set to False")
                self.__logger.info("RRM & BSE registration flow, Checking if DEH Enabler of the container : {} "
                                   "is registered to RRM. ".format(resource_name))
                # Check if resource is already registered
                url = app.config['DEH_RRM_Proxy_URL']
                method = app.config['DEHEnablerHub_Search_Resource']
                headers = app.config['DEH_RRM_Request_Header']
                parameter = {"name": resource_name}
                try:
                    status_code, rrm_response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search(url, parameter,
                                                                                                         headers,
                                                                                                         method=method)
                except Exception as error:
                    self.__logger.warning("RRM & BSE registration flow, Failed to check if DEH Resource : {} "
                                          "is already registered with RRM with exception: {}. ".format(resource_name,
                                                                                                       error))

        if check_for.upper() == "ALL" or check_for.upper() == "BSE":
            if app.config['auto_register'] or app.config['auto_register_bse']:
                self.__logger.info("RRM & BSE registration flow, flag set for auto_register : {} "
                                   "& auto_register_bse : {}. "
                                   .format(app.config['auto_register'], app.config['auto_register_bse']))
                self.__logger.info("RRM & BSE registration flow, Check is Service : {} is registered with BSE "
                                   "If not register with BSE. ".format(resource_name))
                # TODO: Until a streamlined process of associating DEH resource with UID is defined,
                #  Temporary solution is to add uid as label
                #  Validate if UID associated with container/ service name is valid
                # status_code, response = self.deh_enabler_hub_resource_search(payload=parameters,
                #                                                              method=method)
                # Step 1: GET containers metadata:

                service_name = resource_name
                service_registration_payload = self.deh_enabler_bse_register_service_payload_generate(service_name)
                self.__logger.debug("RRM & BSE registration flow, For Container/ Service : {} , generated "
                                    "service_registration_payload : {} . "
                                    "This is done to see if an UID is associated with the Container/Service. "
                                    .format(service_name, service_registration_payload))
                if 'uid' in service_registration_payload:
                    uid = service_registration_payload['uid']
                    if uid != None:
                        self.__logger.info("RRM & BSE registration flow, UID : {} "
                                           "associated with Container/ Service: {} ".format(uid, service_name))
                        self.__logger.info("RRM & BSE registration flow, Validate if UID : {} is actually registered "
                                           "against any DEH Resource in RRM. ".format(uid))
                        try:
                            status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(
                                {"uid": uid})
                            self.__logger.info("RRM & BSE registration flow, "
                                               "Status Code {} for the check if UID {} is registered with RRM. ".
                                               format(status_code, uid))
                            if status_code == 200:
                                registration_data = response.json()
                                self.__logger.info("RRM & BSE registration flow, "
                                                   "Response {} for the check if UID {} is registered with RRM. ".
                                                   format(registration_data, uid))
                                if registration_data['success'] == True and \
                                        registration_data['message'] == 'DEH Resource found':
                                    resource_data = registration_data['data']
                                    rrm_registered_name = resource_data['name']
                                    self.__logger.info("RRM & BSE registration flow, UID : {} found registered with "
                                                       "DEH Resource Name : {} registered RRM"
                                                       .format(uid, rrm_registered_name))
                                    try:
                                        # Check if the service/ resource is registered to BSE, if not register
                                        self.__logger.info("RRM & BSE registration flow, "
                                                           "Check if Service by name:  {} is already registered "
                                                           "with BSE and if not attempt auto-register."
                                                           .format(service_name))
                                        bse_response = self.deh_enabler_hub_obj. \
                                            deh_bse_check_resource_registration(service_registration_payload)

                                    except Exception as error:
                                        self.__logger.warning("RRM & BSE registration flow, "
                                                              "Failed to check if service name: {} is already "
                                                              "registered with BSE with exception: {}. BSE Response:{}."
                                                              .format(service_name, error, bse_response))

                                else:
                                    self.__logger.warning("RRM & BSE registration flow, Skipping BSE auto registration."
                                                          " The UID {} associated with the Container/ Service name "
                                                          "{} is not registered with any valid DEH Resource. "
                                                          "Please validate the UID before associating with any "
                                                          "service container. ".format(uid, service_name))
                            else:
                                self.__logger.warning("RRM & BSE registration flow, Skipping BSE auto registration. "
                                                      "Failed to communicate with RRM with status code {} "
                                                      "to validata if UID {} is registered with RRM. "
                                                      "Please ensure the DEH account you are using have "
                                                      "access to RRM & BSE, "
                                                      "or has required privileges (Provider).".format(status_code, uid))
                        except Exception as error:
                            bse_response = None
                            self.__logger.warning("RRM & BSE registration flow. Failed to fetch DEH Resource "
                                                  "details for uid : {} from RRM,  with ERROR {} .".format(uid, error))
                    else:
                        self.__logger.warning("RRM & BSE registration flow. Skipping BSE auto registration, "
                                              "as no UID is associated with the container/ service name {} "
                                              "Please validate and associate an uid with "
                                              "service container.".format(service_name))
                else:
                    self.__logger.info("RRM & BSE registration flow. Skipping BSE auto registration, "
                                       "as no UID is associated with the container/ service name {} ."
                                       .format(service_name))

            else:
                self.__logger.info("RRM & BSE registration flow. "
                                   "Skipping BSE auto registration as flag auto_register or "
                                   "auto_register_bse is set to False")
                self.__logger.info("RRM & BSE registration flow. "
                                   "Checking if the Service/ Container with name {} is already registered to BSE."
                                   .format(resource_name))
                # GET BSE info
                host = app.config['DEH_BSE_Proxy_URL']
                method = app.config['DEH_BSE_GET_SERVICE']
                deh_bse_obj = DEHAPIWrapper(host, method, payload={"service_name": resource_name})
                status_code, bse_response = deh_bse_obj.deh_bse_get_running_services()
        return rrm_response, bse_response

    def db_check_resource_registration(self, resource_id, check_for="ALL"):
        # Read DB if the resource data is already persisted. If exists update record
        documents = self.mongo_client.read({"_id": resource_id})
        uid = None
        bse_id = None
        if documents:
            for document in documents:
                bse_id = document['BSE_ID']
                uid = document['RRM_ID']
        return uid, bse_id

    def get_metrics_by_container(self, args):
        """Gets statistic metrics for a given container/resource.
        Metrics:
            It gets the container status, the percentage of CPU usage,
            and the percentage of memory usage.
        :param(str) name: container name
        or
        :param(id) name: container id
        or
        :param(uid) name: resource registration
        :return(dic): container metrics.
        """
        self.__logger.info("Generating metrics for container : {} .".format(args))
        metrics = {}
        bse_id = None
        rrm_id = None
        # uid ie deh_id for resources already registered with DEH RRM.
        uid = None
        utc_current_datetime = datetime.now(pytz.timezone("UTC"))
        utc_current_datetime_str = utc_current_datetime.strftime("%Y-%m-%d %H:%M:%S %Z%z")
        try:
            if isinstance(args, dict):
                '''
                if 'id' in args:
                    _id = args['id']
                    name = self.get_container_id_or_name(_id, get="name")
                    # container = self.__docker_client.containers.get(id)
                '''
                if 'uid' not in args:
                    if 'id' in args:
                        container_id = args['id']
                        name = self.get_container_id_or_name(container_id, get="name")
                        # container = self.__docker_client.containers.get(id)
                    if 'name' in args:
                        name = args['name']
                    # In case of get metrics by name, check for RRM & BSE registration
                    try:
                        container = self.__docker_client.containers.get(name)
                        container_id = container.id
                    except docker.errors.NotFound:
                        error_message = "Seems container with name : {} is not hosted/ running on Docker Host : {} ." \
                                        "Possibly docker_host value misconfiguration in .env file. Please ensure " \
                                        "correct docker host is used. ".format(name, app.config['docker_hostname'])
                        self.__logger.error(error_message)
                        response = make_response(jsonify(message=error_message), 501)
                        abort(response)
                    # Check from local DB if the resource registration details are already persisted
                    self.__logger.info("Attempting to read cached info of uid & bse_id for container {}, "
                                       "if record exists in internal DB. ".format(name))
                    try:
                        uid, bse_id = self.db_check_resource_registration(container_id)
                    except pymongo.errors.ServerSelectionTimeoutError as error:
                        self.__logger.warning("Get metrics by name, in an attempt to read cached info of uid & bse_id "
                                              "for Container {}, Failed to communicate with DB with error : {}, "
                                              "proceeding further. Please check DB connectivity. ".format(name, error))

                    if app.config['auto_register'] == "Manual" and uid is None:
                        uid = None
                        self.__logger.info("Get metrics by name, auto_registration set to : {}. "
                                           "Checking if the container : {} is associated with an uid. "
                                           .format(app.config['auto_register'], name))
                        resource_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(name)
                        if 'uid' in resource_data:
                            uid = resource_data["uid"]
                            self.__logger.info("Get metrics by name, Container : {} is associated with an uid. "
                                               .format(app.config['auto_register'], name))
                        else:
                            self.__logger.info("Get metrics by name, auto_registration set to : {}, "
                                               "and container : {} is not associated with uid. "
                                               .format(app.config['auto_register'], name))
                            uid = None

                    # If registration info not found in DB, check using RRR & BSE APIs
                    if app.config['auto_register'] != "Manual" and uid is None:
                        self.__logger.info("Get metrics by name, auto_registration set to : {}. "
                                           "No record or info of container: {} found in DB, "
                                           "so communicate with RRM to get UID."
                                           .format(app.config['auto_register'], name))
                        rrm_response, bse_response = self.deh_rrm_bse_registration_flow(resource_name=name,
                                                                                        check_for="RRM")
                        if rrm_response is not None:
                            try:
                                self.__logger.debug("Get metrics by name, "
                                                    "validating if the DEH Enabler/ resource of the container : {} "
                                                    "is registered with RRM. "
                                                    .format(name))
                                self.__logger.debug("RRM resource registration validation, "
                                                    "RRM response : {} and status code : {}."
                                                    .format(rrm_response.json(), rrm_response.status_code))
                                rrm_response_status_code = rrm_response.status_code
                                if rrm_response_status_code == 200:
                                    rrm_response_json = rrm_response.json()
                                    if 'uid' in rrm_response_json:
                                        uid = rrm_response_json['uid']
                                        self.__logger.debug("RRM resource registration validation, "
                                                            "DEH Enabler/ resource of the container : {} "
                                                            "registered with RRM with UID: {}. "
                                                            .format(name, uid))
                                    elif "data" in rrm_response_json:
                                        contents = rrm_response.json()["data"]
                                        if contents is not None:
                                            if len(contents) == 0:
                                                self.__logger.info(
                                                    "RRM resource registration validation,"
                                                    "DEH Enabler/ resource of the container : {} is not registered "
                                                    "with RRM. ".format(name))
                                                uid = None
                                            else:
                                                # TODO: Handle multiple resources with same name in future
                                                for resource in contents:
                                                    uid = resource['uid']
                                                    break
                                else:
                                    self.__logger.error("Possibly failed to communicate with RRM with status code : {} "
                                                        .format(rrm_response.status_code))
                            except error as exc:
                                # There are cases were a given resource registration or get resource registration
                                # to/ from RRM fails, preventing further code execution,
                                # try catch block to make proceedings further.
                                self.__logger.error("RRM resource registration validation, "
                                                    "Failed to get resource registration info of : {} with RRM. "
                                                    "RRM response :{} and status code :{} ."
                                                    .format(name, rrm_response.json(), rrm_response.status_code))
                    '''
                    # GET RRM info
                    method = app.config['DEHEnablerHub_Search_Resource']
                    deh_enabler_hub_obj = DEHAPIWrapper()
                    parameters = {"name": name}
                    status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=parameters,
                                                                                                method=method)
                    contents = response.json()["content"]
                    if status_code == 200:
                        if len(contents) == 0:
                            self.__logger.info("Service {} not registered to DEH Enabler Hub RRM. ".format(name))
                            uid = None
                        else:
                            # TODO: Handle multiple resources with same name in future
                            for resource in contents:
                                uid = resource['uid']
                                break
                    '''
                    if bse_id is None:
                        self.__logger.info("No record of Container: {} ie. bse_id info. found in DB, "
                                           "so communicate with BSE to get bse_id.".format(name))
                        # TODO :  Rewrite the logic for BSE interaction
                        rrm_response, bse_response = self.deh_rrm_bse_registration_flow(resource_name=name,
                                                                                        check_for="BSE")
                        bse_id = None

                        # TODO: Duplicate service names possible in BSE, handled with break to pick first record
                        if bse_response is not None and not isinstance(bse_response, str):
                            try:
                                if bse_response.status_code in (200, 201) and bse_response.json() != {}:
                                    bse_response_json = bse_response.json()
                                    if isinstance(bse_response.json(), list):
                                        #TODO: Chances are, there could be multiple registrations in BSE with same name.
                                        # So taking the ID for the first matching record.
                                        if len(bse_response_json) >= 1:
                                            for i in bse_response_json:
                                                if "id" in i:
                                                    bse_id = i["id"]
                                                if "ID" in i:
                                                    bse_id = i["ID"]
                                                break
                                        else:
                                            bse_id = None
                                    else:
                                        bse_response_json = bse_response.json()
                                        for i in bse_response_json:
                                            if "id" in bse_response_json[i]:
                                                bse_id = bse_response_json[i]["id"]
                                            elif "ID" in bse_response_json[i]:
                                                bse_id = bse_response_json[i]["ID"]
                                            elif "service_id" in bse_response_json[i]:
                                                bse_id = bse_response_json[i]["service_id"]
                                            else:
                                                bse_id = None
                                            break

                                else:
                                    self.__logger.error("Service {} not registered with BSE or "
                                                        "Failed to connect with BSE, response {} & status code {}"
                                                        "Please check BSE APIs.".format(name,
                                                                                        bse_response,
                                                                                        bse_response.status_code))

                            except Exception as Error:
                                bse_id = None
                                self.__logger.error("Exception encountered interfacing with BSE, exception : {}, "
                                                    "and BSE response {}.".format(Error, bse_response_json))

                        else:
                            bse_id = None

                if 'uid' in args:
                    """
                    Flow : In-case of search by DEH RRM uid & self-registration.
                    step1: Verify DEH RRM registration with uid ie deh_id.
                           >> If not found, Show appropriate message no resource registered with RRM by <<uid>>
                    step2: If found, Get resource info from RRM and identify associated resource/container from Host. 
                    Step3: If Resource exists, check if the resource is registered with BSE.
                            >> If resource not found, Show appropriate message.
                    Step4: If not registered, Register with BSE.
                    Step4: Generate resource consumption metrics.
                    """
                    # In case of get by metrics by uid, skip RRM check and do only BSE
                    status_code, response = self.deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(args)
                    if status_code == 200:
                        uid = args['uid']
                        name = response.json()['name']
                        if bse_id is None:
                            rrm_response, bse_response = \
                                self.deh_rrm_bse_registration_flow(resource_name=name, check_for="BSE")
                            # GET BSE info
                            host = app.config['DEH_BSE_Proxy_URL']
                            method = app.config['DEH_BSE_GET_SERVICE']
                            deh_bse_obj = DEHAPIWrapper(host, method, payload={"service_name": name})
                            status_code, response = deh_bse_obj.deh_bse_get_running_services()
                            if status_code in (200, 201) and response.json() != {}:
                                bse_id = response.json()["ID"]
                            else:
                                self.__logger.info("Service {} not registered with BSE".format(name))

                    elif status_code == 404:
                        error_message = "Reason1: Resource with uid/ deh_id :{} not registered with DEH RRM, " \
                                        "Please register the resource with RRM manually to generate metrics." \
                                        " || or || Reason2: Possibly, failed to communicate with DEH RRM. Please check." \
                            .format(args['uid'])
                        error_message = "Reason1: Resource with uid/ deh_id :{} not registered with DEH RRM, " \
                                        "Please register the resource with RRM via " \
                                        "DEH dashboard or RRM APIs to generate metrics. || or ||" \
                                        "Reason2: Possibly, failed to communicate with DEH RRM. Please check." \
                            .format(uid)
                        self.__logger.error(error_message)
                        response = make_response(jsonify(message=error_message), 404)
                        abort(response)
                    else:
                        error_message = "Possibly, failed to communicate with DEH RRM. Please check"
                        response = make_response(jsonify(message=error_message), 404)
                        abort(response)
                if 'filter' in args:
                    # Get Container name with the filter tag
                    # TODO:Now picking 1st container based on filter,
                    #  need to loop metrics for all the containers from list and accept uid as filter.
                    #  use case : In case of distributed systems easy to fetch resources(same names)
                    #             across multiple docker hosts
                    containers = [container.name for container in
                                  self.__docker_client.containers.list(filters={'name': args['name']})]
                    name = containers[0]
            # to handle request like /metrics/<<resource name>>
            elif isinstance(args, str):
                name = args
            # Gather resource information
            container = self.__docker_client.containers.get(name)
            '''
            # In case of get metrics by name, check for RRM & BSE registration
            if 'name' or 'id' in args:
                rrm_response, bse_response = \
                    self.deh_rrm_bse_registration_flow(resource_name=name, check_for="ALL")
            # In case of get by metrics by uid, skip RRM check and do only BSE
            if 'uid' in args:
                rrm_response, bse_response = \
                    self.deh_rrm_bse_registration_flow(resource_name=name, resource_uid=uid, check_for="BSE")
                # GET BSE info
                host = app.config['DEH_BSE_Proxy_URL']
                method = app.config['DEH_BSE_GET_SERVICE']
                deh_bse_obj = DEHAPIWrapper(host, method, payload={"service_name": name})
                status_code, response = deh_bse_obj.deh_bse_get_running_services()
                if status_code in (200, 201) and response.json() != {}:
                    bse_id = response.json()["ID"]
                else:
                    self.__logger.info("Service {} not registered with BSE".format(name))
            '''
            # Start to generate metrics report.
            _id = container.id
            if uid is not None:
                _id = uid
            if uid is None:
                _id = container.name
            metrics[_id] = {}
            metrics[_id]['status'] = container.status
            # Initializing
            metrics[_id]['Volume'] = {}
            metrics[_id]['Volume']['cpu'] = {}
            metrics[_id]['Volume']['mem'] = {}
            metrics[_id]['info'] = {}
            metrics[_id]['ResourceID'] = ''
            metrics[_id]['ServiceID'] = ''
            # TODO : Future implementation - request registration ID from BSE & RRM
            metrics[_id]['BSE_ID'] = bse_id
            metrics[_id]['RRM_ID'] = uid
            """ In case of future additions of data to track, we just have to add the corresponding
            function to track here"""
            if container.status == 'running':
                data = container.stats(stream=False)
                self.__logger.debug('container name/id: %s statistics: %s', container.name, data)
                # cpu usage (percent)
                metrics[_id]['Volume']['cpu'] = self.__calculate_cpu_percent(data)
                # memory usage (percent)
                metrics[_id]['Volume']['mem'] = self.__calculate_mem_percent(data)
            '''
            # GET registration ID from BSE & RRM
            host = app.config['DEH_BSE_Proxy_URL']
            method = app.config['DEH_BSE_GET_SERVICE']
            """ Note : The service name is case sensitive"""
            deh_bse_obj = DEHAPIWrapper(host, method,
                                        payload={"service_name": container.name})
            status_code, response = deh_bse_obj.deh_bse_get_running_services()
            '''
            # get container info
            info = self.__api_client.inspect_container(container.name)
            metrics[_id]['info'] = self.get_container_info(info)
            metrics[_id]['Uptime'] = metrics[_id]['info']['uptime']
            metrics[_id]['HostName'] = metrics[_id]['info']['hostname']
            metrics[_id]['Image'] = metrics[_id]['info']['image']
            metrics[_id]['IP'] = metrics[_id]['info']['ip']
            metrics[_id]['last_updated'] = utc_current_datetime_str
            metrics[_id]['ResourceID'] = container.id
            metrics[_id]['ResourceName'] = container.name
            # metrics[container.name]['ServiceID'] = metrics[container.name]['info']['container_id']
            """ Interface with BSE """
            container_name = container.name
            # container_name = container_name.split(".")[0]
            # bse_dict = self.request_bse_get_running_services({'service_name': container_name})
            # print(bse_dict)
            bse_dict = {}
            if bse_dict != {}:
                bse_id = [*bse_dict]
                metrics[_id]['ServiceID'] = bse_id[0]

            # Write the metrics to DB:
            # write_to_db = self.metric_updater_client.manage_write_metrics_to_db(metrics)

        except docker.errors.NotFound:
            error_message = "Resource/ Container with name : {} not hosted on Docker Host : {} " \
                .format(name, app.config['docker_hostname'])
            self.__logger.error(error_message)
            response = make_response(jsonify(message=error_message), 501)
            abort(response)
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            abort(408)
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            abort(500)
        return metrics

    def date_diff(self, started_at, finished_at, out_format="Minutes", resource_status=None):
        """Note: issuing the slicing on the string formatting to avoid value error will attempting data diff because of
        Z suffixed with the date time string"""
        datetime_format = '%Y-%m-%dT%H:%M:%S.%f'
        diff_str = ""
        """ The below condition probably means container was never started, return NA"""
        if (started_at == ("0001-01-01T00:00:00Z" or "0001-01-01T00:00" or "0001-01-01T00:00:00Z")
                or resource_status.upper() == "CREATED"):
            return "NA"

        if (finished_at == ("0001-01-01T00:00:00Z" or "0001-01-01T00:00" or "0001-01-01T00:00:00Z")
                or resource_status.upper() == "RUNNING"):
            datetime_str = datetime.now().strftime(datetime_format)
            finished_at = datetime_str

        diff = datetime.strptime(finished_at[:-4], datetime_format) - \
               datetime.strptime(started_at[:-4], datetime_format)
        diff_seconds = diff.total_seconds()

        if out_format.upper() == "MINUTES":
            diff = divmod(diff_seconds, 60)
            time_diff = "{} minutes and {} seconds".format(diff[0], diff[1])
        elif out_format.upper() == "SECONDS":
            time_diff = int(diff_seconds)
        elif out_format.upper() == "DAYS":
            diff = diff.days
            time_diff = int(diff)

        return time_diff

    def get_metrics_by_status_only_with_uid(self, parameters):
        """Gets statistic metrics for all running containers.
        Since the calls to the docker client are slow, this method
        uses a pool of threads to getting the metrics in parallel;
        speeding up the response time.
        :return(dic): metrics for all running containers.
        """
        containers = None
        container_list = []
        all_metrics = None
        final_containers_dict_with_uid = []
        if 'status' in parameters:
            if parameters['status'].upper() == "RUNNING":
                containers = self.__get_running_docker_container_names_with_uid()

        # Process containers only for containers associated with uid: (check uid from label):
        if len(containers) > 0:
            self.__logger.info("Get metrics by uid, list of all containers matching status Running & "
                               "are associated with UID: {} ."
                               .format(containers))
            for container in containers:
                final_containers_dict_with_uid.append({"name": container})
            try:
                #with ThreadPool(min(self.MAX_THREAD_POOL_SIZE, len(final_containers_dict_with_uid))) as pool:
                with ThreadPool() as pool:
                    all_metrics = pool.map(self.get_metrics_by_container, final_containers_dict_with_uid)
                    
            except Exception as E:
                self.__logger.warning("Exception Encountered when attempt to GET metrics by status & UID thread,"
                                      "with exception: {}. ".format(E))
                pass

        elif len(containers) == 0:
            message = "Get metrics by uid, no Containers found matching the criteria {}, Please check filter used."\
                .format(parameters)
            self.__logger.warning("Get metrics by uid, no container found running which are associated with an UID. "
                                  "Please start some Docker Container/s associated with uid.")
            response = make_response(jsonify(message=message), 200)
            abort(response)

        return all_metrics

    def get_metrics(self, parameters):
        """Gets statistic metrics for all running containers.
        Since the calls to the docker client are slow, this method
        uses a pool of threads to getting the metrics in parallel;
        speeding up the response time.
        :return(dic): metrics for all running containers.
        """
        containers = None
        container_list = []
        all_metrics = None
        if 'uid' in parameters:
            label_parameter = 'uid={}'.format(parameters['uid'])
            args = ImmutableMultiDict([('label', label_parameter)])
            containers = self.get_containers_by_filter(args)
            self.__logger.info("List of containers matching filter {} are {}".format(args, containers))

        elif 'status' in parameters:
            if parameters['status'].upper() == "RUNNING":
                containers = self.__get_running_docker_container_names()
            if parameters['status'].upper() == "ALL":
                containers = self.get_all_docker_container_names()

            if not (parameters['status'].upper() == "ALL" or parameters['status'].upper() == "RUNNING"):
                error_message = "Invalid parameter used for generating metrics." \
                                "To search by status, Use status=running (For only running Containers metrics)" \
                                "or status=all (For all Containers metrics)."
                self.__logger.error(error_message)
                response = make_response(jsonify(message=error_message), 501)
                abort(response)

            elif parameters['status'].upper() == "ALL" and len(containers) == 0:
                error_message = "No Docker Container/s is/are detected/deployed on this Docker Host. " \
                                "Please check and start some Containers before trying again."
                self.__logger.error(error_message)
                response = make_response(jsonify(message=error_message), 401)
                abort(response)

            elif parameters['status'].upper() == "RUNNING" and len(containers) == 0:
                error_message = "No Docker Container/s is/are running on this Docker Host for monitoring, " \
                                "Please check and start some Containers before trying again."
                self.__logger.warning(error_message)
                # response = make_response(jsonify(message=error_message), 401)
                # abort(response)
                return None

        else:
            error_message = "Invalid query parameter used, please use one of the following options, " \
                            "Option 1: To search by status, Use status=running (For only running Containers metrics) " \
                            "or status=all (For all Containers metrics). " \
                            "Option 2: To search by uid, Use valid uid ie registered with RRM to generate metrics " \
                            "for all containers associated, query parameter as uid=[[uid]]"
            self.__logger.error(error_message)
            response = make_response(jsonify(message=error_message), 500)
            abort(response)

        if len(containers) > 0:
            for container in containers:
                container = {"name": container}
                container_list.append(container)

            try:
                with ThreadPool(min(self.MAX_THREAD_POOL_SIZE, len(container_list))) as pool:
                    all_metrics = pool.map(self.get_metrics_by_container, container_list)
                return all_metrics

            except Exception as E:
                self.__logger.error("Exception Encountered within Get Metrics method, with exception: "
                                    "{}. ".format(E))

        elif len(containers) == 0:
            message = "No Containers found matching the criteria {}, Please check filter used.".format(parameters)
            self.__logger.info(message)
            response = make_response(jsonify(message=message), 200)
            abort(response)

    @staticmethod
    def __calculate_cpu_percent(data):
        """Calculates the percentage of CPU usage.
        :param data: docker statistics coded as a dictionary.
        :return: percentage of cpu usage.
        Equivalent of :
        docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=demeterdev:2376 stats
        CONTAINER ID        NAME                          CPU %   MEM USAGE / LIMIT     MEM %   PIDS
        5f451ad4bcf4        nervous_curran                0.00%   1.473MiB / 5.806GiB   0.02%   1
        2b6465a1d424        docker_test_animalwelfare_1   0.16%   311.4MiB / 5.806GiB   5.24%   31
        """
        cpu_percent = 0.0
        cpu_data = {}
        cpu_count = len(data["cpu_stats"]["cpu_usage"]["percpu_usage"])

        cpu_delta = (float(data['cpu_stats']['cpu_usage']['total_usage']) -
                     float(data['precpu_stats']['cpu_usage']['total_usage']))

        system_delta = (float(data["cpu_stats"]["system_cpu_usage"]) -
                        float(data["precpu_stats"]["system_cpu_usage"]))

        if system_delta > 0.0:
            cpu_percent = cpu_delta / system_delta * 100.0 * cpu_count

        # return cpu_percent
        cpu_data['cpu_percent'] = cpu_percent
        cpu_data['cpu_stats'] = data["cpu_stats"]
        cpu_data['precpu_stats'] = data["precpu_stats"]
        return cpu_data

    @staticmethod
    def __calculate_mem_percent(data):
        """Calculates the percentage of memory usage.
        :param data: docker statistics coded as a dictionary.
        :return: percentage of memory usage.
        Equivalent of :
        docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=demeterdev:2376 stats
        CONTAINER ID        NAME                          CPU %   MEM USAGE / LIMIT     MEM %   PIDS
        5f451ad4bcf4        nervous_curran                0.00%   1.473MiB / 5.806GiB   0.02%   1
        2b6465a1d424        docker_test_animalwelfare_1   0.16%   311.4MiB / 5.806GiB   5.24%   31
        """
        mem_percent = 0.0
        mem_data = {}
        mem_usage = float(data['memory_stats']['usage'])
        mem_limit = float(data['memory_stats']['limit'])
        if mem_limit > 0.0:
            mem_percent = mem_usage / mem_limit * 100
        mem_data['mem_percent'] = mem_percent
        mem_data['memory_stats'] = data["memory_stats"]
        # return mem_percent
        return mem_data

    def get_container_info(self, info):
        """Get other related container info"""
        # TODO:container restart count
        resource_info_dict = self.get_all_container_info()
        data = {}
        status = info['State']['Status']
        hostname = info['Config']['Hostname']
        image = info['Config']['Image']
        state = info['State']
        container_id = info['Id']
        # Get container uptime
        started_at = info['State']['StartedAt']
        finished_at = info['State']['FinishedAt']
        uptime = self.date_diff(started_at, finished_at, out_format="Seconds", resource_status=status)
        # uptime = resource_info_dict[container_id]['Status']
        hostconfig = info['HostConfig']
        data['status'] = status
        data['hostname'] = hostname
        data['image'] = image
        # data['actual_uptime'] = actual_uptime
        data['uptime'] = uptime
        data['container_id'] = container_id
        data['state'] = state
        # Handle cases were IP address exists in a nested dict - info
        # Case 1: ['NetworkSettings']['Networks']['bridge']['IPAddress']
        # Case 2: ['NetworkSettings']['Networks'][<<'NetworkMode'>>]['IPAddress']
        # Case 3: ['NetworkSettings']['IPAddress']
        network_settings = info['NetworkSettings']
        if 'IPAddress' in network_settings:
            if network_settings['IPAddress'] == '' or None:
                networks = network_settings['Networks']
                for key in networks:
                    if 'IPAddress' in networks[key]:
                        data['ip'] = networks[key]['IPAddress']
            else:
                data['ip'] = network_settings['IPAddress']
        else:
            print("Resource IPAddress Doesnt exists")
            data['ip'] = ""
        return data

    def get_container_list(self):
        url = self.https_url + 'containers/json?all=1'
        response = requests.get(url=url, cert=(self.docker_client_cert, self.docker_client_key),
                                verify=self.docker_ca_cert)
        return response.json()

    def get_all_docker_container_names(self):
        """
        List of all the container names running or not on docker host
        Note : The return from the function get_container_list is of format
        [[/<<<container_name1>>],[/<<container_name2>>]], so formatting the return to
        [<<container_name1>>,<<container_name2>>]
        """
        containers_list = []
        containers = self.get_container_list()
        # containers = [container.name for container in self.__docker_client.containers.list()]
        for container in containers:
            container_name = container['Names'][0]
            container_name = container_name.split('/')[1].strip()
            containers_list.append(container_name)
        return containers_list

    def get_containers_by_filter(self, args):
        """
        Available filters:
                - `exited` (int): Only containers with specified exit code
                - `status` (str): One of ``restarting``, ``running``,
                    ``paused``, ``exited``
                - `label` (str): format either ``"key"`` or ``"key=value"``
                - `id` (str): The id of the container.
                - `name` (str): The name of the container.
                - `ancestor` (str): Filter by container ancestor. Format of
                    ``<image-name>[:tag]``, ``<image-id>``, or
                    ``<image@digest>``.
                - `before` (str): Only containers created before a particular
                    container. Give the container name or id.
                - `since` (str): Only containers created after a particular
                    container. Give container name or id.
        """
        available_filters = """ Available filters:
        - `exited` (int): Only containers with specified exit code
        - `status` (str): One of ``restarting``, ``running``,
            ``paused``, ``exited``
        - `label` (str): format either ``"key"`` or ``"key=value"``
        - `id` (str): The id of the container.
        - `name` (str): The name of the container.
        - `ancestor` (str): Filter by container ancestor. Format of
            ``<image-name>[:tag]``, ``<image-id>``, or
            ``<image@digest>``.
        - `before` (str): Only containers created before a particular
            container. Give the container name or id.
        - `since` (str): Only containers created after a particular
            container. Give container name or id. """
        container_list = []
        try:
            self.__logger.info("Payload for filter request : {}.".format(args))
            containers = self.__docker_client.containers.list(filters=args)
            for container in containers:
                container_name = container.name
                container_list.append(container_name)
            if len(container_list) > 0:
                self.__logger.info("List of Resources matching the search filter criteria {} are {}"
                                   .format(args, container_list))
            else:
                self.__logger.info("No Resources matching the search filter criteria {}, list {}"
                                   .format(args, container_list))
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            abort(408)
        except Exception as Error:
            if 'status' in args and args['status'] not in ["restarting", "running", "paused", "exited"]:
                message = "Please check the filter used values of `status` should be one of " \
                          "``restarting``, ``running``, ``paused``, ``exited``. "
                self.__logger.error(message)
                self.__logger.error(traceback.print_exc())
                response = make_response(jsonify(message=message), 501)
                abort(response)
            else:
                message = "Exception encountered : {}. ".format(available_filters)
                self.__logger.error(message)
                self.__logger.error(traceback.print_exc())
                response = make_response(jsonify(message=message), 500)
                abort(response)
        '''
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            abort(500)
        '''
        return container_list

    def get_all_container_info(self):
        containers = self.get_container_list()
        containers_info_dict = {}
        for container in containers:
            temp_dict = {}
            # containers_info['Id'] =  container['Id']
            temp_dict['Names'] = container['Names']
            temp_dict['Image'] = container['Image']
            temp_dict['ImageID'] = container['ImageID']
            temp_dict['Created'] = container['Created']
            temp_dict['State'] = container['State']
            temp_dict['Status'] = container['Status']
            temp_dict['NetworkSettings'] = container['NetworkSettings']
            containers_info_dict[container['Id']] = temp_dict
        return containers_info_dict

    def __get_running_docker_container_names_with_uid(self):
        """Gets a list of container names.
        :return: list of container names.
        """
        containers = []
        containers_with_uid = []
        uid = None
        try:
            containers = [container.name for container in self.__docker_client.containers.list()]
            self.__logger.info('Get metrics by uid, List of running containers : {}. '
                               'Checking if these Containers are associated with an UID. '.format(containers))
            for container in containers:
                service_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(container)
                self.__logger.debug('Get metrics by uid, Metadata for Container : {} inspect : {}. '
                                    .format(container, service_data))
                uid = service_data['uid']
                if uid is not None and service_data['Status'] == "running":
                    containers_with_uid.append(container)
            if len(containers_with_uid) > 0:
                self.__logger.debug('Get metrics by uid, List of Docker Containers which are running & are '
                                    'associated with UID : {}. '.format(containers))
            else:
                self.__logger.debug('Get metrics by uid, No running running containers are associated with UID. '
                                    'Please associate Docker Container/s with valid UID to start generating metrics.')
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            abort(408)
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            abort(500)
        return containers_with_uid

    def __get_running_docker_container_names(self):
        """Gets a list of container names.
        :return: list of container names.
        """
        containers = []
        try:
            containers = [container.name for container in self.__docker_client.containers.list()]
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            abort(408)
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            abort(500)

        return containers

    def __get_docker_info(self):
        """Display system-wide information ie docker server info
        Equivalent of command : docker info command
        :return: The info as a dict
        """
        info = None
        try:
            info = self.__docker_client.info()
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            abort(408)
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            abort(500)
        return info

    def get_container_info_all(self):
        url = self.https_url + 'containers/json?all=1'
        response = requests.get(url=url, cert=(self.docker_client_cert, self.docker_client_key),
                                verify=self.docker_ca_cert)
        return response.json()

    def print_containers_data(self):
        for container in self.get_container_list():
            print('Container [Id: %s, Name: %s, Status: %s]' %
                  (container['Id'], container['Names'][0], container['Status']))

    def get_docker_containers(self):
        """Gets a list of container names.
        :return: list of container names.
        """
        containers = []
        try:
            containers = [container.name for container in self.client.containers.list()]
        except requests.exceptions.ReadTimeout:
            print('Communication with docker timed out.')
            # self.__logger.error('Communication with docker timed out.')
            # abort(408)
        except docker.errors.APIError:
            print('Communication with docker socket failed.')
            # self.__logger.error('Communication with docker socket failed.')
            # abort(500)

        return containers
