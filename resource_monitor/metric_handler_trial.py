""" Docker container metric service.

This module implements a REST service for getting statistic metrics
from docker containers.
"""
import logging
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
# To Suppress InsecureRequestWarning: Unverified HTTPS request
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import mongodb_wrapper


class MetricHandler:
    """Handler for getting metrics from docker containers.
    """
    MAX_THREAD_POOL_SIZE = 25
    """(int): maximum size of the thread pool for parallel call of docker client. 
    """
    DOCKER_CLIENT_TIMEOUT = 3
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
        #self.__logger = logging.getLogger('DEHClientEnabler.alarms')
        self.docker_ca_cert = docker_ca_cert
        self.docker_client_cert = docker_client_cert
        self.docker_client_key = docker_client_key
        self.https_url = https_url
        self.container_name = container_name

        self.tls_config = docker.tls.TLSConfig(ca_cert=self.docker_ca_cert,
                                               client_cert=(self.docker_client_cert,
                                                            self.docker_client_key))

        self.__docker_client = docker.DockerClient(base_url=self.https_url,
                                                   tls=self.tls_config,
                                                   timeout=self.DOCKER_CLIENT_TIMEOUT)

        self.__api_client = docker.APIClient(base_url=self.https_url, version='auto', tls=self.tls_config)

        self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config['mongo_host'],
                                                     port=app.config['mongo_port'],
                                                     database=app.config['mongo_db'],
                                                     collection=app.config['mongo_collection_metrics'])

        @app.route('/')
        def hello():
            return "Hello World!"

        @app.route('/api/v1.0/DEHClientEnabler/ResourceConsumption/metrics', methods=['GET'])
        def get_metrics():
            parameters = request.args
            return jsonify(self.get_metrics(parameters))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/list_all_services', methods=['GET'])
        def list_service():
            return jsonify(self.list_services())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/list_all_processes', methods=['GET'])
        def list_processes_of_container():
            args = request.args
            return jsonify(self.list_processes(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics', methods=['GET'])
        def get_metrics_by_container_name():
            if request.method == 'GET':
                args = request.args
                return jsonify(self.get_metrics_by_container(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/running_containers', methods=['GET'])
        def get_running_containers():
            return jsonify(self.__get_docker_containers())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter', methods=['GET'])
        def get_containers_by_filter():
            args = request.args
            return jsonify(self.get_containers_by_filter(args))

        # Get host info ie DOCKER DAEMON HOST info
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/host_info', methods=['GET'])
        #@token_required
        def get_docker_info():
            return jsonify(self.__get_docker_info())

        # Get all the container info (running or not)
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_all_resource_info', methods=['GET'])
        #@token_required
        def get_all_container_info():
            return jsonify(self.get_all_container_info())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_container_list', methods=['GET'])
        def get_all_container_list():
            return jsonify(self.get_all_container_names())

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs', methods=['GET'])
        def get_container_logs():
            args = request.args
            return jsonify(self.get_container_logs(args))

        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/get_docker_events', methods=['GET'])
        def get_docker_events():
            args = request.args
            return jsonify(self.get_docker_events(args))

        # Get installation count
        @app.route('/api/v1/DEHClientEnabler/ResourceConsumption/installation', methods=['GET'])
        #@token_required
        def get_installation_count():
            args = request.args
            return jsonify(self.get_installation_count(args))

        # Pull an docker image
        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/create', methods=['POST'])
        def pull_docker_image():
            if not request.json or 'image' not in request.json:
                abort(400)
            payload = request.json
            return jsonify(self.pull_docker_image(payload))

        # Run a docker container
        @app.route('/api/v1/DEHClientEnabler/ResourceManagement/run', methods=['POST'])
        def run_docker_container():
            if not request.json or 'image' not in request.json:
                abort(400)
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

        # DEH Enabler Hub: RRM API
        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/resources/<string:uid>', methods=['GET'])
        def request_deh_enabler_hub_get_resources(uid):
            return jsonify(self.get_deh_enabler_hub_resource(uid))

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

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/resources/search', methods=['GET'])
        def request_deh_enabler_hub_search_resources():
            """Search DEH Resources by filters (name, type, description, endpoint, status, version, owner, rating,
            url, accessibility, maturityLevel)
            e.g request:
            curl "http://localhost:5000/api/v1/DEHClientEnabler/DEHEnablerHub/resources/search?name=Protractor\""""
            parameters = request.args
            return jsonify(self.get_deh_enabler_hub_resource_search(parameters))

        @app.route('/api/v1/DEHClientEnabler/DEHEnablerHub/rrm/save_deh_resource', methods=['POST'])
        def request_deh_enabler_hub_rrm_save_resources():
            """ Sample Request: curl -i -H "Content-Type: application/json" -X POST -d '{"id":"dehclient_latest2"}'
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
        logs = self.__api_client.logs(container=arg['container'], stream=False,
                                      tail=None if 'tail' not in arg else arg['tail'])
        match_lines_list = []
        if 'pattern' in arg:
            ''' Convert byte object to string object '''
            for i in logs.decode("utf-8").split("\n"):
                if re.findall(arg['pattern'], i):
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
            pprint(event_data[-1])
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

    def run_docker_container(self, payload):
        # TODO: Discuss on the appropriate status code for exceptions below
        # TODO : Implement - re-start resource if stopped else if already running return container object
        """
        Run a container
        :param(str) image: image name to run
        :param(str) container_name: custom container name
        :return(str): If detach is True, a Container object is returned.
        """
        containers = self.__get_docker_containers()
        if payload['name'].lower() not in containers:
            try:
                container = self.__docker_client.containers.run(payload['image'], command=payload['command'],
                                                                name=payload['name'], detach=True)
            except docker.errors.ContainerError:
                self.__logger.error('If detach=false, Container %s exits with a non-zero exit code.',
                                    payload['container'])
                return
                # abort(404)
            except docker.errors.ImageNotFound:
                self.__logger.error('Image : %s not found.', payload['image'])
                return
                # abort(404)
            except docker.errors.APIError:
                self.__logger.error('Communication with docker socket failed.')
                return
                # abort(500)
            except requests.exceptions.ReadTimeout:
                self.__logger.error('Communication with docker timed out.')
                return
                # abort(408)

            return container.name, container.id
        else:
            print("The resource name already exists :  Please use a different resource name")
            # abort(410)
            return ""

    def get_resource_stats(self, payload):
        try:
            print(payload['id'])
            stats = self.__api_client.stats(payload['id'], stream=False)
            return stats
        except docker.errors.APIError:
            self.__logger.error("Resource not found or Failed to connect : {}".format(payload['id']))
            response = make_response(jsonify(message="Resource {} not found or Failed to connect".format(payload['id']))
                                     , 501)
            abort(response)

    def pull_docker_image(self, payload):
        """
        Pull image locally from the repo
        :parm(str) repository: The repository to pull
        :param(str) image: image to pull with or without the tag
        :return(str or list): The image that has been pulled. If no tag was specified,
                              the method will return a list of Image objects belonging to this repository
        """
        try:
            image = self.__docker_client.images.pull(payload['image'])

        # TODO: Discuss on the appropriate status code for exceptions below
        except docker.errors.ImageNotFound:
            self.__logger.error("Image : {} not found.".format(payload['image']))
            response = make_response(jsonify(message="Image : {} not found.".format(payload['image'])), 501)
            abort(response)
        except docker.errors.APIError:
            self.__logger.error('Communication with docker socket failed.')
            response = make_response(jsonify(message="Communication with docker socket failed."), 501)
            abort(response)
        except requests.exceptions.ReadTimeout:
            self.__logger.error('Communication with docker timed out.')
            response = make_response(jsonify(message="Communication with docker timed out."), 401)
            abort(response)
        return image.id

    # DEH Enabler Hub : RRM Integration
    def get_deh_enabler_hub_resource_by_uid(self, parameter):
        deh_enabler_hub_obj = DEHAPIWrapper(parameter)
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(parameter)
        # response = "Response is null or empty"
        if status_code == 200:
            print("###################################")
            print(" Successfully fetched DEH resources")
            print("###################################")
            print(response.text)
            print("###################################")
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
            print("Failed to start resource")
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
            print("Successfully registered resource: {} with rrm uid: {}".format(register_resource_payload['id'],
                                                                                 rrm_response_json['uid']))
            self.__logger.info("Successfully registered resource: {} with rrm uid: {}".
                               format(register_resource_payload['id'], rrm_response_json['uid']))
        else:
            status_dict['RRM_Register']['Status'] = False
            status_dict['RRM_Register']['Comments'] = "Failed to register resource with rrm"
            print("Failed to register resource with rrm")
            self.__logger.error("Failed to register resource with rrm")
        print("Resource Register Response : {}".format(register_resource_rrm))
        return status_dict

    def get_deh_enabler_hub_resource_search(self, parameters):
        url = app.config['DEH_RRM_Proxy_URL']
        method = app.config['DEHEnablerHub_Search_Resource']
        headers = app.config['DEH_RRM_Request_Header']
        deh_enabler_hub_obj = DEHAPIWrapper()
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(url, parameters, headers,
                                                                                    method=method)
        if status_code == 200:
            print("###################################")
            print(" Successfully fetched DEH resources")
            print("###################################")
            print(response.text)
            print("###################################")
        else:
            return response
        return response.text

    def put_deh_enabler_hub_rrm_saved_resource(self, parameters):
        deh_enabler_hub_obj = DEHAPIWrapper()
        uid = parameters['uid']
        to_update_data = parameters
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid({"uid":uid})
        if status_code == 200:
            resource_data = response.json()
            for key in resource_data:
                try:
                    resource_data[key] = to_update_data[key]
                except KeyError:
                    continue
            name = resource_data['name']
            self.__logger.info("Resource Name : {} registered with uid : {} in RRM".format(name, uid))
            status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="PUT")
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
        contents = response.json()["content"]
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
                print("#####################")
                print(resource_info)
                print("#####################")
                # Truncating the prefix / from the container name
                resource_name = re.sub("^/", "", resource_info['Name'])
                resource_data['name'] = resource_name
                if "Labels" in resource_info['Config']:
                    labels_dict = resource_info['Config']['Labels']
                    print("labels_dict:")
                    print("#####################")
                    print(labels_dict)
                    print("#####################")
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
                    print("###################################")
                    print(" Successfully saved DEH resource")
                    print("###################################")
                    print(response.text)
                    print("###################################")
                else:
                    return response
                return response.text
        '''
    def deh_enabler_hub_rrm_save_resources_payload_generate(self, resource_name):
        """
        Method to generate payload for POST rrm save resources.
        """
        resource_data = app.config['DEH_Save_Resource_Format']
        resource_data['name'] = resource_name
        try:
            resource_info = self.__api_client.inspect_container(resource_name)
            if "Labels" in resource_info['Config']:
                labels_dict = resource_info['Config']['Labels']
                print("labels_dict:")
                print("#####################")
                print(labels_dict)
                print("#####################")
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
            print("Failed to get data about the container : {} .".format(resource_name))
            self.__logger.error("Failed to get data about the container : {} not found".format(resource_name))

        return resource_data

    def request_deh_enabler_hub_rrm_save_resources(self, parameters):
        end_to_end = app.config['end_to_end']
        deh_enabler_hub_obj = DEHAPIWrapper()
        resource_name = parameters['name']
        self.__logger.info("Checking if the service/ resource is registered to RRM, if not set to register")
        search_method = app.config['DEHEnablerHub_Search_Resource']
        search_parameters = {"name": resource_name}
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=search_parameters,
                                                                                    method=search_method)
        contents = response.json()["content"]
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
                               "Now attempt to register.".format(resource_name))
            resource_data = app.config['DEH_Save_Resource_Format']
            try:
                resource_info = self.__api_client.inspect_container(resource_name)
                print("Resource Info:")
                print("#####################")
                print(resource_info)
                print("#####################")
                # Truncating the prefix / from the container name
                resource_name = re.sub("^/", "", resource_info['Name'])
                resource_data['name'] = resource_name
                if "Labels" in resource_info['Config']:
                    labels_dict = resource_info['Config']['Labels']
                    print("labels_dict:")
                    print("#####################")
                    print(labels_dict)
                    print("#####################")
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
                status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="POST")
                if status_code == 200:
                    print("###################################")
                    print(" Successfully saved DEH resource")
                    print("###################################")
                    print(response.text)
                    print("###################################")
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
        #host = app.config['DEH_BSE_Host']
        host = app.config['DEH_BSE_Proxy_URL']
        method = app.config['DEH_BSE_Register_Service']
        deh_bse_obj = DEHAPIWrapper(host, method, payload=parameters)
        status_code, response = deh_bse_obj.deh_bse_post_register_service()
        print(status_code)
        print(response)
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

    def deh_rrm_bse_registration_flow(self, resource_name=None, check_for=None):
        """ Helper method for get_metrics_by_container. Abstract method to determine the flow"""
        rrm_response = None
        bse_response = None
        deh_enabler_hub_obj = DEHAPIWrapper()
        if check_for.upper() == "ALL" or check_for.upper() == "RRM":
            if app.config['auto_register'] or app.config['auto_register_rrm']:
                resource_data = self.deh_enabler_hub_rrm_save_resources_payload_generate(resource_name)
                self.__logger.info("Check and Attempt to register Resource : {} in DEH RRM".format(resource_name))
                rrm_response = deh_enabler_hub_obj.deh_rrm_check_resource_registration(resource_name, resource_data)
            else:
                self.__logger.info("Skipping DEH RRM auto registration as flag auto_register or "
                                   "auto_register_rrm is set to False")
                self.__logger.info("Checking if the resource/ container with name {} is registered to RRM"
                                   .format(resource_name))
                # Check if resource is already registered
                url = app.config['DEH_RRM_Proxy_URL']
                method = app.config['DEHEnablerHub_Search_Resource']
                headers = app.config['DEH_RRM_Request_Header']
                parameter = {"name": resource_name}
                deh_enabler_hub_obj = DEHAPIWrapper()
                status_code, rrm_response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(url, parameter,
                                                                                                headers, method=method)

        if check_for.upper() == "ALL" or check_for.upper() == "BSE":
            if app.config['auto_register'] or app.config['auto_register_bse']:
                self.__logger.info("Check and Attempt to register Resource : {} in BSE".format(resource_name))
                bse_response = deh_enabler_hub_obj.deh_bse_check_resource_registration(resource_name)
            else:
                self.__logger.info("Skipping BSE auto registration as flag auto_register or "
                                   "auto_register_bse is set to False")
                self.__logger.info("Checking if the resource/ container with name {} is registered to BSE"
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
        else:
            self.__logger.info("No Resource/ Container with ID: {} deployed on this DockerHost. ".format(resource_id))
        return uid, bse_id

    def get_deh_id_and_bse_id(self, resource_name, check_for="ALL"):
        uid = None    # uid or rrm_id is DEH RRM Registration ID.
        bse_id = None  # BSE registration ID.
        rrm_response, bse_response = self.deh_rrm_bse_registration_flow(resource_name=resource_name,
                                                                        check_for=check_for)
        if rrm_response is not None:
            if rrm_response.status_code == 200:
                rrm_response_json = rrm_response.json()
                if 'uid' in rrm_response_json:
                    uid = rrm_response_json['uid']
                elif "content" in rrm_response_json:
                    contents = rrm_response.json()["content"]
                    if len(contents) == 0:
                        self.__logger.info("Service {} not registered to DEH Enabler Hub RRM. ".format(resource_name))
                        uid = None
                    else:
                        # TODO: Handle multiple resources with same name in future
                        for resource in contents:
                            uid = resource['uid']
                            break
            else:
                self.__logger.error("Possibly failed to communicate with RRM with status code : {} "
                                    .format(rrm_response.status_code))
        if bse_response is not None:
            if bse_response.status_code in (200, 201) and bse_response.json() != {}:
                bse_id = bse_response.json()["ID"]
            else:
                self.__logger.error("Service {} not registered with BSE or Failed to connect with BSE, "
                                    "Please check BSE APIs".format(resource_name))

        return {"uid": uid, "bse_id": bse_id}

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
        metrics = {}
        deh_enabler_hub_obj = DEHAPIWrapper()
        bse_id = None
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
                print("Query Parameters ::::: {}".format(args))
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
                        # Check if the Resource / Container registration record exists in mongodb
                        rrm_id, bse_id = self.db_check_resource_registration(resource_id=container.id)
                    except docker.errors.NotFound:
                        error_message = "Resource/ Container with name : {} not hosted on Docker Host : {} " \
                            .format(name, app.config['docker_hostname'])
                        self.__logger.error(error_message)
                        response = make_response(jsonify(message=error_message), 501)
                        abort(response)

                    '''
                    if rrm_id is None and bse_id is None:
                        rrm_response, bse_response = self.deh_rrm_bse_registration_flow(resource_name=name, check_for="ALL")
                        if rrm_response is not None:
                            if rrm_response.status_code == 200:
                                rrm_response_json = rrm_response.json()
                                if 'uid' in rrm_response_json:
                                    uid = rrm_response_json['uid']
                                elif "content" in rrm_response_json:
                                    contents = rrm_response.json()["content"]
                                    if len(contents) == 0:
                                        self.__logger.info("Service {} not registered to DEH Enabler Hub RRM. ".format(name))
                                        uid = None
                                    else:
                                        # TODO: Handle multiple resources with same name in future
                                        for resource in contents:
                                            uid = resource['uid']
                                            break
                            else:
                                self.__logger.error("Possibly failed to communicate with RRM with status code : {} "
                                                    .format(rrm_response.status_code))
                        if bse_response is not None:
                            if bse_response.status_code in (200, 201) and bse_response.json() != {}:
                                bse_id = bse_response.json()["ID"]
                            else:
                                self.__logger.error("Service {} not registered with BSE or Failed to connect with BSE, "
                                                    "Please check BSE APIs".format(name))
                    '''
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
                    status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search_by_uid(args)
                    if status_code == 200:
                        uid = args['uid']
                        name = response.json()['name']
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
                                        " || or || Reason2: Possibly, failed to communicate with DEH RRM. Please check."\
                            .format(args['uid'])
                        error_message = "Reason1: Resource with uid/ deh_id :{} not registered with DEH RRM, " \
                                        "Please register the resource with RRM via " \
                                        "DEH dashboard or RRM APIs to generate metrics. || or ||" \
                                        "Reason2: Possibly, failed to communicate with DEH RRM. Please check."\
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
            print(info)
            metrics[_id]['info'] = self.get_container_info(info)
            metrics[_id]['Uptime'] = metrics[_id]['info']['uptime']
            metrics[_id]['HostName'] = metrics[_id]['info']['hostname']
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
            self.__logger.debug('container name: %s metrics: %s', container.name, metrics)
        except docker.errors.NotFound:
            error_message = "Resource/ Container with name : {} not hosted on Docker Host : {} "\
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

    def get_metrics(self, parameters):
        """Gets statistic metrics for all running containers.

        Since the calls to the docker client are slow, this method
        uses a pool of threads to getting the metrics in parallel;
        speeding up the response time.

        :return(dic): metrics for all running containers.
        """
        if parameters['status'].upper() == "RUNNING":
            containers = self.__get_docker_containers()
        if parameters['status'].upper() == "ALL":
            containers = self.get_all_container_names()
        with ThreadPool(min(self.MAX_THREAD_POOL_SIZE, len(containers))) as pool:
            all_metrics = pool.map(self.get_metrics_by_container, containers)

        return all_metrics

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

    def get_all_container_names(self):
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
        container_list = []
        try:
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

    def __get_docker_containers(self):
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
