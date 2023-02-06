import pytz
import logging
import os
from app import app
from datetime import datetime
import mongodb_wrapper
from runtime import runtime
import metric_handler
import threading
from timeloop import Timeloop
from datetime import timedelta
from lib.API_Wrapper import DEHAPIWrapper
from multiprocessing.pool import ThreadPool
import re
import pymongo
import traceback
import sys

tl = Timeloop()
container_name = None
logger = logging.getLogger("./MetricsUpdater.log")
# LOGLEVEL = app.config["LOGLEVEL"]
# logging.basicConfig(level=LOGLEVEL)

if app.config['secure_connection'].lower().strip() == "true":
    # print("DEH Client - Attempting to establish communication with Docker Host over secured channel.")
    logger.info("DEH Client - Attempting to establish communication with Docker Host over secured channel.")
    CERT_BASE = app.config["tls_cert_path"]
    docker_ca_cert = CERT_BASE + "/ca.pem"
    docker_client_cert = CERT_BASE + "/cert.pem"
    docker_client_key = CERT_BASE + "/key.pem"
    paths = [docker_ca_cert, docker_client_cert, docker_client_key]
    https_url = app.config["docker_host"]
    for path in paths:
        if os.path.exists(path):
            pass
        else:
            logger.info("DEH Client's metrics updater module - In an attempt to establish secured communication, "
                        "found missing cert. file {}. Ensure all necessary cert., "
                        "files are copied starting DEH Client.".format(path))

    try:
        measure_usage_client = metric_handler.MetricHandler(docker_ca_cert,
                                                            docker_client_cert,
                                                            docker_client_key, https_url, container_name)
    except Exception as Error:
        logger.info("DEH Client's metrics updater module - In an attempt to establish secured communication, "
                    "failed to create metric handler client with ERROR {}. ".format(Error))

elif app.config['secure_connection'].lower().strip() == "false":
    # print("Warning DEH Client - Attempting to establish open communication with Docker Host i.e. unsecured. ")
    logger.info("Warning DEH Client - Attempting to establish open communication with Docker Host i.e. unsecured. ")
    docker_ca_cert = None
    docker_client_cert = None
    docker_client_key = None
    https_url = app.config["docker_host"]
    http_url = re.sub("^https://", "http://", https_url)
    try:
        measure_usage_client = metric_handler.MetricHandler(docker_ca_cert,
                                                            docker_client_cert,
                                                            docker_client_key, http_url, container_name)

    except Exception as Error:
        logger.info("DEH Client's metrics updater module - In an attempt to establish unsecured communication, "
                    "failed to create metric handler client with ERROR {}. ".format(Error))


class MetricsUpdater:
    __logger = logging.getLogger("DEHClientEnabler.metric_updater")
    # loglevel = app.config["LOGLEVEL"]
    # logging.basicConfig(level=loglevel)
    MAX_THREAD_POOL_SIZE = 500000
    last_metrics_posted = datetime.now()
    def __init__(self):
        """Initializes the logger and the docker client connection.
        """
        # self.CERT_BASE = app.config["tls_cert_path"]
        # self.docker_ca_cert = self.CERT_BASE + "/ca.pem"
        # self.docker_client_cert = self.CERT_BASE + "/cert.pem"
        # self.docker_client_key = self.CERT_BASE + "/key.pem"
        # self.https_url = app.config["docker_host"]
        # self.container_name = None
        # self.DOCKER_CLIENT_TIMEOUT = 3
        # self.keep_measuring = True

        self.__logger = logging.getLogger("./MetricsUpdater.log")
        # self.loglevel = app.config["LOGLEVEL"]
        # logging.basicConfig(level=self.loglevel)
        try:
            self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config["mongo_host"],
                                                         port=app.config["mongo_port"],
                                                         database=app.config["mongo_db"],
                                                         collection=app.config["mongo_collection_metrics"])
            if self.mongo_client:
                self.__logger.info("Successfully established connection with internal mongodb")

        except Exception as Error:
            self.__logger.error("Failed to establish communication with the mongoDB with ERROR: {},"
                                "Please check DB connection string in .env & docker-compose file, "
                                "if started as Docker Container. Else check in app.py if run from code directly. " 
                                "".format(Error))
        # Internal config
        self.metrics_capture_time_interval = runtime.config["unit_of_measure"]
        self.metrics_sorting_by = runtime.config["sort_by"]
        self.metrics_no_of_records = runtime.config["no_of_records_per_timestamp"]

        # self.measure_usage_client = metric_handler.MetricHandler(self.docker_ca_cert, self.docker_client_cert,
        #                                                          self.docker_client_key,
        #                                                          self.https_url,
        #                                                          self.container_name)

        # thread pool

    def thread_start(self):
        self.__thread = threading.Thread(target=self.run, args=())
        self.__thread.daemon = True
        self.__thread.start()
        self.__thread.join()

    def manage_write_metrics_to_db(self, individual_metric):
        """
        Format the metrics generated by metrics_handler to the desired DataModel recommended by RRM & publish the data
        Implemented : Updates the DB
        Future : POST to RRM Consumer API
        """
        utc_current_datetime = datetime.now(pytz.timezone("UTC"))
        # utc_current_datetime_str = utc_current_datetime.strftime("%Y-%m-%d %H:%M:%S %Z%z")
        utc_current_datetime_str = utc_current_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        resource_id = None
        try:
            for i in individual_metric:
                resource_id = individual_metric[i]["info"]["container_id"]
                MetricsUpdater.__logger.info("Attempting to write metrics to local DB for container id : {}"
                                             .format(resource_id))
                MetricsUpdater.__logger.debug("Metrics data for container id : {} generated is : {}"
                                              .format(resource_id, individual_metric))
                current_cpu_percent = individual_metric[i]["Volume"]["cpu"]["cpu_percent"]
                current_mem_percent = individual_metric[i]["Volume"]["mem"]["mem_percent"]
                uptime = individual_metric[i]["Uptime"]
                hostname = individual_metric[i]["HostName"]
                ip = individual_metric[i]["IP"]
                bse_id = individual_metric[i]["BSE_ID"]
                uid = individual_metric[i]["RRM_ID"]
                image = individual_metric[i]["Image"]
                updated_cpu_present = {"time_stamp": utc_current_datetime_str,
                                       "cpu_percent": current_cpu_percent}
                updated_mem_present = {"time_stamp": utc_current_datetime_str,
                                       "mem_percent": current_mem_percent}
                # Read DB if the resource data is already persisted. If exists update record
                MetricsUpdater.__logger.info("Checking if record for container id : {} ,is already persisted to DB. "
                                             "If so update existing record, else insert a new record. "
                                             .format(resource_id))
                documents = self.mongo_client.read({"_id": resource_id})
                if documents:
                    formatted_data = {}
                    MetricsUpdater.__logger.info("Record for container id : {} ,is already persisted to DB. "
                                                 "So updating existing record in DB with current metrics data. "
                                                 .format(resource_id))
                    for document in documents:
                        utc_lastupdated_datetime = datetime.now(pytz.timezone("UTC"))
                        utc_lastupdated_datetime_str = utc_current_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
                        cpu_percent = self.metrics_sorting_by["cpu"]
                        mem_percent = self.metrics_sorting_by["memory"]
                        cpu_update = self.mongo_client.update_array(resource_id, "cpu_percent", updated_cpu_present,
                                                                    cpu_percent,
                                                                    retain_no_of_records=self.metrics_no_of_records)
                        mem_update = self.mongo_client.update_array(resource_id, "mem_percent", updated_mem_present,
                                                                    mem_percent,
                                                                    retain_no_of_records=self.metrics_no_of_records)
                        if cpu_update and mem_update:
                            MetricsUpdater.__logger.info("Metrics data updated for for container id : {} "
                                                         "updated successfully to local DB.".format(resource_id))
                        else:
                            MetricsUpdater.__logger.warning("Failed to update Metrics data for container id : {}, "
                                                            " possibly cpu & mem attributes missing from "
                                                            "metrics generated."
                                                            .format(resource_id))

                        # If rrm_id & bse_id generated after record persisted in mongodb, update the same.
                        mongo_bse_id = document["BSE_ID"]
                        mongo_uid = document["RRM_ID"]
                        if mongo_uid is None:
                            uid = individual_metric[i]["RRM_ID"]
                        if mongo_bse_id is None:
                            bse_id = individual_metric[i]["BSE_ID"]

                        updated_metadata = {}
                        try:
                            updated_metadata = {"uptime": uptime,
                                                "lastupdated": utc_lastupdated_datetime_str,
                                                "RRM_ID": uid,
                                                "BSE_ID": bse_id
                                                }
                            MetricsUpdater.__logger.info("Record for container id : {} already persisted to DB. "
                                                         "Attempting to updated metadata: {}. "
                                                         .format(resource_id, updated_metadata))
                            output = self.mongo_client.update_one(resource_id, updated_metadata)

                            if 'Status' in output:
                                if output['Status'] == 'Successfully Updated':
                                    MetricsUpdater.__logger.info("Record for container id : {} "
                                                                 "already persisted to DB. "
                                                                 "Successfully updated metadata: {}."
                                                                 .format(resource_id, updated_metadata))
                                elif output['Status'] == "Nothing was updated":
                                    MetricsUpdater.__logger.warning("Seems record for container id : {} "
                                                                    "not persisted to DB already. "
                                                                    "Skipping write/ update. "
                                                                    .format(resource_id))
                                else:
                                    MetricsUpdater.__logger.warning("Seems record for container id : {} "
                                                                    "not persisted to DB already. "
                                                                    "Skipping write/ update. "
                                                                    .format(resource_id))
                            else:
                                MetricsUpdater.__logger.warning("Seems record for container id : {} "
                                                                "not persisted to DB already. "
                                                                "Skipping write/ update. "
                                                                .format(resource_id))
                        except Exception as error:
                            MetricsUpdater.__logger.warning("Seems record for container id : {} "
                                                            "not persisted to DB already or "
                                                            "failed to update existing record. "
                                                            "Skipping write/ update with error: {}. "
                                                            .format(resource_id, error))

                # If new resource create a new record/ document
                else:
                    """
                    # GET BSE registration info
                    # TODO handle multiple BSE registrations with same name
                    #  & attempt to update IDs only if previous iterations failed to get info
                    host = app.config["DEH_BSE_Proxy_URL"]
                    method = app.config["DEH_BSE_GET_SERVICE"]
                    # Note : The service name is case sensitive
                    deh_bse_obj = DEHAPIWrapper(host, method,
                                                payload={"service_name": resource_name})
                    status_code, response = deh_bse_obj.deh_bse_get_running_services()
                    if status_code == 200 and response.json() != {}:
                        for bse_response_dict in response.json():
                            bse_id = response.json()[bse_response_dict]["ID"]
                            # Exit in case of multiple registration with same name
                            break
                    else:
                        bse_id = None
                    # GET RRM registration info
                    method = app.config["DEHEnablerHub_Search_Resource"]
                    deh_enabler_hub_obj = DEHAPIWrapper()
                    parameters = {"name": resource_name}
                    status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=parameters,
                                                                                                method=method)
                    if status_code == 200:
                        contents = response.json()["content"]
                        if len(contents) > 0:
                            for content in contents:
                                rrm_id = content["uid"]
                    """
                    # Writing to DB
                    MetricsUpdater.__logger.info("No record for container id : {} in DB. "
                                                 "So attempting to insert new record with metrics data. "
                                                 .format(resource_id))
                    formatted_data = {"_id": resource_id,
                                      "uptime": uptime,
                                      "hostname": hostname,
                                      "ip": ip,
                                      "image": image,
                                      "BSE_ID": bse_id,
                                      "RRM_ID": uid,
                                      "first_inserted": utc_current_datetime_str,
                                      "lastupdated": utc_current_datetime_str,
                                      "cpu_percent": [updated_cpu_present],
                                      "mem_percent": [updated_mem_present]}


                    # TODO: Retain Historic Data in DB
                    if runtime.config['db_keep_non_uid_records'] == "False" or \
                            runtime.config['db_keep_non_uid_records'] == False:
                        if formatted_data['RRM_ID'] is not None:
                            write = self.mongo_client.write(formatted_data)
                            if write:
                                MetricsUpdater.__logger.info("Metrics data for container id : {} "
                                                             "inserted successfully to local DB.".format(resource_id))
                                MetricsUpdater.__logger.debug("Metrics data for container id : {} "
                                                              "inserted .".format(formatted_data))
                            else:
                                MetricsUpdater.__logger.warning("Failed to write Metrics data for container id : {} "
                                                                "to local DB.".format(resource_id))
                                MetricsUpdater.__logger.debug("Metrics data for container id : {} "
                                                              "which was attempted to insert was : {} ."
                                                              .format(resource_id, formatted_data))
                        else:
                            MetricsUpdater.__logger.warning("Skip writing metrics data to DB since the "
                                                            "container id : {} of DEH Resource : {} , "
                                                            "is not associated with uid. "
                                                            "Please associate an valid UID to track metrics. "
                                                            .format(formatted_data['_id'],
                                                                    formatted_data['image']))
                    elif runtime.config['db_keep_non_uid_records'] == "True" or \
                            runtime.config['db_keep_non_uid_records'] == True:
                        write = self.mongo_client.write(formatted_data)

                        if write:
                            MetricsUpdater.__logger.info("Metrics data for container id : {} "
                                                         "inserted successfully to local DB.".format(resource_id))
                        else:
                            MetricsUpdater.__logger.error("Failed to write metrics data to DB for the "
                                                          "container id : {} & data attempted to write : {} ."
                                                          .format(formatted_data['_id'], formatted_data))

        except KeyError as error:
            MetricsUpdater.__logger.warning("Exception encountered, while monitoring container id {} possible causes:"
                                            "Cause 1: Container under monitoring stopped while metrics generation "
                                            "was in progress. or . "
                                            "Cause 2: Metrics not generated properly ie certain fields not captured. "
                                            "Please check and start/ restart containers".format(resource_id))
            MetricsUpdater.__logger.warning("Exception encountered : KeyError & Possibly missing keyword. "
                                            "details : {}. ".format(error))

        except Exception as error:
            MetricsUpdater.__logger.warning("Exception encounter while monitoring container {}. ".format(resource_id))
            MetricsUpdater.__logger.warning("Exception details : {}. ".format(error))

    @tl.job(interval=timedelta(seconds=runtime.config['unit_of_measure']))
    def measure_usage(resource_status="Running"):
        max_usage = 0
        metrics = []
        try:
            time_interval = runtime.config['unit_of_measure']
            MetricsUpdater.__logger.info("Attempting to generate metrics periodically i.e. at an interval of : {} "
                                         "seconds, metrics data will be captured for all containers with status : {} "
                                         "and are associated with a valid UID. "
                                         .format(time_interval, resource_status))
            metrics = measure_usage_client.get_metrics_by_status_only_with_uid({"status": resource_status})
            if metrics:
                for individual_metric in metrics:
                    try:
                        MetricsUpdater.__logger.info("Metrics data generated i.e. found containers matching status {} "
                                                     ", proceeding to write to DB. ".format(resource_status))
                        # This loop is for accessing the values of dict individual_metric
                        utc_current_datetime = datetime.now(pytz.timezone("UTC"))
                        utc_current_datetime_str = utc_current_datetime.strftime("%Y-%m-%d %H:%M:%S %Z%z")
                        metrics_updater = MetricsUpdater()
                        metrics_updater.manage_write_metrics_to_db(individual_metric)
                        # except KeyError as error:
                        #     MetricsUpdater.__logger.error(
                        #         "Exception encountered while writing data to local DB for docker container : "
                        #         "{} ".format(individual_metric))
                        #     MetricsUpdater.__logger.error("Exception encountered : KeyError & Possibly missing keyword. "
                        #                                   "details : {}. ".format(error))
                        #
                        # except Exception as error:
                        #     MetricsUpdater.__logger.error(
                        #         "Exception encountered while writing metrics data to local DB for docker container : "
                        #         "{}. ".format(individual_metric))
                        #     MetricsUpdater.__logger.error("Exception details : {}. ".format(error))
                    except KeyError as error:
                        MetricsUpdater.__logger.warning("Exception encountered while writing metrics data to local db, "
                                                        "KeyError & Possibly missing keyword. details : {}. "
                                                        .format(error))
                        continue
                    except AttributeError as error:
                        MetricsUpdater.__logger.warning("Exception encountered while writing metrics data to local db, "
                                                        "details : {}. ".format(error))
                        continue
                    except Exception as error:
                        MetricsUpdater.__logger.warning("Exception encountered while writing metrics data to local db, "
                                                        "details : {}. ".format(error))
                        continue
            else:
                MetricsUpdater.__logger.warning("No Docker Container/s is/are running on the configured Docker Host "
                                                "for monitoring. "
                                                "To generate and start tracking metrics, "
                                                "Please start some Container instance of DEH resources, with "
                                                "valid RRM registration(UID) associated with the same. ")

        except Exception as error:
            # MetricsUpdater.__logger.warning("Exception encountered while capturing metrics / writing to db."
            #                                 .format(error))
            if len(metrics) == 0:
                MetricsUpdater.__logger.warning("No Docker Container/s is/are running on the configured Docker Host "
                                                "for monitoring. "
                                                "To generate and start tracking metrics, "
                                                "Please start some Container instance of DEH resources, with "
                                                "valid RRM registration(UID) associated with the same. ")
            else:
                MetricsUpdater.__logger.warning("Exception encountered while capturing metrics / writing to db."
                                                .format(error))

    @tl.job(interval=timedelta(seconds=runtime.config['timestamp']))
    def post_metrics_rrm_thread(resource_status="Running"):
        ## Read data from metrics db
        post_metrics = None
        mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config["mongo_host"],
                                                port=app.config["mongo_port"],
                                                database=app.config["mongo_db"],
                                                collection=app.config["mongo_collection_metrics"])
        documents = mongo_client.find_projection({},
                                                 {"cpu_percent":
                                                      {"$slice": runtime.config["no_of_records_per_timestamp"]},
                                                  "mem_percent":
                                                      {"$slice": runtime.config["no_of_records_per_timestamp"]}}
                                                 )
        records = []
        for document in documents:
            records.append([document])
        deh_enabler_hub_obj = DEHAPIWrapper()

        if len(records) >= 1:
            MetricsUpdater.__logger.info("Post metrics to RRM, Found metrics records in local db to be posted to RRM, "
                                         "Now attempt to POST. ")
            try:
                # with ThreadPool() as pool:
                #     post_metrics = pool.map(deh_enabler_hub_obj.initiate_post_deh_metrics_request, records)
                #     MetricsUpdater.last_metrics_posted = datetime.now()
                #     MetricsUpdater.__logger.info("Post metrics to RRM, Last successful metrics post to RRM : {}. "
                #                                  .format(MetricsUpdater.last_metrics_posted))
                #     return post_metrics
                for record in records:
                    MetricsUpdater.__logger.debug("Post metrics to RRM, attempting to post metrics for record: {}."
                                                  .format(record))
                    post_metrics = deh_enabler_hub_obj.initiate_post_deh_metrics_request(record)
                return post_metrics
            except Exception as E:
                MetricsUpdater.__logger.warning("Post metrics to RRM, "
                                                "Exception encountered While Initiating Post Metrics Thread, with "
                                                "exception: {}. ".format(E))
                MetricsUpdater.__logger.warning("Post metrics to RRM, "
                                                "Exception encountered While Initiating Post Metrics Thread, with "
                                                "trace: {}. ".format(traceback.format_exc()))
                MetricsUpdater.__logger.warning("Post metrics to RRM, "
                                                "Exception encountered While Initiating Post Metrics Thread, with "
                                                "trace: {}. ".format(sys.exc_info()[2]))
                return None

        else:
            MetricsUpdater.__logger.warning("Post metrics to RRM, No metrics found in local db to be posted to RRM. "
                                            "Please check, "
                                            "1) If any DEH containers are running on the configured "
                                            "Docker Host."
                                            "2) If any Containers are running, "
                                            "ensure the same is associated with valid UID. "
                                            "Please refer installation instructions document on how to do so. "
                                            "3) Ensure local mongodb containers is up and running. ")
            pass

    # @tl.job(interval=timedelta(seconds=runtime.config['retry_timestamp']))
    # def retry_post_metrics_to_rrm(resource_status="Running"):
    #     last_successful_metrics_post = MetricsUpdater.last_metrics_posted
    #     current_time_stamp = datetime.now()
    #     time_difference = (current_time_stamp - last_successful_metrics_post).total_seconds()
    #     if time_difference >= runtime.config['retry_timestamp']:
    #         MetricsUpdater.__logger.info("Retry post metrics to RRM, "
    #                                      "Found metrics records in local db to be posted to RRM, "
    #                                      "Now attempt to retry POST. ")
    #         mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config["mongo_host"],
    #                                                 port=app.config["mongo_port"],
    #                                                 database=app.config["mongo_db"],
    #                                                 collection=app.config["mongo_collection_metrics"])
    #         documents = mongo_client.find_projection({},
    #                                                  {"cpu_percent":
    #                                                       {"$slice": runtime.config["no_of_records_per_timestamp"]},
    #                                                   "mem_percent":
    #                                                       {"$slice": runtime.config["no_of_records_per_timestamp"]}}
    #                                                  )
    #         records = []
    #         for document in documents:
    #             records.append([document])
    #
    #         if len(records) >= 1:
    #             MetricsUpdater.__logger.info("Retry post metrics to RRM, "
    #                                          "Found metrics records in local db to be posted to RRM, "
    #                                          "Now attempt to POST to RRM. ")
    #             deh_enabler_hub_obj = DEHAPIWrapper()
    #
    #             try:
    #                 with ThreadPool(min(MetricsUpdater.MAX_THREAD_POOL_SIZE, len(records))) as pool:
    #                     post_metrics = pool.map(deh_enabler_hub_obj.initiate_post_deh_metrics_request, records)
    #                     return post_metrics
    #
    #             except Exception as E:
    #                 MetricsUpdater.__logger.warning("Retry post metrics to RRM, "
    #                                                 "Exception encountered While Retry Post Metrics Thread, with "
    #                                                 "exception: {}. ".format(E))
    #                 return None
    #         else:
    #             MetricsUpdater.__logger.warning("Retry post metrics to RRM, No metrics found in local db to be "
    #                                             "posted to RRM. Please check, "
    #                                             "1) If any DEH containers are running on the configured "
    #                                             "Docker Host."
    #                                             "2) If any Containers are running, "
    #                                             "ensure the same is associated with valid UID. "
    #                                             "Please refer installation instructions document on how to do so. "
    #                                             "3) Ensure local mongodb containers is up and running. ")
    #             pass

    @tl.job(interval=timedelta(seconds=runtime.config['delete_record_service_interval']))
    def purge_older_internal_db_records(resource_status="Running"):
        """ Module to delete metrics records in local DB which are not posted to RRM"""
        utc_current_datetime = datetime.now(pytz.timezone("UTC"))
        utc_timedelta_datetime = utc_current_datetime - timedelta(seconds=runtime.config['delete_record'])
        utc_current_datetime_str = utc_timedelta_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        deh_enabler_hub_obj = DEHAPIWrapper()
        query = {"first_inserted": {"$lt": utc_current_datetime_str}}
        MetricsUpdater.__logger.info("Attempting to delete older internal db records .i.e. older than: {} seconds."
                                     "".format(runtime.config['delete_record']))
        remove_document = deh_enabler_hub_obj.delete_local_db_records(query)

    def run(self):
        try:
            tl.start(block=True)
        except Exception as E:
            MetricsUpdater.__logger.warning("Exception Encountered during : {} ".format(E))
            pass


if __name__ == "__main__":
    metrics_updater = MetricsUpdater()
    metrics_updater.run()
    """
    with ThreadPoolExecutor() as executor:
        monitor = MetricsMonitor()
        mem_thread = executor.submit(monitor.measure_usage(resource))
        try:
            fn_thread = executor.submit(my_analysis_function)
            result = fn_thread.result()
        finally:
            monitor.keep_measuring = False
            max_usage = mem_thread.result()

        print(f"Peak memory usage: {max_usage}")
        """