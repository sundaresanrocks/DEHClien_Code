from flask import Flask, request, json, Response
from pymongo import MongoClient
from app import app
import logging
from runtime import runtime

class MongoAPI:
    def __init__(self, hostname, port, database, collection):
        #self.data = data
        self.__logger = logging.getLogger('DEHClientEnabler.lib.mongodb_wrapper')
        self.hostname = hostname
        self.port = port
        self.database = database
        self.collection = collection
        try:
            self.client = MongoClient("mongodb://"+self.hostname+":"+str(self.port)+"/")
            cursor = self.client[self.database]
            self.collection = cursor[self.collection]
        except Exception as Error:
            self.__logger.info("Failed to create mongo client obj with exception: {}" % Error)

    def find(self, query):
        documents = self.collection.find(query)
        output = [item for item in documents]
        return output

    def find_projection(self, field, collections):
        # Find with projection operator eg., db.collection.find( { "field": value }, { "array": {"$slice": count } } );
        documents = self.collection.find(field, collections)
        output = [item for item in documents]
        return output

    def read(self, data):
        try:
            documents = self.collection.find(data)
            output = [item for item in documents]
            return output
            #output = [{item: self.data[item] for item in self.data if item != '_id'} for self.data in documents]            return output
        except Exception as error:
            self.__logger.error("Failed to read data from DB for record {} with error : {}. ".format(data, error))
            return False

    def write(self, data):
        documents = self.read(data)
        if documents:
            return False
        else:
            try:
                response = self.collection.insert(data, check_keys=False)
                output = {'Status': 'Successfully Inserted', 'Document_ID': str(response)}
                self.__logger.info("Successfully Inserted data to DB for record {}. ".format(data['_id']))
                return output
            except Exception as error:
                self.__logger.error("Failed to write data to DB for record {} with error : {}. ".format(data['_id'],
                                                                                                        error))
                return False

    def update(self, data, ref, tag, new):
        # ref_id = data[ref]
        # tag = tag
        # updated_data = {"$push": {tag: new}}
        # response = self.collection.update_one({ref: ref_id}, updated_data)
        # output = {'Status': 'Successfully Updated' if response.modified_count > 0 else "Nothing was updated."}
        # return output
        try:
            ref_id = data[ref]
            tag = tag
            updated_data = {"$push": {tag: new}}
            response = self.collection.update_one({ref: ref_id}, updated_data)
            output = {'Status': 'Successfully Updated' if response.modified_count > 0 else "Nothing was updated."}
            self.__logger.info("Successfully updated data to DB for record {}. ".format(data['_id']))
            return output
        except Exception as error:
            self.__logger.error("Failed to update data to DB for record {} with error : {}. ".format(data['_id'],
                                                                                                     error))
            return False

    def update_one(self, ref_id, to_update_data):
        output = {}
        response = self.collection.update_one({"_id": ref_id}, {"$set": to_update_data})
        output = {'Status': 'Successfully Updated' if response.modified_count > 0 else "Nothing was updated"}
        return output

    def update_array(self, id, field, to_update, sort_value, retain_no_of_records=6000):
        """
        the $each modifier to add multiple documents to the <<field>> array,
        the $sort modifier to sort all the elements of the modified <<field>> array by the score field in
        descending order, and
        the $slice modifier to keep only the first  sorted elements of the quizzes array.
        """
        if type(sort_value) == str:
            response = self.collection.update({"_id": id},
                                              {"$push": {field: {"$each": [to_update],
                                                                 "$sort": {sort_value: -1},
                                                                 "$slice": retain_no_of_records}}})
        if type(sort_value) == dict:
            response = self.collection.update({"_id": id},
                                              {"$push": {field: {"$each": [to_update],
                                                                 "$sort": sort_value,
                                                                 "$slice": retain_no_of_records}}})
        return response

    def delete(self, data):
        filter_set = data['Document']
        response = self.collection.delete_many({})
        output = {'Status': 'Successfully Deleted' if response.deleted_count > 0 else "Document not found."}
        return output

    def delete_one(self, data):
        response = self.collection.delete_one(data)
        output = {'Status': 'Successfully Deleted' if response.deleted_count > 0 else "Document not found."}
        return output

    def delete_filter(self, delete_filter):
        try:
            documents = self.find(delete_filter)
            if documents:
                for document in documents:
                    self.__logger.info("MongoDB Wrapper - Delete/Purging old records. "
                                       "Record: {} matching delete criteria i.e record which was not posted to RRM "
                                       "for more than: {} seconds. ".format(document['_id'],
                                                                            runtime.config['delete_record']))
                    self.__logger.debug("MongoDB Wrapper - Delete/Purging old records. "
                                        "Filter used or Delete criteria: {}".format(delete_filter))
                response = self.collection.delete_many(delete_filter)
                output = {'Status': 'Successfully Deleted' if response.deleted_count > 0 else "Document not found."}

            else:
                self.__logger.info("MongoDB Wrapper - Delete/Purging old records. "
                                   "No Record/s matches the delete criteria i.e "
                                   "no records (if captured any) were skipped from posting to RRM "
                                   "for more than: {} seconds. No action taken. "
                                   .format(runtime.config['delete_record']))
                output = {'Status': 'No Records matching delete criteria. No action taken'}

            self.__logger.debug("MongoDB Wrapper - Delete/Purging old records. "
                                "Status of the delete action: {}.".format(output))
            return output

        except Exception as ERROR:
            self.__logger.warning("MongoDB Wrapper - Delete/Purging old records. "
                                  "Possibly failed to communicate with local db ")
            output = {'Status': 'No Records deleted. Possibly failed to communicate with local DB. '}
            self.__logger.debug("MongoDB Wrapper - Delete/Purging old records. "
                                "Status of the delete action: {}.".format(output))
            return output

    def delete_many(self):
        response = self.collection.delete_many({})
        output = {'Status': "{} documents deleted.".format(response.deleted_count)}
        return output


if __name__ == '__main__':
    '''
    data = {
        "database": "DEHClient",
        "collection": "metrics",
    }

    alarm_json = {"namespace": "dojot.docker", "domain": "container went down",
                  "additionalData": {"event": "stop", "container": "test_ubunthu9", "image": "ubuntu:latest",
                                     "exitCode": "0",
                                     "id": "e4bf829973bffe77c5186bdee77376a4688ffb1b5216762694e3f63d1d24370f",
                                     "imageId": "sha256:d70eaf7277eada08fca944de400e7e4dd97b1262c06ed2b1011500caa4decaf1"},
                  "severity": "Major", "eventTimestamp": "2020-12-23T19:18:52"}

    formatted_data = {'_id': alarm_json['additionalData']['id'], 'metadata': alarm_json['additionalData']}
    events_list = []
    event_data = {'event': alarm_json["additionalData"]["event"],
                  'exitcode': alarm_json["additionalData"]["exitCode"],
                  'severity': alarm_json["severity"],
                  'eventTimestamp': alarm_json["eventTimestamp"]}
    events_list.append(event_data)
    formatted_data['events'] = events_list
    #print(formatted_data)
    #mongo_obj = MongoAPI(data)
    mongo_client = MongoAPI(hostname=app.config['mongo_host'],
                                                 port=app.config['mongo_port'],
                                                 database=app.config['mongo_db'],
                                                 collection=app.config['mongo_collection_events'])
    doc = mongo_client.read({'_id': 'e4bf829973bffe77c5186bdee77376a4688ffb1b5216762694e3f63d1d24370f'})
    if doc:
        update = mongo_client.update(formatted_data, '_id', 'events', event_data)
    else:
        doc = mongo_client.write(formatted_data)

    doc = mongo_client.read({'_id': 'e4bf829973bffe77c5186bdee77376a4688ffb1b5216762694e3f63d1d24370f'})
    for i in doc:
        print(i)
    '''
    mongo_client = MongoAPI(hostname=app.config['mongo_host'],
                                                 port=app.config['mongo_port'],
                                                 database=app.config['mongo_db'],
                                                 collection=app.config['mongo_collection_metrics'])
    print(mongo_client)
    docs = mongo_client.read({})



