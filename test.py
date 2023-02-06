import requests

x = requests.get('https://w3schools.com')
response = None
if response is None and isinstance(x, str):
    print(x.status_code)

status_code = 200
s = {"S":"P"}

if status_code == 200 and (s== {} or s==[]):
    print("PASS")


test_dict = {"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-18678fa4-5cca-4ff5-bab2-85ced52b9ded":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-18678fa4-5cca-4ff5-bab2-85ced52b9ded",
                  "Service":"estimate-animal-welfare-condition-release09","Tags":["latest"],
                  "Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"},"Port":0,
                  "Address":"0.0.0.1","TaggedAddresses":{"lan_ipv4":{"Address":"0.0.0.1","Port":0},
                                                         "wan_ipv4":{"Address":"0.0.0.1","Port":0}},
                  "Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-4ff93b6b-d77c-4617-be6a-fe2a65d08288":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-4ff93b6b-d77c-4617-be6a-fe2a65d08288",
                  "Service":"estimate-animal-welfare-condition-release09",
                  "Tags":["string"],"Meta":{"additionalProp1":"string","additionalProp2":"string",
                                            "additionalProp3":"string","deh_id":"234234"},"Port":0,"Address":"string",
                  "Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-5d36e406-dfd2-4433-a077-d0b23245d02f":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-5d36e406-dfd2-4433-a077-d0b23245d02f",

                  "Service":"estimate-animal-welfare-condition-release09","Tags":["string"],
                  "Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"},
                  "Port":0,"Address":"string","Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-62c12b83-67af-4911-bb87-76a79601627e":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-62c12b83-67af-4911-bb87-76a79601627e",
                  "Service":"estimate-animal-welfare-condition-release09","Tags":["string"],
                  "Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"},
                  "Port":0,"Address":"127.0.0.0","TaggedAddresses":{"lan_ipv4":{"Address":"127.0.0.0","Port":0},
                                                                    "wan_ipv4":{"Address":"127.0.0.0","Port":0}},
                  "Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-7ee9a616-0e77-42dc-b374-7a4d60230a5e":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-7ee9a616-0e77-42dc-b374-7a4d60230a5e",
                  "Service":"estimate-animal-welfare-condition-release09","Tags":["string"],
                  "Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"}
                     ,"Port":0,"Address":"string","Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-7f56edf9-2e67-470d-b21f-0372f3b31bb0":
                 {"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-7f56edf9-2e67-470d-b21f-0372f3b31bb0",
                  "Service":"estimate-animal-welfare-condition-release09","Tags":["latest"],
                  "Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string","deh_id":"21212"},
                  "Port":0,"Address":"0.0.0.1","TaggedAddresses":{"lan_ipv4":{"Address":"0.0.0.1","Port":0},
                                                                  "wan_ipv4":{"Address":"0.0.0.1","Port":0}},
                  "Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},
             "DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-97f6700f-7bca-43de-8fd8-93ade8c87331":{"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-97f6700f-7bca-43de-8fd8-93ade8c87331","Service":"estimate-animal-welfare-condition-release09","Tags":["string"],"Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"},"Port":0,"Address":"string","Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False},"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-cc3f44dd-9dcf-4f17-bad1-e780044025d2":{"ID":"DEMETER:BSE-ID:(estimate-animal-welfare-condition-release09)-cc3f44dd-9dcf-4f17-bad1-e780044025d2","Service":"estimate-animal-welfare-condition-release09","Tags":["latest"],"Meta":{"additionalProp1":"string","additionalProp2":"string","additionalProp3":"string"},"Port":0,"Address":"stri","Weights":{"Passing":1,"Warning":1},"EnableTagOverride":False}}


record = ""
if record and ( record != {} or record is not None):
    print("PASS")
else:
    print("Fail")

import schedule
import time


def job():
    print("I'm working...")


list = []
print(len(list))


schedule.every(10).minutes.do(job)
schedule.every().hour.do(job)
schedule.every().day.at("10:30").do(job)
schedule.every().monday.do(job)
schedule.every().wednesday.at("13:15").do(job)

while True:
    schedule.run_pending()
    time.sleep(1)