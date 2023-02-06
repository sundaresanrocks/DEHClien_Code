from multiprocessing import Pool, Process
from queue import Queue
import logging

def run_parallel(num, shared_new_num_list, to_add): # to_add is passed as an argument
    new_num = num + to_add
    shared_new_num_list.append(new_num)

class DataGenerator:
    def __init__(self, num_list, num_to_add):
        self.num_list = num_list # e.g. [4,2,5,7]
        self.num_to_add = num_to_add # e.g. 1

        self.run()

    def run(self):
        pool = Pool(processes=50)
        new_num_list = [2,3,4,5,6]
        results = [pool.apply_async(run_parallel, (num, new_num_list, self.num_to_add)) # num_to_add is passed as an argument
                      for num in self.num_list]
        roots = [r.get() for r in results]
        pool.close()
        pool.terminate()
        pool.join()
        return results


DataGenerator_class = DataGenerator([1,2,3,4,5],1)
result = DataGenerator_class.run()
print(result)

parameters = {'status': 'running'}

if not (parameters['status'].upper() == "ALL" or parameters['status'].upper() == "RUNNING"):
    print("InValid")
else:
    print("Valid")