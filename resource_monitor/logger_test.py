import logging

# logger = logging.getLogger(__name__)

# # Create handlers
# c_handler = logging.StreamHandler()
# f_handler = logging.FileHandler('file.log')
# logger.setLevel(logging.INFO) # <<< Added Line
# c_handler.setLevel(logging.INFO)
# f_handler.setLevel(logging.INFO)
#
# # Create formatters and add it to handlers
# c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
# f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# c_handler.setFormatter(c_format)
# f_handler.setFormatter(f_format)
#
# # Add handlers to the logger
# logger.addHandler(c_handler)
# logger.addHandler(f_handler)


# logger.warning('logs')
# logger.error('logs')
# logger.info('should log but doesn\'t')
# logger.debug('should log but doesn\'t')



# import schedule
# import time
#
# def task():
#     print("Job Executing - every 10 min!")
#     time.sleep(30)
#
# def task_2():
#     print("Job Executing - every 20 min!")
#     time.sleep(30)
#
# # for every n minutes
# schedule.every(10).seconds.do(task)
#
# schedule.every(20).seconds.do(task_2)
#
# # every hour
# schedule.every().hour.do(task)
#
# # every daya at specific time
# schedule.every().day.at("10:30").do(task)
#
# # schedule by name of day
# schedule.every().monday.do(task)
#
# # name of day with time
# schedule.every().wednesday.at("13:15").do(task)
#
# while True:
#     schedule.run_pending()
import time
from datetime import datetime
from runtime import runtime

scheduled_post = runtime.config['timestamp']

last_metrics_posted = datetime.now()

time.sleep(5)

current_datetime = datetime.now()


time_difference = (current_datetime - last_metrics_posted).total_seconds()

if time_difference > 9:
    print("Attempt Retry")
else:
    print("Continue without retry.")

