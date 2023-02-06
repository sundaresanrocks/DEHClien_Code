import calendar, time
from datetime import datetime
from time import mktime
import pytz

utc_current_datetime = datetime.now(pytz.timezone("UTC"))
utc_current_datetime_str = utc_current_datetime.strftime("%Y-%m-%d %H:%M:%SZ")
print("utc_current_datetime_str", utc_current_datetime_str)