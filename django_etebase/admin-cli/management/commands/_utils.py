from distutils.util import strtobool
from datetime import datetime
import pytz

def argbool(arg):
    if arg == None: return None
    return bool(strtobool(arg))

def argdate(arg):
    if arg == None: return None
    try:
        return pytz.utc.localize(datetime.strptime(arg, '%Y-%m-%d %H:%M:%S'))
    except ValueError:
        return pytz.utc.localize(datetime.strptime(arg, '%Y-%m-%d %H:%M:%S.%f'))
