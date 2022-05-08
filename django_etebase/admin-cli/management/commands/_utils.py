from distutils.util import strtobool

def argbool(arg):
    if arg == None: return None
    return bool(strtobool(arg))
