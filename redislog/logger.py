import socket
import getpass
import datetime
import inspect
import logging
from redislog import handlers
def configure():
    log = RedisLogger('my.logger')
    log.addHandler(handlers.RedisHandler.to("logging:test", host='10.211.55.12',port=6379, password='ZuPEFJCwKxJ7nHG', level="DEBUG"))
    return log


def levelAsString(level):
    return {logging.DEBUG: 'debug',
            logging.INFO: 'info',
            logging.WARNING: 'warning',
            logging.ERROR: 'error',
            logging.CRITICAL: 'critical',
            logging.FATAL: 'fatal'}.get(level, 'unknown')


def _getCallingContext():
    """
    Utility function for the RedisLogRecord.

    Returns the module, function, and lineno of the function
    that called the logger.

    We look way up in the stack.  The stack at this point is:
    [0] logger.py _getCallingContext (hey, that's me!)
    [1] logger.py __init__
    [2] logger.py makeRecord
    [3] _log
    [4] <logging method>
    [5] caller of logging method
    """
    frames = inspect.stack()

    if len(frames) > 4:
        context = frames[5]
    else:
        context = frames[0]

    modname = context[1]
    lineno = context[2]

    if context[3]:
        funcname = context[3]
    else:
        funcname = ""

    # python docs say you don't want references to
    # frames lying around.  Bad things can happen.
    del context
    del frames

    return modname, funcname, lineno


class RedisLogRecord(logging.LogRecord):

    def __init__(self, name, lvl, fn, lno, msg, args, exc_info, func=None, **extra):
        logging.LogRecord.__init__(
            self, name, lvl, fn, lno, msg, args, exc_info, func=None, **extra)

        # You can also access the following instance variables via the
        # formatter as
        #     %(hostname)s
        #     %(username)s
        #     %(modname)s
        # etc.
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.modname, self.funcname, self.lineno = _getCallingContext()

        self._raw = {
            'name': name,
            'level': levelAsString(lvl),
            'filename': fn,
            'line_no': self.lineno,
            'msg': str(msg),
            'args': list(args),
            'time': datetime.datetime.utcnow(),
            'funcname': self.funcname,
            'username': self.username,
            'hostname': self.hostname,
            'traceback': exc_info
        }
        self._raw.update(extra)


class RedisLogger(logging.getLoggerClass()):

    def makeRecord(self, name, lvl, fn, lno, msg, arg, exc_info, *args, **extra):

        record = RedisLogRecord(name, lvl, fn, lno, msg, arg,
                                exc_info, args, **extra)
        if extra:
            for key in extra:
                if (key in ["message", "asctime"]) or (key in record.__dict__):
                    raise KeyError(
                        "Attempt to overwrite %r in RedisLogRecord" % key)
                record.__dict__[key] = extra[key]
        # print(record)
        return record
