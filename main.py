import logging
import logging.handlers
import sys

logger = logging.getLogger('mylogger')
logger.setLevel(logging.DEBUG)

syslog = logging.handlers.SysLogHandler(address=("192.168.0.33", 514))

#formatter = logging.Formatter('%(asctime)s module@hostname Appname: %(levelname)s[%(name)s] %(message)s', datefmt= '%b %d %H:%M:%S')

syslog.setLevel(logging.INFO)
#syslog.setFormatter(formatter)

logger.addHandler(syslog)

logger.info("Sample for SysLogHandler")