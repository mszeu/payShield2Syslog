import logging
import logging.handlers
import sys

logger = logging.getLogger('mylogger')
syslog = logging.handlers.SysLogHandler(address=("127.0.0.1", 514))
logger.setLevel(logging.DEBUG)

#formatter = logging.Formatter('%(asctime)s module@hostname Appname: %(levelname)s[%(name)s] %(message)s', datefmt= '%b %d %H:%M:%S')

syslog.setLevel(logging.INFO)
#syslog.setFormatter(formatter)

logger.addHandler(syslog)

logger.info("Sample for SysLogHandler")