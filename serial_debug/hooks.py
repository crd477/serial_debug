#!/usr/bin/python2.7
#from nova.openstack.common import log as logging
import logging
import logging.handlers
import serial_debug
import pprint

class serial_debug_run_hook(object):
        def pre(self, *args, **kwargs):
		pass

        def post(self, rv, *args, **kwargs):
                # set up logging
                log = logging.getLogger(__name__)
                handler = logging.handlers.SysLogHandler(address = '/dev/log')
                formatter = logging.Formatter('serial_debug_run.%(funcName)s: %(message)s')
                handler.setFormatter(formatter)
                log.addHandler(handler)

                log.error("post hook called")

		# list of tuples that have the instance information
		opt_list = args[2]
		uuid = opt_list['instance_uuids']

		# list of information
		opt_list = args[9]
		name = opt_list['name']

		log.error(uuid[0])
		log.error(name)

                try:
                        exitCode = serial_debug.attach_debug(name, uuid[0])
                        if exitCode == 0:
                                log.info("serial_debug run exited successfully")

                except SystemExit as e:
                        log.error("serial_debug run exited with error %s" % (e.code))

                except Exception:
                        log.error("serial_debug could not run. Unhandled exception")

class serial_debug_teardown(object):
        def pre(self, *args, **kwargs):
                # set up logging
                log = logging.getLogger(__name__)
                handler = logging.handlers.SysLogHandler(address = '/dev/log')
                formatter = logging.Formatter('serial_debug_teardown.%(funcName)s: %(message)s')
                handler.setFormatter(formatter)
                log.addHandler(handler)

                log.error("pre hook called")

		# find the name of the instance
		opt_list = args[2]
		name = opt_list['name']
		log.error("name: " + name)

                try:
                        exitCode = serial_debug.detach_debug(name)
                        if exitCode == 0:
                                log.info("serial_debug run exited successfully")

                except SystemExit as e:
                        log.error("serial_debug run exited with error %s" % (e.code))

                except Exception:
                        log.error("serial_debug could not run. Unhandled exception")

        def post(self, rv, *args, **kwargs):
                pass

if __name__ == "__main__":
        testMe = serial_debug_run_hook()
	testMe.post(1)
