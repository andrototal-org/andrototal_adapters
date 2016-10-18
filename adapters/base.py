from datetime import datetime
import logging
from andropilot.pilot import AndroPilot

from andropilot.pilot import TIMEOUT, LONG_TIMEOUT, MEDIUM_TIMEOUT, SHORT_TIMEOUT

module_logger = logging.getLogger(__name__)


class ScanTimeout(Exception):
    pass


def test_method(method):
    def wrapper(self, *args, **kwargs):
        self.result = {'detected_threat': None, 'analysis_time': None}

        self.start_time = datetime.now()

        try:
            self.pilot = AndroPilot(device_name=self.device_name,
                                    view_server_port=self.view_server_port,
                                    monkey_server_port=self.monkey_port)
            self.pilot.open()
            method(self, *args, **kwargs)
        finally:
            # in the end take a screenshot and close AndroPilot instance
            self.pilot.take_screenshot(self.screenshot)
            self.pilot.get_logcat(self.logcat)
            # sleep one second to avoid problesm closing viewserver
            self.pilot.close()

        end_time = datetime.now()
        self.result['analysis_time'] = \
            int((end_time - self.start_time).total_seconds())

        module_logger.info("Scan result: %s (took %s)",
                           self.result['detected_threat'],
                           self.result['analysis_time'])
        return self.result
    return wrapper


def update_method(method):
    def wrapper(self, *args, **kwargs):
        self.result = {'duration': None,
                       'executed': False}

        self.start_time = datetime.now()

        with AndroPilot(device_name=self.device_name,
                        view_server_port=self.view_server_port,
                        monkey_server_port=self.monkey_port) as self.pilot:
            method(self, *args, **kwargs)

        end_time = datetime.now()
        self.result['duration'] = str(end_time - self.start_time)
        module_logger.info("Update result: %s (took %s)",
                           self.result['executed'],
                           self.result['duration'])
        return self.result
    return wrapper


class TestSuiteMetaClass(type):

    def __new__(meta, name, bases, dct):
        detection_methods = []
        for attribute in dct:
            if hasattr(dct[attribute], '__call__'):
                function_name = dct[attribute].__name__
                if function_name.startswith('detection_'):
                    dct[attribute] = test_method(dct[attribute])
                    detection_methods.append(function_name)

                elif function_name.startswith('updater'):
                    dct[attribute] = update_method(dct[attribute])
        dct['detection_methods'] = detection_methods
        return super(TestSuiteMetaClass, meta).__new__(meta, name, bases, dct)


class BaseTestSuite():
    __metaclass__ = TestSuiteMetaClass

    def __init__(self, device_name, monkey_port,
                 view_server_port, screenshot_path, logcat_path):
        self.device_name = device_name
        self.monkey_port = monkey_port
        self.view_server_port = view_server_port
        self.pilot = None
        self.screenshot = screenshot_path
        self.logcat = logcat_path
