import datetime
import logging
import re
import time

import base
import config

module_logger = logging.getLogger(__name__)


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 10,
                               critical=False):
            self.result['detected_threat'] = self.__extract_threat_name_app()
        else:
            p.press_home()
            p.start_activity('com.lookout', '.ui.v2.Dashboard')
            # the antivirus may show the theat warning when launched
            if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 5,
                                   critical=False):
                self.result[
                    'detected_threat'] = self.__extract_threat_name_app()

            p.wait_for_activity('com.lookout.ui.v2.Dashboard', 10)
            p.tap_on_coordinates(120, 180)
            p.wait_for_activity('com.lookout.ui.v2.SecurityActivity', 10)
            p.tap_on_coordinates(195, 230)
            if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 35,
                                   critical=False):
                self.result[
                    'detected_threat'] = self.__extract_threat_name_app()
                return

            p.refresh()
            if p.exist_view_by_text('No Threats Detected'):
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)

        if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 10,
                               critical=False):
            self.result['detected_threat'] = self.__extract_threat_name_file()
        else:
            p.press_home()
            p.start_activity('com.lookout', '.ui.v2.Dashboard')
            # the antivirus may show the theat warning when launched
            if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 5,
                                   critical=False):
                self.result[
                    'detected_threat'] = self.__extract_threat_name_file()

            p.wait_for_activity('com.lookout.ui.v2.Dashboard', 10)
            p.tap_on_coordinates(120, 180)
            p.wait_for_activity('com.lookout.ui.v2.SecurityActivity', 10)
            p.tap_on_coordinates(195, 230)
            if p.wait_for_activity('com.lookout.ui.WarnOfThreatActivity', 35,
                                   critical=False):
                self.result[
                    'detected_threat'] = self.__extract_threat_name_file()
                return

            p.refresh()
            if p.exist_view_by_text('No Threats Detected'):
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT

    def __extract_threat_name_app(self):
        time.sleep(2)
        p = self.pilot
        p.tap_on_coordinates(120, 200)
        p.wait_for_activity('com.lookout.ui.v2.AppDetailActivity', 5)
        self.pilot.refresh()

        threat_view = p.get_view_by_id('app_alert_classified')
        # extract the threat name, example: "CLASSIFICATION:
        # Trojan.Android.RootSmart.a"
        threat_name_regex = r"CLASSIFICATION: (.*)"
        regex_result = re.search(threat_name_regex, threat_view.mText)
        return regex_result.group(1)

    def __extract_threat_name_file(self):
        time.sleep(2)
        p = self.pilot
        p.tap_on_coordinates(120, 200)
        p.wait_for_activity('com.lookout.ui.v2.FileDetailActivity', 5)
        self.pilot.refresh()

        threat_view = p.get_view_by_id('app_alert_classified')
        # extract the threat name, example: "CLASSIFICATION:
        # Trojan.Android.RootSmart.a"
        threat_name_regex = r"CLASSIFICATION: (.*)"
        regex_result = re.search(threat_name_regex, threat_view.mText)
        return regex_result.group(1)

    def updater(self):
        p = self.pilot
        # set current date time
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        p.adb_command(['shell', 'date', '-s', current_time])

        # start lookout
        p.start_activity('com.lookout', '.ui.v2.Dashboard')
        p.wait_for_activity('com.lookout.ui.v2.Dashboard', 10)

        # wait for 1 minute
        module_logger.info("Waiting 1 minute for push updates...")
        time.sleep(60)
        p.refresh()

        last_event = p.get_view_by_id('event_item_with_icon_text', 'layout')
        last_event_text = last_event.get_children_by_id(
            'module_event_text')[0].mText
        last_event_time_text = last_event.get_children_by_id(
            'module_event_subtext')[0].mText

        module_logger.debug("Last event text: %s", last_event_text)
        module_logger.debug("Last event time: %s", last_event_time_text)

        p.press_back()
        time.sleep(1)

        if 'Malware definition list updated' in last_event_text:
            if 'min' in last_event_time_text:
                self.result['executed'] = True
                return
        self.result['executed'] = False
