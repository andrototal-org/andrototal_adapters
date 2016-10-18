import datetime
import logging
import time
import re

import config
import base

logger = logging.getLogger(__name__)


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        time.sleep(2)

        if p.wait_for_activity(
                "com.trendmicro.tmmssuite.antimalware.scan.RealtimeAlert",
                60, critical=False):
            self.result['detected_threat'] = self.__extract_name()

        else:
            # self.result['detected_threat'] = config.NO_THREAT_FOUND
            p.start_activity(
                "com.trendmicro.tmmspersonal",
                "com.trendmicro.tmmssuite.consumer.login.ui.Login")
            time.sleep(5)
            p.wait_for_activity(
                "com.trendmicro.tmmssuite.consumer.\
main.ui.TmmsSuiteComMainEntry", 400)
            time.sleep(2)
            # tap on "Scan device"
            p.tap_on_coordinates(120, 280)
            if p.wait_for_activity(
                    "com.trendmicro.tmmssuite.antimalware.\
scan.RealtimeAlert", 200,
                    critical=False):
                self.result['detected_threat'] = self.__extract_name()
            else:
                if p.wait_for_activity(
                        "com.trendmicro.tmmssuite.consumer.\
scanner.ScanResultActivity", 300):
                    p.refresh()
                    if p.exist_view_by_text('Threats found'):
                        scan_result = p.get_view_by_id(
                            "scan_result_item_name").mText
                        threat_name = re.search(
                            r'Threat: (.*)\\n', scan_result).group(1)
                        self.result['detected_threat'] = threat_name
                    else:
                        self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    self.result['detected_threat'] = config.SCAN_TIMEOUT
                    raise base.ScanTimeout()

    def __extract_name(self):
        p = self.pilot
        p.refresh()
        threat_view = p.get_view_by_id("tv_malware_name")
        if not threat_view:
            return config.THREAT_FOUND
        else:
            threat_text = threat_view.mText
            threat_name = re.sub(r"Name: ", '', threat_text)
            return threat_name.strip()

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        p.start_activity("com.trendmicro.tmmspersonal",
                         "com.trendmicro.tmmssuite.consumer.login.ui.Login")
        p.wait_for_activity(
            "com.trendmicro.tmmssuite.consumer.\
main.ui.TmmsSuiteComMainEntry", 200)

        time.sleep(2)
        p.monkey_controller.swipe_left()
        time.sleep(2)
        # tap on "Virus Scanner"
        p.tap_on_coordinates(120, 85)
        p.wait_for_activity(
            "com.trendmicro.tmmssuite.consumer.\
scanner.threat.ThreatScannerMain", 60)
        time.sleep(1)
        # tap on "Update"
        p.tap_on_coordinates(140, 175)
        time.sleep(1)
        p.tap_on_coordinates(200, 220)

        # wait for 1 minute to finish the update
        logger.info("Waiting for update...")
        p.wait_for_activity(
            "com.trendmicro.tmmssuite.consumer.\
scanner.threat.UpdateResultDialog", 65)
        p.refresh()
        update_result = p.get_view_by_id("tv_update_result").mText
        if 'No update needed' in update_result:
            self.result['executed'] = False
        else:
            self.result['executed'] = True

        p.press_back()  # back to home screen
        time.sleep(1)
        p.press_back()
        time.sleep(1)
        p.press_back()
        time.sleep(1)
