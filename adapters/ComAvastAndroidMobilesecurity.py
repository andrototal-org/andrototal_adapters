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
        self.__check_popup()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.press_home()
            p.start_activity("com.avast.android.mobilesecurity",
                             ".app.home.StartActivity")
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.home.HomeActivity", 60)

            p.tap_on_coordinates(120, 80)
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.\
scanner.ScannerActivity", 60)
            # start scan
            p.tap_on_coordinates(120, 255)
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.\
scanner.ScannerLogActivity", 120)

            p.refresh()

            if p.get_view_by_text("No problems found") is not None:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                threat_name = p.get_view_by_id("virus").mText
                self.result['detected_threat'] = threat_name

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        time.sleep(2)
        self.__check_popup()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.press_home()
            p.start_activity("com.avast.android.mobilesecurity",
                             ".app.home.StartActivity")
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.home.HomeActivity", 60)

            p.tap_on_coordinates(120, 80)
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.\
scanner.ScannerActivity", 50)
            time.sleep(1)
            # disable app scan
            p.tap_on_coordinates(120, 110)
            time.sleep(1)
            # enable storage scan
            p.tap_on_coordinates(120, 180)
            time.sleep(1)
            # start scan
            p.tap_on_coordinates(120, 255)
            p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.\
scanner.ScannerLogActivity")

            p.refresh()

            if p.get_view_by_text("No problems found") is not None:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                threat_name = p.get_view_by_id("virus").mText
                self.result['detected_threat'] = threat_name

    def __check_popup(self):
        p = self.pilot
        if p.wait_for_activity(
                "com.avast.android.mobilesecurity.app.\
scanner.VirusShieldActivity",
                60, critical=False):
            p.refresh()
            scan_result = p.get_view_by_id("title").mText

            # search malware report string
            regex_result = re.search(
                r"been reported as ([^\\\n\(\)]*) \(([^\\\n]*)\)", scan_result)
            if regex_result is None:
                # search PUA report string
                # Darky ROM is a potentially unwanted program (ELF:Lootor-G
                # [PUP]).\n
                regex_result = re.search(
                    r"is a potentially unwanted program ([^\\\n]*)",
                    scan_result)
                threat_name = regex_result.group(1)
            else:
                threat_name = regex_result.group(2)

            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        # start avast
        p.start_activity("com.avast.android.mobilesecurity",
                         ".app.home.StartActivity")
        p.wait_for_activity(
            "com.avast.android.mobilesecurity.app.home.HomeActivity", 50)

        p.monkey_controller.swipe_up()
        p.tap_on_coordinates(120, 245)
        p.wait_for_activity(
            "com.avast.android.mobilesecurity.app.\
settings.SettingsActivity", 60)
        time.sleep(1)
        p.tap_on_coordinates(120, 120)
        p.wait_for_activity(
            "com.avast.android.mobilesecurity.app.\
settings.SettingsUpdatesActivity", 60)
        time.sleep(1)
        p.tap_on_coordinates(120, 275)
        logger.info("Waiting 120 seconds for udpate...")
        time.sleep(120)

        #update_result = p.get_view_by_id("row_subtitle")

        p.press_back()  # back to home screen
        time.sleep(1)
        p.press_back()
        time.sleep(1)
        p.press_back()

        self.result['executed'] = True
