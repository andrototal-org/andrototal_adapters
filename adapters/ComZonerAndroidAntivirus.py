import datetime
import logging
import time

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
            p.start_activity("com.zoner.android.antivirus", ".ActMain")
            p.wait_for_activity("com.zoner.android.antivirus.ActMain")

            p.tap_on_coordinates(120, 130)
            p.wait_for_activity("com.zoner.android.antivirus.ActMalware")
            # start scan
            p.tap_on_coordinates(120, 80)
            p.wait_for_activity(
                "com.zoner.android.antivirus_common.ActScanResults")

            p.refresh()
            event_checker = lambda: (
                p.exist_view_by_text("All scanned files are clean")
                or p.exist_view_by_text("One problem found"))

            if p.wait_for_custom_event(
                    event_checker, timeout=p.TIMEOUT, refresh=True):
                if p.exist_view_by_text("One problem found"):
                    threat_view = p.get_view_by_id("scaninfected_row_virus")
                    self.result['detected_threat'] = threat_view.mText
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # copy sample to SD card
            p.push_file(sample_path)
        time.sleep(2)
        self.__check_popup()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.start_activity("com.zoner.android.antivirus", ".ActMain")
            p.wait_for_activity("com.zoner.android.antivirus.ActMain")

            p.tap_on_coordinates(120, 130)
            p.wait_for_activity("com.zoner.android.antivirus.ActMalware")
            # start scan (on SD card)
            p.tap_on_coordinates(120, 120)
            p.wait_for_activity(
                "com.zoner.android.antivirus_common.ActScanResults")

            p.refresh()
            event_checker = lambda: (
                p.exist_view_by_text("All scanned files are clean")
                or p.exist_view_by_text("One problem found"))

            if p.wait_for_custom_event(
                    event_checker, timeout=base.TIMEOUT, refresh=True):
                if p.exist_view_by_text("One problem found"):
                    threat_view = p.get_view_by_id("scaninfected_row_virus")
                    self.result['detected_threat'] = threat_view.mText
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()

    def __check_popup(self):
        p = self.pilot
        if p.wait_for_activity(
                "com.zoner.android.antivirus_common.ActScanResults",
                base.TIMEOUT, critical=False):
            p.refresh()
            threat_view = p.get_view_by_id("scaninfected_row_virus")
            self.result['detected_threat'] = threat_view.mText
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        p.start_activity("com.zoner.android.antivirus", ".ActMain")
        p.wait_for_activity("com.zoner.android.antivirus.ActMain")

        time.sleep(1)
        start_x = end_x = 120
        start_y = 270
        end_y = 20
        p.monkey_controller.drag(start_x, start_y, end_x, end_y, 0.5, 5)

        time.sleep(1)

        # tap on "Update now"
        p.tap_on_coordinates(120, 220)
        # wait for 45 seconds to finish the update
        logger.info("Waiting for update...")
        time.sleep(45)

        p.press_back()  # back to home screen
        time.sleep(1)
        self.result['executed'] = True
