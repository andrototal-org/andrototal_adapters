import datetime
import logging
import time

import config
import base

module_logger = logging.getLogger(__name__)


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        if p.wait_for_activity(
                "com.symantec.mobilesecurity.ui.RemovePackageDialog",
                15, critical=False):
            self.result['detected_threat'] = config.THREAT_FOUND
        else:
            p.start_activity("com.symantec.mobilesecurity", ".ui.Startor")
            p.wait_for_activity(
                "com.symantec.mobilesecurity.ui.phone.ViewPagerActivity", 10)
            time.sleep(2)
            p.monkey_controller.swipe_left()

            p.tap_on_coordinates(210, 165)

            if p.wait_for_activity(
                    "com.symantec.mobilesecurity.ui.phone.ScanResultActivity",
                    30, critical=False):
                self.result['detected_threat'] = config.THREAT_FOUND
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        # start norton
        p.start_activity("com.symantec.mobilesecurity", ".ui.Startor")
        p.wait_for_activity(
            "com.symantec.mobilesecurity.ui.phone.ViewPagerActivity", 10)

        time.sleep(2)
        # skip possible user rate dialog
        if p.wait_for_activity("com.symantec.mobilesecurity.ui.UserRateDialog",
                               10, critical=False):
            p.press_back()
            module_logger.info("Skipped UserRate dialog")

        p.press_menu()
        time.sleep(2)
        p.tap_on_coordinates(120, 120)

        p.wait_for_activity(
            "com.symantec.mobilesecurity.ui.UpdateProgressScreen", 10)
        # wait for 1 minute to finish the update
        module_logger.info("Waiting 1 minute for update...")
        time.sleep(60)
        p.press_back()  # back to home screen
        time.sleep(1)
        self.result['executed'] = True
