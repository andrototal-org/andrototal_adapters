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

        self.__check_notification()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.press_back()
            p.start_activity("com.drweb", ".activities.DrWebAntivirus")
            p.wait_for_activity("com.drweb.activities.DrWebAntivirus", 10)

            p.tap_on_coordinates(120, 160)
            p.wait_for_activity(
                "com.drweb.antivirus.lib.activities.scaner.ScanerActivity", 10)

            # start scan
            p.tap_on_coordinates(120, 90)

            # 30 seconds timeout
            if p.wait_for_activity(
                    "com.drweb.antivirus.lib.activities.\
scaner.VirusListActivity",
                    30, critical=False):
                p.refresh()
                threat_name = p.get_view_by_id("ListItemIconTitle").mText
                self.result['detected_threat'] = threat_name
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # copy sample to SD card
            p.push_file(sample_path)

        self.__check_notification()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.press_back()
            p.start_activity("com.drweb", ".activities.DrWebAntivirus")
            p.wait_for_activity("com.drweb.activities.DrWebAntivirus", 10)

            p.tap_on_coordinates(120, 160)
            p.wait_for_activity(
                "com.drweb.antivirus.lib.activities.scaner.ScanerActivity", 10)

            # start scan (full scan)
            p.tap_on_coordinates(120, 150)

            # 4 minutes timeout (full scan takes a lot of time)
            if p.wait_for_activity(
                    "com.drweb.antivirus.lib.activities.\
scaner.VirusListActivity",
                    240, critical=False):
                p.refresh()
                threat_name = p.get_view_by_id("ListItemIconTitle").mText
                self.result['detected_threat'] = threat_name
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND

    def __check_notification(self):
        p = self.pilot
        # open the notification bar in order to correctly compute the view
        # coordinates of the notification to click
        p.notification_manager.open_notification_bar()
        if p.notification_manager.wait_for_notification_by_title(
                "Threats detected", 20):
            # gets the notification center coordinates
            notif = p.notification_manager.get_notifications_by_title(
                "Threats detected")
            x, y = notif[0]['node'].get_center_point()
            p.tap_on_coordinates(x, y)
            p.wait_for_activity(
                "com.drweb.antivirus.lib.monitor.MonitorVirusActivity", 15)
            p.refresh()
            threat_name = p.get_view_by_id("ListItemIconTitle").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        # start drweb
        p.start_activity("com.drweb", ".activities.DrWebAntivirus")
        p.wait_for_activity("com.drweb.activities.DrWebAntivirus", 10)

        p.tap_on_coordinates(120, 200)

        logger.info("Waiting 60 seconds for udpate...")
        time.sleep(60)

        p.refresh()
        update_result = p.get_view_by_text("Last update")
        update_date_text = update_result.mText.split('\\n')[1]
        logger.info("Last update made on: %s", update_date_text)

        #update_date = datetime.datetime.strptime(
        #    "%I:%M %p %m/%d/%Y", update_date_text)

        p.press_back()  # back to home screen

        self.result['executed'] = True
