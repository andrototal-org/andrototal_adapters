import time

import config
import base

implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        self.pilot.start_activity("com.ssd.vipre", ".ui.SplashScreenActivity")
        self.pilot.wait_for_activity("com.ssd.vipre.ui.home.HomeFragmentActivity", 10)
        self.pilot.tap_on_coordinates(60, 100)
        self.pilot.wait_for_activity("com.ssd.vipre.ui.av.AntivirusPreferences", 10)
        # start scan
        self.pilot.tap_on_coordinates(110, 150)
        self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanActivity", 10)
        # now the antivirus updates its signature database
        # we don't care, just wait till the end of the scan

        # 70 seconds scan timeout
        if self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanResultActivity", 70):
            self.pilot.refresh()
            if self.pilot.exist_view_by_text("Threat(s) Found"):
                self.pilot.tap_on_coordinates(120, 260)
                self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanMalwareActivity", 10)
                self.pilot.tap_on_coordinates(120, 145)
                self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanMalwareDeleteActivity", 10)
                self.pilot.refresh()
                threat_name = self.pilot.get_view_by_id("threat_name_id").mText
                self.result['detected_threat'] = threat_name
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        time.sleep(5)

        # open the notification bar in order to correctly compute the view
        # coordinates of the notification to click
        self.pilot.notification_manager.open_notification_bar()
        self.pilot.tap_on_coordinates(120, 160)
        if self.pilot.notification_manager.wait_for_notification_by_message("Malware threat(s) have been", 20):
            # gets the notification center coordinates
            notif = self.pilot.notification_manager\
                .get_notifications_by_message("Malware threat(s) have been")
            x, y = notif[0]['node'].get_center_point()

            self.pilot.tap_on_coordinates(x, y)

            self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanMalwareActivity", 10)
            self.pilot.tap_on_coordinates(120, 145)
            self.pilot.wait_for_activity("com.ssd.vipre.ui.av.ScanMalwareDeleteActivity", 10)
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("threat_name_id").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

# if __name__ == "__main__":
#     logger = logging.getLogger('andropilot')
#     logger.addHandler(logging.StreamHandler())
#     logger.setLevel(logging.DEBUG)
#     test = TestSuite("localhost:5561", 12345, 4939)

#     test.on_install_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
