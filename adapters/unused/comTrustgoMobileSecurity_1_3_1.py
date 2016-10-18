import time

import config
import base

implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)

        if self.pilot.wait_for_activity("com.trustgo.mobile.security.MonitorInstallReportActivity", 10):
            self.pilot.go_back()

        self.pilot.start_activity("com.trustgo.mobile.security", ".SecurityMainActivity")
        self.pilot.wait_for_activity("com.trustgo.mobile.security.SecurityMainActivity")
        # start scan
        self.pilot.tap_on_coordinates(120, 140)
        self.pilot.wait_for_activity("com.trustgo.mobile.security.ScanResultBadActivity")
        self.pilot.wait_for_dialog_to_close()
        self.pilot.refresh()

        if self.pilot.exist_view_by_text("Your device is safe"):
            self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.pilot.tap_on_coordinates(100, 188)
            self.pilot.wait_for_activity("com.trustgo.mobile.security.AppSecurityDetailActivity")
            self.pilot.wait_for_dialog_to_close()
            time.sleep(5)
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("app_security_name").mText
            self.result['detected_threat'] = threat_name

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        time.sleep(5)

        # 10 seconds to report any malicious activity
        if self.pilot.wait_for_activity("com.trustgo.mobile.security.MonitorInstallReportActivity", 10):
            self.pilot.tap_on_coordinates(180, 220)
            self.pilot.wait_for_activity("com.trustgo.mobile.security.AppSecurityDetailActivity", 5)
            self.pilot.wait_for_dialog_to_close()
            time.sleep(5)
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("app_security_name").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

# if __name__ == "__main__":
#     logger = logging.getLogger('andropilot')
#     logger.setLevel(logging.DEBUG)
#     logger.addHandler(logging.StreamHandler())
#     test = TestSuite("localhost:5555", 12345, 4939)

#     test.on_install_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
