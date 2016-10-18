import time

import config
import base

implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        self.pilot.start_activity("com.aegislab.sd3prj.antivirus.free", ".activity.FrontActivity")

        self.pilot.wait_for_activity("com.aegislab.sd3prj.antivirus.free.activity.ScanActivity")

        # start scan
        self.pilot.tap_on_coordinates(120, 130)
        self.pilot.wait_for_activity("com.aegislab.sd3prj.antivirus.free.activity.ScanResultTabActivity")

        self.pilot.refresh()
        suspicious_view = self.pilot.get_view_by_id("scan_summary_suspicious_pkg_value")
        suspicious_value = int(suspicious_view.mText)

        if suspicious_value > 0:
            threat_name = self.pilot.get_view_by_id("item_text").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        time.sleep(2)
        if self.pilot.notification_manager.wait_for_notification_by_message("is suspicious", 10):
            self.pilot.notification_manager.open_notification_bar()
            self.pilot.tap_on_coordinates(120, 70)
            self.pilot.wait_for_activity("com.aegislab.sd3prj.antivirus.free.activity.ScanResultTabActivity")
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("item_text").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
            self.pilot.notification_manager.open_notification_bar()
            self.pilot.tap_on_coordinates(120, 70)
            self.pilot.wait_for_activity("com.aegislab.sd3prj.antivirus.free.activity.ScanResultTabActivity")

# if __name__ == "__main__":
#     test = TestSuite("emulator-5554", 5554, 12345, 4939)

#     test.on_demand_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
