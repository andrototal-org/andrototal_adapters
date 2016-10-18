import time

import config
import base

implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        self.pilot.install_package(sample_path)
        self.pilot.start_activity("com.bitdefender.security", ".BDMain")

        if self.pilot.wait_for_activity("com.bitdefender.security.antimalware.NotifyUserMalware", 15):
            self.pilot.tap_on_coordinates(170, 240)

        #event_checker = lambda: self.pilot.exist_view_by_text("was detected") or (self.pilot.get_current_view_classname() == "com.bitdefender.security.antimalware.NotifyUserMalware")
        #self.pilot.wait_for_custom_event(event_checker)

        self.pilot.wait_for_activity("com.bitdefender.security.BDMain")
        time.sleep(1)
        self.pilot.tap_on_coordinates(60, 200)
        self.pilot.wait_for_activity("com.bitdefender.security.antimalware.MalwareActivity")
        self.pilot.tap_on_coordinates(120, 170)
        self.pilot.refresh()
        self.pilot.wait_for_text("was detected")

        if self.pilot.exist_view_by_text("No malware was detected"):
            self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.pilot.go_back()
            self.pilot.wait_for_activity("com.bitdefender.security.BDMain")
            self.pilot.tap_on_coordinates(120, 90)
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("TextViewMalwareAppThreatName").mText
            self.result['detected_threat'] = threat_name

    @base.test_method
    def on_install_detection(self, sample_path):
        self.pilot.install_package(sample_path)
        time.sleep(5)

        # 10 seconds to report any malicious activity
        if self.pilot.wait_for_activity("com.bitdefender.security.antimalware.NotifyUserMalware", 10):
            # start the application and get the threat name
            self.pilot.start_activity("com.bitdefender.security", ".BDMain")
            self.pilot.tap_on_coordinates(120, 90)
            self.pilot.refresh()
            threat_name = self.pilot.get_view_by_id("TextViewMalwareAppThreatName").mText
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

# if __name__ == "__main__":
#     test = TestSuite("emulator-5554", 5554, 12345, 4939)

#     test.on_install_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
