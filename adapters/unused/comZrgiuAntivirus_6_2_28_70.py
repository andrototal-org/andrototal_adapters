import logging
import time
import re

import config
import base


implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        self.pilot.start_activity("com.zrgiu.antivirus", ".MainAntiFreeActivity")
        self.pilot.wait_for_activity("com.zrgiu.antivirus.MainAntiFreeActivity", 10)

        # start scan
        self.pilot.tap_on_coordinates(180, 225)

        # 30 seconds timeout
        self.pilot.wait_for_activity("com.zrgiu.antivirus.AFTScanActivity", 30)

        self.pilot.refresh()

        scan_result = self.pilot.get_view_by_id("message").mText
        # No malicious apps were found. Your phone is clean.

        if "No malicious apps were found." in scan_result:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.result['detected_threat'] = config.THREAT_FOUND

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        time.sleep(2)
        if self.pilot.wait_for_activity("com.netqin.antivirus.scan.MonitorVirusTip", 10):
            self.pilot.refresh()
            threat_message = self.pilot.get_view_by_id("message").mText

            threat_name = re.search(r"\[Virus name\]: (.*)\\n\[Virus path\]",
                                    threat_message, re.DOTALL).group(1)

            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

if __name__ == "__main__":
    logger = logging.getLogger('localhost:5557')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    test = TestSuite("localhost:5557", 5556, 12345, 4939)

    test.on_demand_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
    #test.on_demand_detection("/Users/andrea/Desktop/with_problems/avast.apk")
