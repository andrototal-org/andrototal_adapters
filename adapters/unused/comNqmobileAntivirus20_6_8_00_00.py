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
        self.pilot.start_activity("com.nqmobile.antivirus20", "com.netqin.antivirus.AntiVirusSplash")
        self.pilot.wait_for_activity("com.netqin.antivirus.ui.slidepanel.SlidePanel", 10)

        self.pilot.tap_on_coordinates(65, 145)
        self.pilot.wait_for_activity("com.netqin.antivirus.scan.ScanMain")

        # start scan
        self.pilot.tap_on_coordinates(125, 215)

        # 30 seconds to complete the scan
        if self.pilot.wait_for_activity("com.netqin.antivirus.scan.ScanResult", 30):
            self.pilot.refresh()
            if self.pilot.exist_view_by_text("No viruses or malware detected"):
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                threat_name = self.pilot.get_view_by_id("result_item_subtitle").mText
                self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        time.sleep(5)

        # 10 seconds to report any malicious activity
        if self.pilot.wait_for_activity("com.netqin.antivirus.scan.MonitorVirusTip", 10):
            self.pilot.refresh()
            threat_message = self.pilot.get_view_by_id("message").mText

            threat_name = re.search(r"\[Virus name\]: (.*)\\n\[Virus path\]",
                                    threat_message, re.DOTALL).group(1)

            self.result['detected_threat'] = threat_name

        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

# if __name__ == "__main__":
#     logger = logging.getLogger('andropilot')
#     logger.setLevel(logging.DEBUG)
#     logger.addHandler(logging.StreamHandler())
#     test = TestSuite("localhost:5555", 12345, 4939)

#     test.on_install_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
