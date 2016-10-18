import config
import base


implemented_methods = ['on_demand_detection', 'on_install_detection']


class TestSuite(base.BaseTestSuite):
    @base.test_method
    def on_demand_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)
        self.pilot.start_activity("com.antivirus", ".ui.AntivirusMainScreen")

        if self.pilot.wait_for_activity("com.antivirus.ui.UnInstall", 5):
            self.result['detected_threat'] = config.THREAT_FOUND
        else:
            self.pilot.wait_for_activity("com.antivirus.ui.AntivirusMainScreen", 5)
            # start scan
            self.pilot.tap_on_coordinates(120, 160)
            self.pilot.tap_on_coordinates(120, 160)

            if self.pilot.wait_for_activity("com.antivirus.ui.UnInstall", 15):
                self.result['detected_threat'] = config.THREAT_FOUND
            elif self.pilot.wait_for_activity("com.antivirus.ui.scan.results.ScanResultsExpandable"):
                self.pilot.tap_on_coordinates(120, 130)
                self.pilot.refresh()
                if self.pilot.exist_view_by_text("All security issues were addressed"):
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    self.result['detected_threat'] = config.THREAT_FOUND

    @base.test_method
    def on_install_detection(self, sample_path):
        # install sample
        self.pilot.install_package(sample_path)

        if self.pilot.wait_for_activity("com.antivirus.ui.UnInstall", 20):
            self.result['detected_threat'] = config.THREAT_FOUND
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

# if __name__ == "__main__":
#     logger = logging.getLogger('andropilot')
#     logger.setLevel(logging.DEBUG)
#     logger.addHandler(logging.StreamHandler())
#     test = TestSuite("localhost:5559", 12345, 4939)

#     test.on_demand_detection("/Users/andrea/Desktop/samples/Pjapps/030b481d0f1014efa6f730bf4fcaff3d4b4c85ac.apk")
