import time

import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        time.sleep(2)
        self.__check_popup()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)

        time.sleep(2)
        self.__check_popup()

    def __check_popup(self):
        p = self.pilot
        if p.wait_for_activity("com.kms.free.antivirus.gui.AppCheckerAlert",
                               10, critical=False):
            p.tap_on_coordinates(120, 210)

            if p.wait_for_activity(
                    "com.kms.free.antivirus.gui.AppCheckerVirusAlert",
                    30, critical=False):
                p.refresh()
                threat_view = p.get_view_by_id("ObjectType")
                self.result['detected_threat'] = threat_view.mText.strip()
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
