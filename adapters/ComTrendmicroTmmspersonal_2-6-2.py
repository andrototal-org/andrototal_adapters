import time
import re

import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        time.sleep(2)

        if p.wait_for_activity(
                "com.trendmicro.tmmssuite.antimalware.scan.RealtimeAlert",
                15, critical=False):
            p.refresh()
            threat_view = p.get_view_by_id("tv_malware_name")
            if not threat_view:
                self.result['detected_threat'] = config.THREAT_FOUND
            else:
                threat_text = threat_view.mText
                threat_name = re.sub(r"Name: ", '', threat_text)
                self.result['detected_threat'] = threat_name.strip()
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
