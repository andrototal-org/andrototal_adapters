import datetime
import logging
import time
import re

import config
import base

logger = logging.getLogger(__name__)


class TestSuite(base.BaseTestSuite):
    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # Install sample
            p.install_package(sample_path)
        time.sleep(4)
        self.__check_popup()
        if self.result['detected_threat'] == config.NO_THREAT_FOUND:
            p.start_activity("com.sophos.smsec", ".ui.DroidGuardMainActivity")
            p.wait_for_activity("com.sophos.smsec.ui.DroidGuardMainActivity")
            time.sleep(10)
            p.tap_on_coordinates(250, 200)
            p.wait_for_activity("com.sophos.smsec.plugin.scanner.ScanActivity")
            p.tap_on_coordinates(130, 360)
            # Start Scan
            time.sleep(80)
            p.refresh()
            if p.get_view_by_id('threats_found_count').mText == '0 ':
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                time.sleep(2)
                p.tap_on_coordinates(325, 355)
                p.wait_for_activity("com.sophos.smsec.plugin.scanner.ScanResultActivity")
                time.sleep(3)
                p.tap_on_coordinates(230, 210)
                time.sleep(2)
                p.refresh()
                threat_view = p.get_view_by_id('apk_detail_view_malware_text').mText
                self.result['detected_threat'] = threat_view
    
    def __check_popup(self):
        p = self.pilot
        time.sleep(10)
        p.refresh()
        time.sleep(2)
        if p.exist_view_by_text('Threat found'):
            p.tap_on_coordinates(385, 495)
            time.sleep(2)
            p.refresh()
            threat_view = p.get_view_by_id('apk_detail_view_malware_text').mText
            self.result['detected_threat'] = threat_view
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND


    def updater(self):
        p = self.pilot
        # Set current time
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        p.adb_command(['shell', 'date', '-s', current_time])
        self.result['execute'] = False
        # It's a cloud app that is an application program that functions in the cloud with some characteristics of a pure desktop app and some characteristics of a pure Web app. Because this no updates are needed.
        time.sleep(1)
        

        
        
              

                
