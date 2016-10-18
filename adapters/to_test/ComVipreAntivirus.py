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
        time.sleep(2)
        if p.wait_for_activity("com.ssd.vipre.ui.av.ScanActivity",15,critical=False):
            p.refresh()
            threat_view = p.get_view_by_id('threat_name_id').mText
            self.result['detected_threat'] = threat_view
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
        if    self.result['detected_threat'] == config.NO_THREAT_FOUND:   
                  p.start_activity("com.ssd.vipre", ".ui.SplashScreenActivity")
                  p.wait_for_activity("com.ssd.vipre.ui.home.HomeFragmentActivity")
                  time.sleep(10)
                  p.tap_on_coordinates(60, 275)
                  p.wait_for_activity("com.ssd.vipre.ui.av.AntivirusPreferences")
                  p.tap_on_coordinates(240, 200)
                  #Start Scan
                  time.sleep(80)
                  p.wait_for_activity("com.ssd.vipre.ui.av.ScanResultActivity")
                  p.refresh()
                  event_checker = lambda: (p.exist_view_by_text("No malware threat(s) detected on your device") or p.exist_view_by_text("1 malware threat(s) detected on your device"))
                  if p.wait_for_custom_event(event_checker, timeout=60, refresh=True):
                      if p.exist_view_by_text("1 malware threat(s) detected on your device"):
                         p.tap_on_coordinates(225, 475)
                         time.sleep(5)
                         p.tap_on_coordinates(230, 280)
                         time.sleep(10)
                         p.refresh()
                         threat_view = p.get_view_by_id("threat_name_id").mText
                         self.result['detected_threat'] = threat_view 
                      else:
                         self.result['detected_threat'] = config.NO_THREAT_FOUND
                  else:
                      self.result['detected_threat'] = config.SCAN_TIMEOUT
    

    def __check_update(self):
        p = self.pilot
        if p.wait_for_activity("com.ssd.vipre.ui.av.ScanActivity", 10, critical=False):
            p.refresh()
            self.result['executed'] = True
        else:
            self.result['executed'] = False	


    def updater(self):
        p = self.pilot
        # Set current date time
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        p.adb_command(['shell', 'date', '-s', current_time])
        # Start lookout
        p.start_activity("com.ssd.vipre",".ui.SplashScreenActivity")
        p.wait_for_activity("com.ssd.vipre.ui.home.HomeFragmentActivity")
        time.sleep(10)
        # Start update
        p.tap_on_coordinates(60, 275)
        p.wait_for_activity("com.ssd.vipre.ui.av.AntivirusPreferences")
        p.tap_on_coordinates(240, 200)
        # Wait to finish the update
        logger.info("Waiting for update...")
        time.sleep(80)
        self.__check_update()
        # Back to home screen
        p.press_back()
        time.sleep(1)
        p.press_back
        time.sleep(1)
        p.press_back()
        time.sleep(1)











