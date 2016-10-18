import datetime
import re
import time

import config
import base

from andropilot.pilot import AndroPilotException


class TestSuite(base.BaseTestSuite):

    def __extract_threat_name(self):
        p = self.pilot
        p.refresh()
        threat_view = p.get_view_by_id("TextView01")
        if 'Threat detected' in threat_view.mText:
            threat_name_regex = r"Threat detected: (.*)"
            regex_result = re.search(
                threat_name_regex, threat_view.mText.strip())
            label = regex_result.group(1)
        elif 'This app can be' in threat_view.mText:
            threat_name_regex = r"This app can be used by \
criminals against your interests: (.*)"
            regex_result = re.search(
                threat_name_regex, threat_view.mText.strip())
            label = regex_result.group(1)
        else:
            label = config.THREAT_FOUND

        return label

    def __security_code(self):
        p = self.pilot
        p.wait_for_activity("com.kms.gui.KMSEnterCodeActivity", 10)
        p.type('1234')
        p.tap_on_coordinates(50, 310)

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.install_package(sample_path)

        time.sleep(2)

        if p.wait_for_activity("com.kms.antivirus.gui.AvUserActionActivity",
                               15, critical=False):
            self.result['detected_threat'] = self.__extract_threat_name()
        else:
            p.start_activity(
                'com.kms.free', 'com.kms.gui.KMSEnterCodeActivity')
            p.wait_for_activity("com.kms.gui.KMSEnterCodeActivity", 10)
            self.__security_code()

            p.wait_for_activity("com.kms.gui.KMSMain", 10)
            time.sleep(2)
            p.tap_on_coordinates(120, 85)
            time.sleep(2)
            p.tap_on_coordinates(120, 145)
            time.sleep(2)
            # start quick scan
            p.tap_on_coordinates(120, 110)
            time.sleep(1)

            if p.wait_for_activity(
                    "com.kms.antivirus.gui.AvUserActionActivity",
                    20, critical=False):
                self.result['detected_threat'] = self.__extract_threat_name()
            else:
                if p.wait_for_activity(
                        "com.kms.antivirus.gui.AvScanResultActivity",
                        5, critical=False):
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    self.result['detected_threat'] = config.SCAN_TIMEOUT
                    raise base.ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)

        if p.wait_for_activity("com.kms.antivirus.gui.AvUserActionActivity",
                               15, critical=False):
            self.result['detected_threat'] = self.__extract_threat_name()
        else:
            p.start_activity(
                'com.kms.free', 'com.kms.gui.KMSEnterCodeActivity')
            self.__security_code()

            p.wait_for_activity("com.kms.gui.KMSMain", 10)
            time.sleep(2)
            p.tap_on_coordinates(120, 85)
            time.sleep(2)
            p.tap_on_coordinates(120, 145)
            time.sleep(2)
            # start full scan
            p.tap_on_coordinates(120, 140)
            time.sleep(1)

            # 2 minutes timeout
            if p.wait_for_activity(
                    "com.kms.antivirus.gui.AvUserActionActivity",
                    120, critical=False):
                self.result['detected_threat'] = self.__extract_threat_name()
            else:
                if p.wait_for_activity(
                        "com.kms.antivirus.gui.AvScanResultActivity",
                        5, critical=False):
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    self.result['detected_threat'] = config.SCAN_TIMEOUT
                    raise base.ScanTimeout()

    def updater(self):
        p = self.pilot
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        # set current date time
        p.adb_command(['shell', 'date', '-s', current_time])

        p.start_activity('com.kms.free', 'com.kms.gui.KMSEnterCodeActivity')
        p.wait_for_activity("com.kms.gui.KMSEnterCodeActivity", 10)
        self.__security_code()

        p.wait_for_activity("com.kms.gui.KMSMain", 10)
        time.sleep(1)
        p.tap_on_coordinates(120, 85)
        time.sleep(1)
        p.tap_on_coordinates(120, 190)

        try:
            p.wait_for_activity('com.kms.updater.gui.UpdateActivity', 10)
        except AndroPilotException:
            p.tap_on_coordinates(120, 200)
            p.wait_for_activity('com.kms.updater.gui.UpdateActivity', 10)

        time.sleep(30)
        p.refresh()
        if p.exist_view_by_id('bases_date'):
            self.result['executed'] = True
        else:
            self.result['executed'] = False

        p.press_back()
        time.sleep(1)
        p.press_back()
        time.sleep(1)
        p.press_back()
