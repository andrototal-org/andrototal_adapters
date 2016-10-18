import time

from datetime import datetime
import config
from base import BaseTestSuite, ScanTimeout
import base


class TestSuite(BaseTestSuite):

    def detection_on_install(self, sample_path):
        p = self.pilot
        if sample_path:
            p.install_package(sample_path)

        p.press_menu()
        # Problem is that com.bitdefender.antivirus/.NotifyUserMalware
        # give no detail of the infection
        # So lets start a full scan and since is the same as scanning a
        # copied app we reuse the same method
        p.refresh()
        if p.wait_for_activity('com.bitdefender.antivirus.NotifyUserMalware',
                               timeout=base.LONG_TIMEOUT,
                               critical=False):
            self._run_full_scan_with_check(p)
        else:
            # Make a second check to detect if it only a timeout or
            # really there is no threat
            p.start_activity('com.bitdefender.antivirus',
                             'com.bitdefender.antivirus.StartActivity')
            p.refresh()
            if p.wait_for_activity(
                    'com.bitdefender.antivirus.StartActivity',
                    timeout=base.TIMEOUT,
                    critical=False):
                p.refresh()
                # If this view do not exist no threat has been found
                if not p.exist_view_by_id('main_result_scan_container'):
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    self._run_full_scan_with_check(p)
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        time.sleep(2)
        # Run a full scan
        self._run_full_scan_with_check(p)

    def updater(self):
        # As far as I can see there is no update option.
        # The Av uses a in-cloud-scan during the scanning
        # So update is useless, and also not present in the UI
        self.result['signature_version'] = None
        self.result['cloud_signatures'] = True
        self.result['signature_date'] = datetime.now()
        self.result['executed'] = True

    def _run_full_scan_with_check(self, p):
        """This function is used to run a full scan checking if
        appears an useless screen with the 'Continue' button and
        take care of this case.

        Keyword arguments
        p -- an instance of AndroPilot

        Return
        Nothing but will set result['detected_threat']
        """
        self._run_full_scan(p)
        # Sometimes the Av shows a useless page and it gives no
        # result.
        # if this appen, we must call directly the Results activity
        # it's a life of hardship...
        p.refresh()
        if p.exist_view_by_text('Continue'):
            # Tap on 'Continue' button
            p.tap_on_coordinates(130, 300)
            p.start_activity('com.bitdefender.antivirus',
                             'com.bitdefender.antivirus.ResultActivity')
            p.refresh()
            if p.wait_for_activity(
                    'com.bitdefender.antivirus.ResultActivity',
                    timeout=base.TIMEOUT,
                    critical=False):
                # Extract the threat name
                threat_name = self._get_threat_name_from_view(p)
                if threat_name is not None:
                    self.result['detected_threat'] = threat_name
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise ScanTimeout()

    def _run_full_scan(self, p):
        """This function will run a full scan on the device

        Keyword arguments
        p -- an instance of AndroPilot

        Return
        Nothing but will set result['detected_threat']
        """
        # unlock the phone
        p.press_menu()
        # Start main activity for AV
        p.start_activity('com.bitdefender.antivirus',
                         'com.bitdefender.antivirus.StartActivity')
        # Tap on the giant scan button
        p.refresh()
        if p.wait_for_activity(
                'com.bitdefender.antivirus.StartActivity',
                timeout=base.TIMEOUT,
                critical=False):
            p.tap_on_coordinates(120, 190)
            # Timeout for the scan
            # Since the AV will use in-the-cloud-scanning this timeout is
            # quite important
            p.refresh()
            if p.wait_for_activity('com.bitdefender.antivirus.ResultActivity',
                                   timeout=base.LONG_TIMEOUT*2,
                                   critical=False):
                threat_name = self._get_threat_name_from_view(p)
                # if threat name is not None we found something
                # else no threat was found
                if threat_name is not None:
                    self.result['detected_threat'] = threat_name
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                # If we get here the scan ran out of time
                # (this should not happen)
                # Try to adjust TIME_OUT
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise ScanTimeout()
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise ScanTimeout()

    def _get_threat_name_from_view(self, pilot):
        """This function will extract the threat name from the view.
        It will automatically refresh the tree node list.

        Keyword arguments
        p -- an instance of AndroPilot

        Return
        Str -- a string containing the threat Name
        None -- if the view was not present
        """
        pilot.refresh()
        threat_view = pilot.get_view_by_id('TextViewMalwareAppThreatName')
        if threat_view:
            return threat_view.mText.strip()
        return None

if __name__ == "__main__":
    import sys
    import logging
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    test = TestSuite("emulator-5554", 12345, 4939, "/tmp", "/tmp")

    if(len(sys.argv) < 3):
        print 'usage: %s test_type path_to_apk' % (sys.argv[0])
        print 'test_type : "install" or "copy" or "update"'
        sys.exit(-1)

    if sys.argv[1] == 'install':
        test.detection_on_install(sys.argv[2])
        print 'detected threat: ' + test.result['detected_threat']
    elif sys.argv[1] == 'copy':
        test.detection_on_copy(sys.argv[2])
        print 'detected threat: ' + test.result['detected_threat']
    else:
        test.updater()
        print test.result['executed']
