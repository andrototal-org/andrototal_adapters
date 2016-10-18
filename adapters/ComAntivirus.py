import config
import datetime
from base import BaseTestSuite, ScanTimeout
import base

from time import sleep


class TestSuite(BaseTestSuite):

    def detection_on_install(self, sample_path):
        # Get an an instance of andropilot
        p = self.pilot
        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        # We get activity com.antivirus/.ui.scan.UnInstall
        # on infection but no clue about the infection...
        # And even the main window gives no clue
        # So we can infer that the apk is a threat
        p.press_menu()

        self.result['detected_threat'] = config.NO_THREAT_FOUND

        # really long timeout... no other way to catch...
        if p.wait_for_activity('com.antivirus.ui.scan.UnInstall',
                               timeout=base.TIMEOUT,
                               critical=False):

            self.result['detected_threat'] = config.THREAT_FOUND

        return

        # not working trying to get data to validate no threat found info
        if False:
            TIME_OUT = base.TIMEOUT
            # disable completely this is not working we need a different way...
            # Check if the scan was run
            # Start main activity com.antivirus/.ui.main.HandheldMainActivity
            p.start_activity('com.antivirus',
                             'com.antivirus.ui.main.HandheldMainActivity')
            # Wait for Main Activity to show up
            if p.wait_for_activity(
                    'com.antivirus.ui.main.HandheldMainActivity',
                    timeout=TIME_OUT,
                    critical=False):
                # This view contain the date of the last scan
                p.refresh()
                last_scan = p.get_view_by_id('scanResultsTextView')
                if last_scan is None:
                    # This should not happen
                    raise ScanTimeout()

                last_scan_date_text = last_scan.mText[11:].strip()
                last_scan_date = datetime.datetime.strptime(
                    last_scan_date_text,
                    '%b %d, %Y').date()
                now = datetime.datetime.now().date()
                print 'current date: %s, last scan date: %s' % (
                             now, last_scan_date)
                if last_scan_date == now:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    raise ScanTimeout()


    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # If we are not able to reach the protection activity
        # abort
        if not self._go_to_protection_activity(p):
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise ScanTimeout()
        # Push 'scan now'
        p.refresh()
        p.tap_on_coordinates(180, 125)
        end_scan_checker = lambda: (
            p.exist_view_by_text('Threats found!')
            or p.exist_view_by_text("You're protected!")
        )
        # Wait for result screen
        p.refresh()
        if p.wait_for_custom_event(
                end_scan_checker,
                timeout=base.LONG_TIMEOUT,
                refresh=True):

            # check the results message
            if p.exist_view_by_text('Threats found!'):
                self.result['detected_threat'] = config.THREAT_FOUND
            elif p.exist_view_by_text("You're protected!"):
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                # Someting strange appened since this branch should never be
                # used
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise ScanTimeout()
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise ScanTimeout()

    def updater(self):
        # Get an an instance of andropilot
        p = self.pilot
        self._go_to_protection_activity(p)
        # tap on 'Update Now'
        p.refresh()
        p.tap_on_coordinates(150, 250)

        def _wait_event():
            return(
                p.exist_view_by_text(
                    'You have the latest update installed.')
                or (not p.exist_view_by_text('Updating database'))
            )

        if p.wait_for_custom_event(
                _wait_event,
                timeout=base.LONG_TIMEOUT,
                refresh=True):
            # Close the informativa popup
            p.tap_on_coordinates(120, 220)

        p.refresh()
        version_view = p.get_view_by_text('Version')
        # If version_view is none try to get again it
        if version_view is None:
            sleep(5)
            p.refresh()
            version_view = p.get_view_by_text('Version')
        # Version Text
        # Remove the initial 'Version ' text
        if version_view:
            ver_t = version_view.mText[8:].strip()
        else:
            # if we aren't able to get the version
            # we need a way to know there's something fishy
            # going on, raise a Scan Timeout
            raise ScanTimeout()

        self.result['signature_version'] = ver_t
        self.result['signature_updated_at'] = datetime.datetime.now()
        self.result['executed'] = True

    def _go_to_protection_activity(self, pilot):
        """This is an helper method used to call ProtectionActivity.

        Keyword arguments
        pilot --  An instance of Andropilot

        Return
        True -- if it success to reach the activity
        False -- if any error occurs
        """
        pilot.press_menu()
        # Start main activity com.antivirus/.ui.main.HandheldMainActivity
        pilot.start_activity(
            'com.antivirus',
            'com.antivirus.ui.main.HandheldMainActivity')

        TIME_OUT = base.TIMEOUT
        # Wait for Main Activity to show up
        if pilot.wait_for_activity(
                'com.antivirus.ui.main.HandheldMainActivity',
                timeout=TIME_OUT,
                critical=False):
            # Push 'Protection' btn
            pilot.tap_on_coordinates(65, 105)

            TIME_OUT = base.TIMEOUT
            # Wait for protection activity to show up
            if pilot.wait_for_activity(
                    'com.antivirus.ui.protection.ProtectionActivity',
                    timeout=TIME_OUT,
                    critical=False):
                return True
            else:
                return False
        else:
            return False

if __name__ == "__main__":
    import sys

    import logging
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    test = TestSuite("emulator-5554", 12345, 4939, "/tmp", "/tmp")

    if len(sys.argv) == 2 and sys.argv[1] == 'update':
        test.updater()
        print 'Updated: ' + str(test.result['executed'])
        print "Version: " + str(test.result['signature_version'])
        print "Date: " + str(test.result['signature_date'])
        sys.exit(0)

    elif len(sys.argv) < 3:
        print 'usage: python %s test_type path_to_apk' % (sys.argv[0])
        print 'test_type : "install" or "copy" or "update"'
        print 'With "update" you can omit path_to_apk'
        sys.exit(-1)

    if sys.argv[1] == 'install':
        test.detection_on_install(sys.argv[2])
    elif sys.argv[1] == 'copy':
        test.detection_on_copy(sys.argv[2])
    else:
        print 'test_type not valid. Aborting'
        sys.exit(-1)

    print 'Vairus: ' + test.result['detected_threat']
