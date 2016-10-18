import time

import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        # Get an an instance of andropilot
        p = self.pilot
        nm = p.notification_manager

        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        # Wait for popup activity
        p.press_menu()

        self.sample_malicious = False
        self.sample_ok = False

        def _wait_event():
            self.sample_ok = bool(p.get_view_by_text(
                    'is certified', partial_matching=True))

            self.sample_malicious = (
                p.get_view_by_text(
                    'is malicious', partial_matching=True
                ) or p.get_view_by_text(
                    'Security Analysis', partial_matching=True
                ))

            nm.open_notification_bar()
            return (self.sample_malicious or self.sample_ok)

        nm.open_notification_bar()
        if p.wait_for_custom_event(
                _wait_event,
                timeout=base.LONG_TIMEOUT, refresh=True):

            if self.sample_ok:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
                return

            if self.sample_malicious:
                p.press_back()
                self._extract_threat_details(p)
                return

            # should not get here something wrong happened
            raise base.ScanTimeout()
        # No activity no threat
        else:
            raise base.ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the device
        p.press_menu()
        # Star the main activity
        p.start_activity('com.trustgo.mobile.security',
                         'com.trustgo.mobile.security.SecurityMainActivity')
        # Tap on 'Security Scanner' button
        time.sleep(2)
        p.tap_on_coordinates(135, 135)

        # If someting bad and even not
        # ScanResultBadActivity shows up
        if p.wait_for_activity(
                'com.trustgo.mobile.security.ScanResultBadActivity',
                timeout=base.LONG_TIMEOUT,
                critical=False):
            time.sleep(8)
            # If exist the view 'scan_bad_hint'
            # a threat has been found
            # No information about the threat is given
            # so we can set only THREAT_FOUND or NO_THREAT_FOUND
            p.refresh()
            if p.wait_for_custom_event(
                    p.exist_view_by_id('scan_bad_hint'),
                    timeout=base.LONG_TIMEOUT, refresh=True):
                # Tap on threat name to get datails
                p.tap_on_coordinates(120, 190)
                self._extract_threat_details(p)

            elif p.wait_for_custom_event(
                    p.exist_view_by_id('scan_ok_hint'),
                    timeout=base.LONG_TIMEOUT, refresh=True):
                self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                # We should not reach this branch. If this happen
                # I cannot tell if a threat is found or not
                raise base.ScanTimeout()
        else:
            raise base.ScanTimeout()

    def updater(self):
        # Get an an instance of andropilot
        p = self.pilot
        # unlock the device
        p.press_menu()
        # Star the main activity
        p.start_activity('com.trustgo.mobile.security',
                         'com.trustgo.mobile.security.SecurityMainActivity')
        # Wait to show a view
        time.sleep(5)
        # Press menu button to show the update menu
        p.press_menu()
        time.sleep(2)
        # press Update
        p.tap_on_coordinates(190, 230)
        # The update message should be
        # You have the latest version.
        check_for_update = lambda: (
            p.exist_view_by_text('Connection Failed') or
            p.exist_view_by_text('You have the latest version.'))

        p.refresh()
        # In my test almost always the update fails
        # Maybe is my connection
        if p.wait_for_custom_event(check_for_update,
                                   timeout=base.LONG_TIMEOUT,
                                   refresh=True):
            if p.exist_view_by_text('Connection Failed'):
                self.result['executed'] = False
            elif p.exist_view_by_text('You have the latest version.'):
                self.result['executed'] = True
        else:
            self.result['executed'] = False

    def _extract_threat_details(self, p):

        self.result['detected_threat'] = config.THREAT_FOUND

        if p.wait_for_text(
                'Security Analysis'):

            # Tap on 'Details' button
            p.tap_on_coordinates(180, 220)
            # Wait for the activity with datails
            # get the view with the threat details

            def _check():
                return (p.exist_view_by_text('Security Scan')
                        or p.exist_view_by_id('app_security_name'))

            # We have to wait until the view shows up
            p.wait_for_custom_event(_check,
                                    timeout=base.TIMEOUT,
                                    refresh=True)
            threat_view = p.get_view_by_id('app_security_name')
            if threat_view is not None:
                threat_name = threat_view.mText
                # here some regex
                self.result['detected_threat'] = threat_name.strip()


if __name__ == "__main__":
    import sys
    import logging
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    test = TestSuite("emulator-5554", 12345, 4939, '/tmp/l_tmp', '/tmp/s_tmp')

    if len(sys.argv) == 2 and sys.argv[1] == 'update':
        test.updater()
        print "Updated: " + str(test.result['executed'])
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
