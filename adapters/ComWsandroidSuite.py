import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        # Get an an instance of andropilot
        p = self.pilot
        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)

        p.press_menu()
        # start activity is
        # com.wsandroid.suite/com.mcafee.app.LauncherDelegateActivity
        # If a threat is found appears
        # com.wsandroid.suite/com.mcafee.vsmandroid.AlertDetails
        # Problem is that no threat's details are given even runnig a full scan
        # so we can only notify a found threat or not found
        if p.wait_for_activity('com.mcafee.vsmandroid.AlertDetails',
                               timeout=base.TIMEOUT,
                               critical=False):
            self.result['detected_threat'] = config.THREAT_FOUND
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        if self._go_to_security_scan(p):
            # Tap on 'Scan now' button
            p.tap_on_coordinates(130, 210)
            # Wait for summary activity to shows up.
            # This could take a long time,
            # no really, a long long time
            TIME_OUT = base.LONG_TIMEOUT*2
            # If this activity shows up the scan is over
            if p.wait_for_activity('com.mcafee.vsmandroid.OdsSummary',
                                   timeout=TIME_OUT,
                                   critical=False):
                p.refresh()
                # Get the alert view
                # if this view do not exist no threat has been found
                threat_view = p.get_view_by_id('id_alert_virus')
                if threat_view is not None:
                    # To extract the threat name a regex is used
                    # regex : a random number of chars (at least one)
                    # followed by a / and match a group of non space
                    # followed by a space and some other chars
                    import re
                    threat_name_groups = re.match(r'.+/([^\s]+)\s{1}.+',
                                                  threat_view.mText)
                    threat_name = threat_name_groups.group(1)

                    self.result['detected_threat'] = threat_name.strip()
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise base.ScanTimeout()

    def updater(self):
        import datetime
        # Get an an instance of andropilot
        p = self.pilot
        # set current date time
        current_time = datetime.datetime.now().strftime('%Y%m%d.%H%M%S')
        p.adb_command(['shell', 'date', '-s', current_time])
        if self._go_to_security_scan(p):
            # tap on 'Update'
            p.tap_on_coordinates(120, 260)
            p.refresh()
            # Now check if exist the view with updated.
            check_if_updated = lambda: (
                p.exist_view_by_id('id_update_last_check_date'))
            TIME_OUT = base.TIMEOUT
            if p.wait_for_custom_event(check_if_updated,
                                       timeout=TIME_OUT,
                                       refresh=True):
                # get the last update date
                date_view = p.get_view_by_id('id_update_last_check_date')
                if date_view is not None:
                    last_updated = date_view.mText.strip()
                    now = datetime.datetime.now().strftime('%-m/%-d/%Y')
                    # if is today consider the update executed
                    if last_updated == now:
                        self.result['executed'] = True
                        self.result['signature_date'] = datetime.datetime.now()
                        #Get the definition version
                        sdb_ver = p.get_view_by_id('id_update_sdb_ver')
                        if sdb_ver is not None:
                            self.result['signature_version'] = sdb_ver.mText
                        return

        self.result['executed'] = False
        self.result['signature_version'] = None
        self.result['signature_date'] = None


    def _go_to_security_scan(self, pilot):
        # Start AV
        pilot.press_menu()
        pilot.start_activity('com.wsandroid.suite',
                             'com.mcafee.app.LauncherDelegateActivity')
        # wait for main activity
        TIME_OUT = base.TIMEOUT
        if pilot.wait_for_activity('com.mcafee.app.MainActivity',
                                   timeout=TIME_OUT,
                                   critical=False):
            # Tap on 'Security scan' button
            pilot.tap_on_coordinates(130, 95)
            # Wait for the view to appear
            # It is not shown a new view so check for a text
            TIME_OUT = base.TIMEOUT
            pilot.refresh()
            if pilot.wait_for_text('Scan now',
                                   timeout=TIME_OUT):
                return True
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
        print "Updated: " + str(test.result['executed'])
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
