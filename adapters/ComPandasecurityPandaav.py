import time

import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        # Get an an instance of andropilot
        p = self.pilot
        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        # unlock the phone
        p.press_menu()
        # If a threat is found com.pandasecurity.pandaav.DialogFragmentActivity
        # should appear
        TIME_OUT = 60
        if p.wait_for_activity(
                'com.pandasecurity.pandaav.DialogFragmentActivity',
                timeout=TIME_OUT,
                critical=False):
            # get the threat name
            p.refresh()
            view = p.get_view_by_id('messageText')
            if view is not None:
                # Extract the threat name from the threat text
                import re
                threat_groups = re.match(r'[^/]+/([^\s]+).*', view.mText)
                threat_name = threat_groups.group(1)
                self.result['detected_threat'] = threat_name.strip()
            else:
                # Should not appen but just in case
                self.result['detected_threat'] = config.THREAT_FOUND
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the phone
        p.press_menu()
        # Start main activity
        p.start_activity('com.pandasecurity.pandaav',
                         'com.pandasecurity.pandaav.MainActivity')
        # And wait for the welcome Screen
        if p.wait_for_activity('com.pandasecurity.pandaav.WelcomeActivity',
                               critical=False):
            time.sleep(5)
            # Tap on Continue
            p.tap_on_coordinates(125, 310)
            time.sleep(10)
            # Start the scan
            p.tap_on_coordinates(125, 125)
            # If no threat found text 'System clean' is present
            # else text 'Threats' is present
            threats_found = lambda: (p.exist_view_by_text('Threats') or
                                     p.exist_view_by_text('System clean'))
            # Scan can take up to 15 minutes
            TIME_OUT = 15 * 60
            p.refresh()
            if p.wait_for_custom_event(threats_found,
                                       timeout=TIME_OUT,
                                       refresh=True):
                # If this view exist a threat is found
                if p.exist_view_by_text('Threats'):
                    # Tap on datails
                    # This part is very slow
                    time.sleep(5)
                    p.tap_on_coordinates(125, 280)
                    # sleep 5 second to ensure that the view is up
                    time.sleep(5)
                    p.refresh()
                    threat_view = p.get_view_by_id('DetectionName')
                    if threat_view is not None:
                        import re
                        threat_groups = re.match(r'[^/]+/([^\s]+).*',
                                                 threat_view.mText)
                        threat_name = threat_groups.group(1)
                        self.result['detected_threat'] = threat_name.strip()

                    else:
                        # Just in case...
                        self.result['detected_threat'] = config.THREAT_FOUND
                # If this view exist no threat is found
                elif p.exist_view_by_text('System clean'):
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
                else:
                    # Something really weird happened
                    # This branch should never be reached
                    self.result['detected_threat'] = config.SCAN_TIMEOUT
                    raise base.ScanTimeout()
            else:
                # We went time out
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()
        else:
            # main program didn't start
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise base.ScanTimeout()

    def updater(self):
        p = self.pilot
        # Get the current timestamp
        command = 'shell date +%s'
        now = p.adb_command(command.split(), need_result=True)
        # HACK
        # p.close(), will close monkeycontroller and viewserver
        # If not closed the next call to detection_on_copy will starve
        # but since 'detection_on_copy' will open again the two controllers
        # they will be available after it returns
        p.close()
        # Call detection_on_copy with a None params to let it scan the system
        self.detection_on_copy(None)
        # Get the config file with the timestamp and store it to temp file
        panda_config = ('/data/data/com.pandasecurity.pandaav/shared_prefs/' +
                        'com.pandasecurity.pandaav.xml')
        update_string_grep = 'com.pandasecurity.pandaav.lastupdatetime'
        # Command is  cat 'config_file'|grep 'updatetime_line'
        command = "shell cat %s | grep %s" % (panda_config, update_string_grep)
        # get the line with the update timestamp
        updated = p.adb_command(command.split(), need_result=True)
        import re
        # The timestamp contains millisecond
        # so \d{10} will take only the first ten digit of the timestamp
        # ignoring milliseconds
        last_update = re.match(r'<[^>]+>(\d{10}).*', updated.strip()).group(1)
        if int(now) < int(last_update):
            self.result['executed'] = True
        else:
            self.result['executed'] = False

if __name__ == "__main__":

    import sys
    import logging
    # Set the logger
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    # Star an instance of this TestSuite
    test = TestSuite("emulator-5554", 12345, 4939)

    # If update method
    if len(sys.argv) == 2 and sys.argv[1] == 'update':
        test.updater()
        print "Updated: " + str(test.result['executed'])
        sys.exit(0)

    # if not update but the number of params is wrong
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
