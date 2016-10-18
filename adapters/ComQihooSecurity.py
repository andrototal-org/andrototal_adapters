import time

import config
from base import BaseTestSuite, ScanTimeout
import base


class TestSuite(BaseTestSuite):

    def detection_on_install(self, sample_path):
        # Get an an instance of andropilot
        p = self.pilot
        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        # unlock the phone
        p.press_menu()

        # The av shows a popup if it found a threat
        # Get notificaiton manager from pilot
        notification = p.notification_manager
        # This function will check the end of the scan
        notification.open_notification_bar()

        def _check_scan_end():
            p.refresh()
            is_malware = p.exist_view_by_text(
                'is a malware', partial_matching=True)
            is_safe = p.exist_view_by_text(
                'is clean', partial_matching=True)
            return (is_safe or is_malware)

        if p.wait_for_custom_event(_check_scan_end, timeout=base.LONG_TIMEOUT):
            # press back to close the notification bar
            p.press_back()
            # Timeout is short because at this point the activiry should exist
            if p.wait_for_activity(
                    'com.qihoo.security.dialog.NewInstalledApkMalware',
                    timeout=base.SHORT_TIMEOUT,
                    critical=False):
                self.result['detected_threat'] = config.THREAT_FOUND
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            raise ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the phone
        p.press_menu()
        # Start the main activity
        #
        p.start_activity('com.qihoo.security',
                         'com.qihoo.security.AppEnterActivity')

        # This activity shows up when ready to scan
        if p.wait_for_activity('com.qihoo.security.ui.malware.MalwareActivity',
                               timeout=base.TIMEOUT,
                               critical=False):
            time.sleep(5)
            # Open the menu with the 'Full scan' button
            p.monkey_controller.swipe_left()
            time.sleep(2)
            # Tap on 'Full scan button'
            p.tap_on_coordinates(120, 140)
            # This view will show up when the scan is over
            exist_threat = 'malware_threat_number'
            # Or if no threat is found exists a view with this text
            #'Warning'
            scan_finished = lambda: (p.exist_view_by_id(exist_threat) or
                                     p.exist_view_by_text('Warning'))

            p.refresh()
            # Wait the scan to finish
            if p.wait_for_custom_event(scan_finished,
                                       timeout=base.TIMEOUT,
                                       refresh=True):
                p.refresh()
                # Close the popup message
                if p.exist_view_by_text('Warning'):
                    p.tap_on_coordinates(120, 270)
                    time.sleep(2)
                    p.refresh()
                threat_number_view = p.get_view_by_id('number_view_text')
                # The av detects 2 valid system apks as threats
                # but it also report the number of threats found
                # so if we have 2 or more threats we found something
                existing_threat = 2
                if int(threat_number_view.mText) > existing_threat:
                    self.result['detected_threat'] = config.THREAT_FOUND
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                self.result['detected_threat'] = config.SCAN_TIMEOUT
                raise base.ScanTimeout()
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise base.ScanTimeout()

    def updater(self):
        # Get an an instance of andropilot
        p = self.pilot
        # unlock the phone
        p.press_menu()
        # Start the main activity
        #
        p.start_activity('com.qihoo.security',
                         'com.qihoo.security.AppEnterActivity')
        TIME_OUT = base.TIMEOUT
        # This activity shows up when ready to scan
        if p.wait_for_activity('com.qihoo.security.ui.malware.MalwareActivity',
                               timeout=TIME_OUT,
                               critical=False):
            time.sleep(5)
            # start the update activity
            p.start_activity('com.qihoo.security',
                             'com.qihoo.security.ui.net.CheckUpdateDialog')

            # this activity will popup when the update is finished
            if p.wait_for_activity('com.qihoo.security.ui.net.UpdatedDialog',
                                   timeout=base.TIMEOUT,
                                   critical=False):
            # Dialog_message_textview
                time.sleep(2)
                p.refresh()
                # Just to be sure lets check the text in the update
                # dialog
                update_text = 'Antivirus database updated!'
                if p.exist_view_by_text(update_text):
                    self.result['executed'] = True
                else:
                    self.result['executed'] = False
            else:
                self.result['executed'] = False
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
    test = TestSuite("emulator-5554", 12345, 4939, "/tmp", "/tmp")

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
