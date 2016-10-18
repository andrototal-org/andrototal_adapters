import time

import config
from base import BaseTestSuite, ScanTimeout, TIMEOUT
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
        # Wait for dialog activity to appear
        if p.wait_for_activity(
                'com.comodo.pimsecure_lib.ui.activity.ShowDialogActivity',
                timeout=TIMEOUT,
                critical=False):
            time.sleep(2)
            # Get the view with threat name
            p.refresh()
            threat_view = p.get_view_by_id('item_type_name')
            if threat_view is not None:
                threat_name = threat_view.mText.strip()
                self.result['detected_threat'] = threat_name
            else:
                self.result['detected_threat'] = config.THREAT_FOUND

        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND
        pass

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the phone
        p.press_menu()
        # Start main activity
        if self._go_to_antivirus_activity(p):
            # Tap on Full scan
            p.tap_on_coordinates(130, 190)
            # This view shows up when the scan is completed
            scan_finished = lambda: (
                p.exist_view_by_id('id_virus_main_finish_scan_uplayout_title'))

            p.refresh()
            # Full scan can be painful slow
            # so a proper timeout is needed
            if p.wait_for_custom_event(scan_finished,
                                       timeout=base.LONG_TIMEOUT,
                                       refresh=True):
                p.refresh()
                # If a threat is found 'Dangerous' should exist
                # as string in the threat report
                if p.exist_view_by_text('Dangerous',
                                        partial_matching=True):
                    # No threat details are given, so we can infer
                    # if there is a treat or not
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
        if not self._go_to_antivirus_activity(p):
            raise ScanTimeout()
        # Tap on update button
        p.tap_on_coordinates(130, 240)
        # If an update is available there will be a dialog with the text:
        # New Version Available
        update_present = lambda: (
            p.exist_view_by_text('New Version Available'))
        p.refresh()
        if p.wait_for_custom_event(update_present,
                                   timeout=base.TIMEOUT,
                                   refresh=True):
            # Tap on Yes
            # to start the update
            p.tap_on_coordinates(75, 215)

            # When the update is finished this text will be present
            #'Last updated time: 0 mins ago'
            update_finished = lambda: (
                p.exist_view_by_text('Last updated time: 0 mins ago'))
            p.refresh()
            if p.wait_for_custom_event(update_finished,
                                       timeout=base.TIMEOUT,
                                       refresh=True):
                self.result['executed'] = True
            else:
                self.result['executed'] = False
        else:
            self.result['executed'] = False

    def _go_to_antivirus_activity(self, p):
        p.start_activity(
            'com.comodo.pimsecure',
            'com.comodo.pimsecure_lib.ui.activity.SplashActivity')
        if p.wait_for_activity(
                'com.comodo.pimsecure_lib.ui.activity.HomeActivity',
                timeout=TIMEOUT,
                critical=False):
            #Sometimes commodo ask for update
            update_CMS_text = 'Updates are available for CMS.'
            #if exists close it
            p.refresh()
            #Check if the update CMS message is shown and in this case
            #close it
            if p.wait_for_text(update_CMS_text, timeout=TIMEOUT):
                p.tap_on_coordinates(170, 214)
            #Also it ask to update database randomly
            update_VDB_text = 'Updates are available for Virus'
            p.refresh()
            #Check if the update Virus DB message is shown and in this case
            #close it
            if p.wait_for_text(update_VDB_text, timeout=TIMEOUT):
                p.tap_on_coordinates(170, 214)
            #wait until we are back to HomeActivity

            wait_for_home_activity = lambda: (
                'HomeActivity' in p.get_focus_activity())

            p.refresh()
            #If we not come back in time return false
            if not p.wait_for_custom_event(wait_for_home_activity,
                                           timeout=TIMEOUT,
                                           refresh=True):
                return False
            # tap on Antivirus
            p.tap_on_coordinates(60, 220)

            #Wait for activity to start
            if p.wait_for_activity(
                    'com.comodo.pimsecure_lib.virus.core.activity.VirusMainActivity',
                    timeout=TIMEOUT,
                    critical=False):
                return True
            else:
                return False
        else:
            return False

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
