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
        # Unlock the device
        # if the device is locked the popup will show
        # but will not be detected
        p.press_menu()
        threat_name = self.__check_popup(p)
        if threat_name is not None:
            self.result['detected_threat'] = threat_name
        else:
            self.result['detected_threat'] = config.NO_THREAT_FOUND

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the phone
        p.press_menu()
        # Star the main activity for the AV
        p.start_activity('com.eset.ems2.gp', 'com.eset.ems2.gui.MainActivity')
        # Wait 2 seconds until activity starts
        p.wait_for_activity('com.eset.ems2.gui.MainActivity')
        time.sleep(2)
        # Tap on 'Antivirus' button
        p.tap_on_coordinates(70, 170)
        # Need to refresh the tree node list
        p.refresh()
        # And wait until the antivirus page is shown
        # It's used wait_for_text() and not time.wait()
        # because it's more reliable and consistent
        p.wait_for_text('Antivirus')
        # Tap on Scan Device
        p.tap_on_coordinates(125, 100)
        # Wait scan to finish
        p.refresh()
        if p.wait_for_text("Scan finished"):
            # We have found something
            # 'found_threats_label' exists only if a threat is found
            if p.exist_view_by_id('found_threats_label'):
                threat_name = self.__get_threat_name_from_view(
                    p, 'threat_name')
                self.result['detected_threat'] = threat_name
            else:
                self.result['detected_threat'] = config.NO_THREAT_FOUND
        else:
            self.result['detected_threat'] = config.SCAN_TIMEOUT
            raise base.ScanTimeout()

    def updater(self):
        """This method update the AV database.

        Return
        True -- If the AV's database was successfully updated
        False -- If any error (even timeout) occurs
        """
        p = self.pilot
        p.press_menu()
        # Star the main activity for the AV
        p.start_activity('com.eset.ems2.gp', 'com.eset.ems2.gui.MainActivity')
        # Wait 2 seconds until activity starts
        time.sleep(2)
        # Tap on 'Antivirus' button
        p.tap_on_coordinates(70, 170)
        # Need to refresh the tree node list
        p.refresh()
        # And wait until the antivirus page is shown
        # It's used wait_for_text() and not time.wait()
        # because it's more reliable and consistent
        p.wait_for_text('Antivirus')
        # I know i'm a bad guy, but using internal implementation
        # was the only way to reach the update button
        p.monkey_controller.swipe_up()
        p.tap_on_coordinates(120, 250)
        # Wait until the view refresh
        # and is shown the message 'Version: something (up-to-date)
        # It's easier to check only if '(up-to-date)' appears
        check_message_update = lambda: (
            p.exist_view_by_text('(up-to-date)'))
        p.refresh()
        # The update could take a long time
        # No, really, sometimes it takes up to 4 minutes
        if p.wait_for_custom_event(
                check_message_update, timeout=base.LONG_TIMEOUT, refresh=True):
            self.result['executed'] = True
        else:
            self.result['executed'] = False

    def __check_popup(self, pilot):
        """This function will check the presence of the AV's threat alert
        and return the threat name. The popup is shown only on installation
        of a new apk.

        Keyword arguments
        pilot -- an instance of andropilot

        Return
        Str -- containing the threat name if a threat is found
        None -- if no threat is found
        """
        # The Av should start automatically and show a pop is it finds a virus
        # So wait the popup
        # if pilot.wait_for_activity('com.eset.ems2.gui.DialogActivity',
        #                           timeout=base.TIMEOUT,
        #                           critical=False):
        if pilot.wait_for_text('Threat Found'):
            # If the popup exits extract the threat text
            return self.__get_threat_name_from_view(pilot, 'threat_name')
        return None

    def __get_threat_name_from_view(self, pilot, mid):
        """Simple helper used to extract from a view
        the threat name. It uses regex.

        Keyword arguments
        pilot -- an instance of andropilot
        mid -- the id of the view to get

        Return:
        Str -- containing the threat name
        None -- if the unable to extract the threat name
        """
        threat_view = pilot.get_view_by_id(mid)
        if threat_view is not None:
            threat_text = threat_view.mText.strip()
            # extract the threat name
            import re
            threat_name = re.sub(r"Threat: ", '', threat_text)
            return threat_name
        return None


if __name__ == "__main__":
    import sys
    import logging
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    test = TestSuite("emulator-5554", 12345, 4939)

    if(len(sys.argv) < 3):
        print 'usage: %s test_type path_to_apk' % (sys.argv[0])
        print 'test_type : "install" or "copy" or "update"'
        sys.exit(-1)

    if sys.argv[1] == 'install':
        test.detection_on_install(sys.argv[2])
        print 'Vairus: ' + test.result['detected_threat']
    elif sys.argv[1] == 'copy':
        test.detection_on_copy(sys.argv[2])
        print 'Vairus: ' + test.result['detected_threat']
    else:
        test.updater()
        print test.result['executed']
