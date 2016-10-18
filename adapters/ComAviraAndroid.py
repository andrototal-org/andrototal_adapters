from time import sleep
import datetime
import config
from base import BaseTestSuite, ScanTimeout
import base


class TestSuite(BaseTestSuite):

    def detection_on_install(self, sample_path):

        self.result['detected_threat'] = None
        # Get an an instance of andropilot
        p = self.pilot
        # If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        # unlock the phone
        p.press_menu()
        # If a threat is detected should exist a view with text:
        # 'Problem detected!'
        # Notification Manager is need to open the notification bar
        # because the AV do not give popups but gives only a notification

        notification = p.notification_manager

        def check_result():
            notification.refresh()
            is_malware = notification.get_notifications_by_title(
                'Problem detected!')
            is_safe = notification.get_notifications_by_title('safe')

            if is_safe:
                self.result['detected_threat'] = config.NO_THREAT_FOUND

            return (is_malware or is_safe)

        notification.open_notification_bar()
        if p.wait_for_custom_event(
                check_result,
                timeout=base.LONG_TIMEOUT,
                refresh=False):
            notification.open_notification_bar()
            sleep(1)  # give some more time...
            p.tap_on_coordinates(140, 60)
            if self.result['detected_threat'] == config.NO_THREAT_FOUND:
                return
            else:
                p.tap_on_coordinates(140, 60)
                # Wait to give malwareList time to appear
                threat_name = self._extract_threat_name_from_view(p)
                self.result['detected_threat'] = threat_name
        else:
            raise ScanTimeout()

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        # unlock the phone
        p.press_menu()
        p.start_activity('com.avira.android',
                         'com.avira.android.dashboard.DashboardActivity')
        # Check that the activity is fully started

        p.refresh()
        if p.wait_for_activity(
                'com.avira.android.dashboard.DashboardActivity',
                timeout=base.TIMEOUT,
                critical=False):
            # Tap Antivirus button
            p.tap_on_coordinates(130, 190)
            # Wait for antivirus activity to show
            p.refresh()
            if p.wait_for_activity(
                    'com.avira.android.antivirus.AntivirusOEActivity',
                    timeout=base.TIMEOUT,
                    critical=False):
                # Tap on Scan
                p.tap_on_coordinates(120, 260)

                # If a threat is found exists a view with name 'problemCount'
                p.refresh()
                # Wait for the end of the scan
                if p.wait_for_custom_event(
                        lambda: (p.exist_view_by_id('problemCount')),
                        timeout=base.LONG_TIMEOUT,
                        refresh=True):
                    # Tap on Fix problem(s)
                    p.tap_on_coordinates(130, 40)
                    p.refresh()
                    if p.wait_for_activity(
                            'com.avira.android.antivirus.OEScanResultActivity',
                            timeout=base.LONG_TIMEOUT,
                            critical=False):
                        # tap on Threat details
                        p.tap_on_coordinates(130, 110)
                        p.refresh()
                        if p.wait_for_custom_event(
                                lambda: (p.exist_view_by_id('scanResultList')),
                                timeout=base.LONG_TIMEOUT,
                                refresh=True):
                            threat_name = self._extract_threat_name_from_view(
                                p)

                            self.result['detected_threat'] = threat_name
                        else:
                            raise ScanTimeout()
                    else:
                        raise ScanTimeout()
                else:
                    self.result['detected_threat'] = config.NO_THREAT_FOUND
            else:
                raise ScanTimeout()
        else:
            raise ScanTimeout()

    def updater(self):
        p = self.pilot
        p.press_menu()
        p.start_activity('com.avira.android',
                         'com.avira.android.dashboard.DashboardActivity')
        # Check that the activity is fully started
        TIME_OUT = base.LONG_TIMEOUT*2
        p.refresh()
        if p.wait_for_activity(
                'com.avira.android.dashboard.DashboardActivity',
                timeout=TIME_OUT,
                critical=False):
            # Tap Antivirus button
            p.tap_on_coordinates(130, 190)
            # Wait for antivirus activity to show
            p.refresh()
            if p.wait_for_activity(
                    'com.avira.android.antivirus.AntivirusOEActivity',
                    timeout=TIME_OUT,
                    critical=False):
                # Get the version text
                p.refresh()
                vdf_text = p.get_view_by_id('vdfVersion')
                # If is none something bad appened
                if vdf_text is None:

                    raise ScanTimeout()
                # Else set all
                else:
                    self.result = {
                        'signature_version': vdf_text.mText,
                        'signature_updated_at': datetime.datetime.now(),
                        'executed': True
                    }
            else:
                raise ScanTimeout()
        else:
            raise ScanTimeout()

    def _extract_threat_name_from_view(self, pilot):

        def _get_result():
            # Get the malware view
            malware_view = pilot.get_view_by_id('malwareList')

            if not malware_view:
                return False

            if malware_view is not None:
                malware_full_text = malware_view.mText
                # Extract the threat name
                import re
                malware_name_group = re.match(r'.+"(.+)".*', malware_full_text)
                malware_name = malware_name_group.group(1)
                return malware_name
            else:
                # We should not arrive there
                # Just in case of any stange error
                return config.THREAT_FOUND

        result = pilot.wait_for_custom_event(
            _get_result,
            timeout=base.TIMEOUT,
            refresh=True)

        if not result:
            result = config.THREAT_FOUND

        return result


if __name__ == "__main__":

    import sys
    import logging
    # Set the logger
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    # Start an instance of this TestSuite
    test = TestSuite("emulator-5554", 12345, 4939, "/tmp", "/tmp")

    # If update method
    if len(sys.argv) == 2 and sys.argv[1] == 'update':
        test.updater()
        print "Updated: " + str(test.result['executed'])
        print "Version: " + str(test.result['signature_version'])
        print "Date: " + str(test.result['signature_date'])

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

    print 'Detected threat: ' + test.result['detected_threat']
