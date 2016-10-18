import time

import config
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_install(self, sample_path):
        #Get an an instance of andropilot
        p = self.pilot
        #If sample is passed, install it
        if sample_path:
            p.install_package(sample_path)
        #unlock the phone
        p.press_menu()
        pass

    def detection_on_copy(self, sample_path):
        p = self.pilot
        if sample_path:
            # install sample
            p.push_file(sample_path)
        #unlock the phone
        p.press_menu()
        pass

    def updater(self):
        #Get an an instance of andropilot
        p = self.pilot
        #unlock the phone
        p.press_menu()
        pass

if __name__ == "__main__":

    import sys
    import logging
    #Set the logger
    logger = logging.getLogger('andropilot')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    #Star an instance of this TestSuite
    test = TestSuite("emulator-5554", 12345, 4939)

    #If update method
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
