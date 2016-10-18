import logging
import sys
import unittest


def import_module(name):
    mod = __import__(name)
    components = name.split('.')
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


class TestAdapter(unittest.TestCase):
    def setUp(self):
        rl = logging.getLogger()
        rl.setLevel(logging.DEBUG)

    def test_on_install(self):
        test_module = import_module(adapter_name)
        test = test_module.TestSuite("emulator-5554", 12345, 4939)
        print test.detection_methods
        result = test.detection_on_install(None)
        self.assertEqual(result['detected_threat'], 'NO_THREAT_FOUND')

    # def test_on_copy(self):
    #     test_module = import_module(adapter_name)
    #     test = test_module.TestSuite("emulator-5554", 12345, 4939)
    #     test.on_copy_detection(None)


if __name__ == "__main__":
    adapter_name = sys.argv[1]
    del sys.argv[1:]
    unittest.main()

    #test_module = import_module(sys.argv[1])
    #test = test_module.TestSuite("emulator-5554", 12345, 4939)

    #test.on_install_detection(None)
    #test.on_install_detection("/Users/andrea/Desktop/android_malware/21450.apk")
    #test.on_copy_detection(None)
    #test.on_copy_detection("/Users/andrea/Desktop/android_malware/21450.apk")
    #test.updater()
