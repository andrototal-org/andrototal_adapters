import time
import base


class TestSuite(base.BaseTestSuite):

    def detection_on_demand(self, sample_path):
        p = self.pilot
        # install sample
        p.install_package(sample_path)

    def detection_on_install(self, sample_path):
        p = self.pilot
        # install sample
        p.install_package(sample_path)
        time.sleep(2)
