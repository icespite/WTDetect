import time

import uiautomator2 as u2

from base.operation_base import ParseFactory
from base.view_base import View
from driver.driver import ActivityPackage, Driver


class DriverUIAutomator2(Driver):
    def __init__(self, adb_name, parse_factory: ParseFactory):
        self.parse_factory = parse_factory
        self.driver = u2.connect(adb_name)

    def get_driver(self):
        return self.driver

    def get_current_view(self, shuffle=False):
        while True:
            try:
                xml = self.driver.dump_hierarchy()
                view = View(xml)
                view.parseSource(self.parse_factory, shuffle)
                return view
            except Exception as e:
                time.sleep(2)

    def get_curr_activity_package(self):
        info = self.driver.app_current()
        return ActivityPackage(info["activity"], info["package"])

    def tap(self, x, y):
        self.driver.click(x, y)

    def rollback(self):
        self.driver.press("back")

    def swipe_up(self, x, y, x1, y1, duration=0.5):
        self.driver.swipe(x, y, x1, y1, duration)
