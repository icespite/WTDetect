from appium import webdriver
from appium.options.common.base import AppiumOptions

from base.operation_base import ParseFactory
from base.view_base import View


class DriverAppium(Driver):
    def __init__(self, parse_factory: ParseFactory):
        self.parse_factory = parse_factory
        options = AppiumOptions()
        options.load_capabilities(
            {
                "platformName": "Android",
                "appium:automationName": "UiAutomator2",
                "appium:ensureWebviewsHavePages": True,
                "appium:nativeWebScreenshot": True,
                "appium:newCommandTimeout": 3600,
                "appium:connectHardwareKeyboard": True,
            }
        )
        self.driver = webdriver.Remote("http://127.0.0.1:4723", options=options)

    def get_driver(self):
        return self.driver

    def get_current_view(self, shuffle=False):
        view = View(self.driver.page_source)
        view.parseSource(self.parse_factory, shuffle)
        return view

    def get_curr_activity_package(self):
        return self.driver.current_activity

    def tap(self, x, y):
        self.driver.tap([(x, y)])

    def rollback(self):
        self.driver.back()

    def swipe_up(self, x, y, x1, y1, duration):
        self.driver.swipe(x, y, x1, y1, duration)

    def is_cur_app(self, package):
        activity = self.driver.get_curr_activity()
        if activity[0] != ".":
            return False
        return True
