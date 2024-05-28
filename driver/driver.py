from abc import ABCMeta, abstractmethod

from base.view_base import View


class ActivityPackage:
    package = ""
    activity = ""

    def __init__(self, activity, package):
        self.package = package
        self.activity = activity

    def __str__(self) -> str:
        return f"package: {self.package}, activity: {self.activity}"

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, ActivityPackage):
            return self.package == __value.package and self.activity == __value.activity
        return False

    def __hash__(self) -> int:
        return hash((self.package, self.activity))


class Driver(metaclass=ABCMeta):
    driver = None

    @abstractmethod
    def get_driver(self):
        pass

    @abstractmethod
    def get_current_view(self, shuffle) -> View:
        pass

    @abstractmethod
    def get_curr_activity_package(self) -> ActivityPackage:
        pass

    @abstractmethod
    def tap(self, x, y):
        pass

    @abstractmethod
    def rollback(self):
        pass

    @abstractmethod
    def swipe_up(self, x, y, x1, y1, duration):
        pass
