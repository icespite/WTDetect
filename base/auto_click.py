import json
import os
import signal
import sys
import time
from datetime import datetime

from base.operation_base import *
from base.view_base import *
from driver.driver import Driver


class ExecTool:
    def __init__(self, driver, Operation: Operation):
        self.driver = driver
        self.operation = Operation

    def rollback(self):
        self.driver.rollback()

    def tap(self):
        self.driver.tap(*self.operation.point.coord)

    def swipe_up(self):
        middle_x, middle_y = self.operation.point.coord
        sx = middle_x
        sy = (
            self.operation.point.bounds[3] * 0.95
            if self.operation.point.bounds[3] * 0.95 > middle_y
            else middle_y
        )
        ex = sx
        ey = self.operation.point.bounds[1]
        print("sx, sy, ex, ey", sx, sy, ex, ey)
        self.driver.swipe_up(sx, sy, ex, ey)

    def exec(self):
        self.operation.num += 1
        print("executing operation", self.operation)
        if self.operation.operation_type == SingleOperation.CLICK:
            self.tap()
        elif self.operation.operation_type == SingleOperation.ROLLBACK:
            self.rollback()
        elif self.operation.operation_type == SingleOperation.SWIPE_UP:
            self.swipe_up()


class Auto:
    def __init__(self, driver: Driver, package, watchdog):
        self.views_map = {}
        self.view_names_history = ["fake-start"]
        self.currt_view = None
        self.package = package
        self.watch_dog = watchdog

        self.tap_num = 0
        self.rollback_num = 0
        self.view_num = 0
        self.swipe_up_num = 0
        self.ad_view_num = 0
        self.activity_packages = set()
        self.driver = driver

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        print("\nSignal Catched! You have just type Ctrl+C! ")
        self.performance()
        sys.exit(0)

    def exec_operation(self, operation: Operation):
        if operation.operation_type == SingleOperation.CLICK:
            self.tap_num += 1
        elif operation.operation_type == SingleOperation.ROLLBACK:
            self.rollback_num += 1
        elif operation.operation_type == SingleOperation.SWIPE_UP:
            self.swipe_up_num += 1
        ExecTool(self.driver, operation).exec()

    def change_view_with_watchdog(self, before_name):
        self.watch_dog.update_last_time()
        if self.watch_dog.is_alive() == False:
            return
        time.sleep(1.5)
        activity_package = self.driver.get_curr_activity_package()
        if activity_package.activity == "co.aospa.launcher.ParanoidLauncher":
            return

        if activity_package not in self.activity_packages:
            self.activity_packages.add(activity_package)

        if activity_package.package != self.package:
            self.exec_operation(Operation(SingleOperation.ROLLBACK, None))
            self.change_view_with_watchdog("fake-name")
            return

        # 获取当前view
        real_curr_view = self.driver.get_current_view(shuffle=False)
        real_curr_view.activity_name = activity_package.activity

        if self.view_names_history[-1] == real_curr_view.name:
            realname = real_curr_view.name
            self.views_map[realname].continue_visit += 1
            if self.views_map[realname].continue_visit > 17:
                self.views_map[realname].cur = len(self.views_map[realname].operations)
                self.exec_operation(Operation(SingleOperation.ROLLBACK, None))
                if self.views_map[realname].continue_visit > 9:
                    if self.views_map[realname].back_operation_pointer:
                        self.exec_operation(
                            self.views_map[realname].back_operation_pointer
                        )
                    else:
                        self.exec_operation(Operation(SingleOperation.ROLLBACK, None))

                self.change_view_with_watchdog("fake-rollback")
                return
        else:
            if self.view_names_history[-1] in self.views_map:
                self.views_map[self.view_names_history[-1]].continue_visit = 0
            self.view_names_history.append(real_curr_view.name)

        if before_name != real_curr_view.name:
            if real_curr_view.name not in self.views_map:
                self.views_map[real_curr_view.name] = real_curr_view
                self.currt_view = real_curr_view

            else:
                if self.views_map[real_curr_view.name].back == False:
                    last_name = self.view_names_history[-2]
                    print("上一个view：", last_name, end=" ")
                    if last_name in self.views_map:
                        self.views_map[last_name].back = True
                        self.views_map[last_name].back_operation_pointer = (
                            self.views_map[last_name].operations[
                                self.views_map[last_name].cur - 1
                            ]
                        )
                    # if random.choice([True, False]):
                    if False:
                        self.views_map[real_curr_view.name].cur -= 1
                self.views_map[real_curr_view.name].back = False
                self.currt_view = self.views_map[real_curr_view.name]
        next_operation = self.currt_view.getNextOperation()
        while next_operation is not None and next_operation.num >= 3:
            next_operation = self.currt_view.getNextOperation()
        for i in range(self.currt_view.cur, len(self.currt_view.operations)):
            print(self.currt_view.operations[i])
        print("next_operation: ", next_operation)
        if next_operation is None:
            self.exec_operation(Operation(SingleOperation.ROLLBACK, None))
            return
        self.exec_operation(next_operation)
        # time.sleep(2)
        self.change_view_with_watchdog(real_curr_view.name)

    def performance(self):
        self.view_num = len(self.views_map)
        res = (
            {
                "package_name": self.package,
                "tap_num": self.tap_num,
                "rollback_num": self.rollback_num,
                "swipe_up_num": self.swipe_up_num,
                "view_num": self.view_num,
                "ad_view_num": self.ad_view_num,
                "tap_num + rollback_num + swipe_up_num": self.tap_num
                + self.rollback_num
                + self.swipe_up_num,
                "effective": self.ad_view_num / (self.tap_num + self.rollback_num),
                "views": [view.getPerformanceStr() for view in self.views_map.values()],
                "activitys": [str(act) for act in self.activity_packages],
            },
        )
        print(res)
        path = os.path.join(
            os.path.dirname(__file__), "../res/autoclick/" + self.package + "/"
        )
        if not os.path.exists(path):
            os.makedirs(path)
        current_time = datetime.now()
        formatted_time = current_time.strftime("_%Y-%m-%d@%H:%M:%S")
        with open(path + formatted_time + ".json", "w") as f:
            json.dump(res, f, ensure_ascii=False)
