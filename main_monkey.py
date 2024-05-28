import json
import re
import subprocess
from datetime import datetime

from driver.driver import ActivityPackage


class Monkey:
    def __init__(self, package_name, num_events):
        self.package_name = package_name
        self.num_events = num_events

        self.activity_packages = set()

    def run_monkey_test(self):
        command = f"adb shell monkey -p {self.package_name} -v-v-v --throttle  1500  {self.num_events}"  #  --ignore-crashes --ignore-timeouts
        path = "./res/monkey/"
        current_time = datetime.now()
        formatted_time = current_time.strftime("_%Y-%m-%d@%H:%M:%S")
        output_text_file = path + self.package_name + formatted_time + ".txt"
        with open(output_text_file, "w") as f:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            for line in process.stdout:
                print(line, end="")
                tmp = self.getActivityAndPackage(line)
                if len(tmp) > 0:
                    tmp = tmp[0]
                    self.add_activity_package(ActivityPackage(tmp[1], tmp[2]))
                f.write(line)
            process.wait()

        output_json_file = path + self.package_name + formatted_time + ".json"
        json_res = {
            "package_name": self.package_name,
            "num_events": self.num_events,
            "activitys": [str(act) for act in self.activity_packages],
        }
        with open(output_json_file, "w") as f:
            json.dump(json_res, f)

    def getActivityAndPackage(self, content):
        pattern = r"Allowing start of Intent \{ cmp=(\S+)/(\S+) \} in package (\S+)"
        matches = re.findall(pattern, content)
        return matches

    def add_activity_package(self, activity_package: ActivityPackage):
        self.activity_packages.add(activity_package)

    def show_activity_packages(self):
        for act in self.activity_packages:
            print(act)


def many_app():
    packages = [
        "com.mayt.recognThings.app",
        "com.snda.wifilocating",
    ]
    num_events = 50
    for package in packages:
        monkey = Monkey(package, num_events)
        monkey.run_monkey_test()


if __name__ == "__main__":
    many_app()
