from functools import partial

import frida

from base.auto_click import *
from base.csv_info import get_ad_sdk_names
from base.watchdog import WatchDog
from driver.driver_uiautomator2 import DriverUIAutomator2
from parse.parse_element_tree import (
    ParseAdElementTree,
    ParseClickElementTree,
    ParseClickSwitchFirstElementTree,
    ParseFactoryElementTree,
    ParseImageElementTree,
    ParseSwipeElementTree,
)

CHECKS = get_ad_sdk_names()


def on_message(message, data, auto, watchdog):
    global CHECKS
    if message["type"] == "send":
        payload = message["payload"]
        print(payload)
        if "tag" in payload:
            tag = payload["tag"]
            if tag == "activity" or tag == "fragment" or tag == "xfragment":
                auto.change_view_with_watchdog("frida-fake-name")
                print("frida end")
                watchdog.update_end_time()

        if "stack" in payload["tag"]:
            for check in CHECKS:
                if check in payload["stack"]:
                    print("[***] Find:", check)
                    auto.ad_view_num += 1


def hook_activity(package, auto, watchdog):
    dev = frida.get_remote_device()
    pid = dev.spawn(package)
    with open("./js/hook_activity.js", encoding="utf-8") as f:
        jscode = f.read()
    session = dev.attach(pid)
    script = session.create_script(jscode, runtime="v8")
    script.on("message", partial(on_message, auto=auto, watchdog=watchdog))
    print("[*] Running Script...")
    script.load()
    dev.resume(pid)
    while watchdog.is_alive():
        time.sleep(5)
    print("*" * 30)
    print("watchdog is dead")
    watchdog.show()
    auto.performance()


def main_many(packages):
    for package in packages:
        parse_factorys = [
            ParseFactoryElementTree(
                [
                    ParseAdElementTree(),
                    ParseSwipeElementTree(20),
                    ParseClickSwitchFirstElementTree(2400),
                ]
            ),  # Page switching priority
            ParseFactoryElementTree(
                [
                    ParseSwipeElementTree(50),
                    ParseAdElementTree(),
                    ParseClickElementTree(),
                ]
            ),  # Advertising Priority
            ParseFactoryElementTree(
                [
                    ParseClickElementTree(),
                    ParseSwipeElementTree(),
                    ParseImageElementTree(50),
                ]
            ),  # maddroid
        ]
        for parse_factory in parse_factorys:
            watchdog = WatchDog("hook_activity_test", 120)
            driver = DriverUIAutomator2("273a2ba8", parse_factory)
            auto = Auto(driver, package, watchdog)
            hook_activity(package, auto, watchdog)


if __name__ == "__main__":
    main_many(
        [
            "com.mayt.recognThings.app",
            # "com.snda.wifilocating",
            # "com.smzdm.client.android",
        ]
    )
