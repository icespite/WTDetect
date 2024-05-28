import hashlib
import json
import signal
import sys
from functools import partial
from html import unescape

import frida
from androguard.misc import AnalyzeAPK

from base.csv_info import get_ad_sdk_names
from tool.install_app import get_apk_package_name, install_apk_via_adb
from tool.unistall_app import main_uninstall


def on_message(message, data, checks):
    if message["type"] == "send":
        payload = message["payload"]
        # print(payload)
        if "tag" in payload:
            if "stack" in payload["tag"]:
                # print(payload["stack"])
                if checks:
                    for check in checks:
                        if check in payload["stack"]:
                            print("[***] Find:", check)
                            # break
            # if "activity" in payload["tag"]:
            #     print(payload["activity"])


def hook_usb(package):
    process = frida.get_usb_device().attach(package)
    with open("./js/hook_activity.js", encoding="utf-8") as f:
        jscode = f.read()
    script = process.create_script(jscode)
    script.on("message", on_message)
    print("[*] Running USB")
    script.load()
    sys.stdin.read()


def hook_activity(package, checks=None):
    dev = frida.get_remote_device()
    pid = dev.spawn(package)
    with open("./js/hook_activity.js", encoding="utf-8") as f:
        jscode = f.read()
    session = dev.attach(pid)
    script = session.create_script(jscode, runtime="v8")
    script.on("message", partial(on_message, checks=checks))
    print("[*] Running Script...")
    script.load()
    dev.resume(pid)
    sys.stdin.read()


def get_apk_package_with_analysis(apk_path, checks):
    apk, d, dx = AnalyzeAPK(apk_path)
    package = apk.get_package()
    activities = apk.get_activities()
    print("activities", activities)
    print("checks:", checks)
    for activity in activities:
        for check in checks:
            if check in activity:
                print("Find:", check)
    print("min sdk: ", apk.get_min_sdk_version())
    print("target sdk: ", apk.get_target_sdk_version())
    # print("max sdk: ", apk.get_max_sdk_version())
    # print("effective sdk: ", apk.get_effective_target_sdk_version())
    return package


def exit_(signum, frame):
    main_uninstall()
    exit()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_)
    signal.signal(signal.SIGTERM, exit_)

    # path = (
    #     "/run/media/icespite_work/Caviar_s移动硬盘0/APPCHINA/"
    #     + "0DCF7AFF9F6026E58017B567500C49D3B21C978D40937100E4A8AAEE44E8C77F.apk"
    # )
    # path = (
    #     "/run/media/icespite_work/Caviar_s移动硬盘0/Adware/"
    #     + "0EDFFB0DD75679EDDDD7CCC64F588857E72C83F43A3A9B3F7D76868B675B7C49.apk"
    # )
    path = (
        "/run/media/icespite_work/Expansion/apk/new/"
        + "A56A45FBA78F4E785593F747E6FE9A7F3BFF7A94EAF1D08428D67959629C538F.apk"
    )

    install_apk_via_adb(path)
    package = get_apk_package_name(path)
    # package = get_apk_package_with_analysis(path, checks=get_sdk_names())
    checks = get_ad_sdk_names()
    print("-> package:", package)
    hook_activity(package, checks=checks)
