import base64
import hashlib
import json
import os
import sys
from functools import partial
from html import unescape

import frida

from base.csv_info import get_ad_sdk_names
from tool.install_app import try_install

PACKAGE = None


def write_to_file(filename, data):
    global PACKAGE
    save_dir = "./res/webcontent/" + PACKAGE + "/"
    if os.path.exists(save_dir) == False:
        os.makedirs(save_dir)
    with open(save_dir + filename, "w", encoding="utf-8") as f:
        f.write(data)


def on_message(message, data, checks):
    if message["type"] == "send":
        payload = message["payload"]
        # print(payload)
        if "tag" in payload:
            if payload["tag"] == "webview_content":
                print(payload["url"])
                # md5 url
                md5hash = hashlib.md5(payload["value"].encode("utf-8"))
                md5 = md5hash.hexdigest()
                payload["value"] = payload["value"].encode().decode("unicode-escape")
                write_to_file(md5 + ".json", json.dumps(payload, ensure_ascii=False))
                decoded_bytes = base64.b64decode(payload["value"])
                decoded_str = json.loads(decoded_bytes.decode("utf-8"))
                if decoded_str:
                    write_to_file(md5 + ".html", decoded_str)

            if "stack" in payload["tag"]:
                # print(payload["stack"])
                if checks:
                    for check in checks:
                        if check in payload["stack"]:
                            print("[***] Find:", check)
            # if "activity" in payload["tag"]:
            #     print(payload["activity"])


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


if __name__ == "__main__":
    # PACKAGE = "com.ifmvo.togetherad.demo"
    # PACKAGE = "com.anythink.sdk.demo"
    PACKAGE = "com.meishu.meishu_sdk_demo"
    # PACKAGE = try_install("Ucapan_Selamat_Hari_Raya_1.4_Apkpure", True)
    # if PACKAGE is None:
    #     print("Failed to install APK.")
    #     sys.exit(-1)
    checks = get_ad_sdk_names()
    print(checks)
    hook_activity(PACKAGE, checks)
