import csv
import gc
import os
import subprocess
import time
from multiprocessing import Lock, Manager, Pool

from androguard.misc import AnalyzeAPK, get_default_session

from base.csv_info import (
    ApkINFO,
    get_ad_sdk_names,
    get_appchina_apk_names,
    get_googleplay_apk_names,
    remove_apk_info_duplication,
)

SAVE_FILE = "appchina_check_apks.csv"


def check_apk_sdk_with_androguard(
    apk_info: ApkINFO, checks, lock, ckeck_min_sdk=False, force_save=False
):
    global SAVE_FILE
    path = apk_info.path
    if not os.path.exists(path):
        print("File not found:", path)
        return
    apk, _, _ = AnalyzeAPK(path, session=None)
    apk_info.package = apk.get_package()
    activities = apk.get_activities()
    apk_info.min_sdk = apk.get_min_sdk_version()
    apk_info.target_sdk = apk.get_target_sdk_version()
    if ckeck_min_sdk:
        if apk_info.min_sdk <= 20:
            return
    flag = False
    sdks = set()
    for activity in activities:
        for check in checks:
            if check in activity:
                flag = True
                sdks.add(check)
    apk_info.sdk_names = ",".join(sdks)
    gc.collect()
    lock.acquire()
    try:
        with open(SAVE_FILE, "a", encoding="utf-8") as f:
            writer = csv.writer(f)
            if flag or force_save:
                print("save")
                apk_info.dump_to_csv(writer)
    finally:
        lock.release()


def check_apk_sdk_with_aapt(
    apk_info: ApkINFO, checks, lock, res, ckeck_min_sdk=False, force_save=False
):
    global SAVE_FILE
    path = apk_info.path
    print("path:", path)
    if not os.path.exists(path):
        print("File not found:", path)
        return

    result = subprocess.run(
        ["aapt", "dump", "badging", path], capture_output=True, text=True
    )
    output = result.stdout
    for line in output.split("\n"):
        if line.startswith("package:"):
            apk_info.package_name = line.split("name=")[1].split("'")[1]
            if "compileSdkVersion=" in line:
                apk_info.compile_sdk = line.split("compileSdkVersion=")[1].split("'")[1]
        elif "sdkVersion:" in line:
            apk_info.min_sdk = line.split("sdkVersion:")[1].strip("'")
        elif "targetSdkVersion:" in line:
            apk_info.target_sdk = line.split("targetSdkVersion:")[1].strip("'")
    lock.acquire()
    try:
        # with open(SAVE_FILE, "a", encoding="utf-8") as f:
        #     writer = csv.writer(f)
        #     apk_info.dump_to_csv(writer)
        res.append(apk_info)
    finally:
        lock.release()


def main_check_sdks(ckeck_min_sdk=False, force_save=False):
    global SAVE_FILE, res, lock
    apks = get_googleplay_apk_names()
    print("len:", len(apks))
    print(apks)
    checks = get_ad_sdk_names()
    manager = Manager()
    lock = manager.Lock()

    # 写入CSV文件头
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Dataset",
                "APK",
                "Package",
                "Flag",
                "SDKs",
                "Min SDK",
                "Target SDK",
                "Compile SDK",
            ]
        )
    process_count = 20
    res = manager.list()
    with Pool(processes=process_count) as pool:
        for apk in apks:
            pool.apply_async(
                check_apk_sdk_with_aapt,
                args=(apk, checks, lock, res, ckeck_min_sdk, force_save),
            )
        pool.close()
        pool.join()

    # for apk in apks:
    #     check_apk_sdk_with_aapt(apk, checks, lock, ckeck_min_sdk, force_save)
    # time.sleep(10)

    print("len:", len(res))
    res_list = remove_apk_info_duplication(res)
    print("len:", len(res_list))
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        writer = csv.writer(f)
        for apk in res_list:
            apk.dump_to_csv(writer)


if __name__ == "__main__":
    main_check_sdks(ckeck_min_sdk=False, force_save=True)
