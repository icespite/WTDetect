import os
import subprocess


def get_all_packages():
    cmd = ["adb", "shell", "pm", "list", "packages"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    packages = []
    for line in result.stdout.split("\n"):
        if line.startswith("package:"):
            package_name = line.split(":")[1]
            packages.append(package_name)
    return packages


def install_apk_via_adb(apk_path):
    cmd = ["adb", "install", apk_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("APK installed successfully.")
        return 1
    else:
        print("Failed to install APK:", result.stderr)
        return -1


def get_apk_package_name(apk_path):
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.split("\n"):
            if line.startswith("package:"):
                package_name = line.split(" ")[1].split("=")[1].strip("'")
                return package_name
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
    return None


def try_install(apk_name, skip_install_if_exist=False):
    path1 = "/run/media/icespite_work/Caviar_s移动硬盘0/APPCHINA/" + apk_name + ".apk"
    path2 = "/run/media/icespite_work/Caviar_s移动硬盘0/Adware/" + apk_name + ".apk"
    path3 = "/run/media/icespite_work/Expansion/apk/new/" + apk_name + ".apk"
    path4 = (
        "/run/media/icespite_work/Caviar_s固态/download_appchina/APK/"
        + apk_name
        + ".apk"
    )
    path5 = (
        "/run/media/icespite_work/Caviar_s固态/download_gp/APP2/" + apk_name + ".apk"
    )

    paths = [path1, path2, path3, path4, path5]

    for path in paths:
        if os.path.exists(path) == False:
            continue

        if skip_install_if_exist:
            exist_packages = get_all_packages()
            package = get_apk_package_name(path)
            if package in exist_packages:
                print("Skip install. Package already exists.")
                print("Package name:", package)
                return package
        try:
            res = install_apk_via_adb(path)
            if res == -1:
                continue
            package = get_apk_package_name(path)
            print("Package name:", package)
            if package is not None:
                return package
        except Exception as e:
            pass


if __name__ == "__main__":
    # try_install("03C7E669BBEADFB4AEB2B46E5822677A5A0C3E4ACD7C454C13C5635FB05191E3")
    print(get_all_packages())
