import codecs
import csv
import os
from typing import List


class ApkINFO:
    def __init__(
        self,
        sha256,
        base_dir,
        dataset=None,
        package_name=None,
        is_adware=None,
        sdk_names=None,
        min_sdk=None,
        target_sdk=None,
        compile_sdk=None,
    ):
        self.sha256 = sha256
        self.dataset = dataset
        self.package_name = package_name
        self.is_adware = is_adware
        self.sdk_names = sdk_names
        self.min_sdk = min_sdk
        self.target_sdk = target_sdk
        self.compile_sdk = compile_sdk

        if self.sha256.endswith(".apk") == False:
            self.sha256 = self.sha256 + ".apk"

        self.path = os.path.join(base_dir, self.sha256)

    def __eq__(self, other):
        return self.sha256 == other.sha256

    def __hash__(self):
        return hash(self.sha256)

    def dump_to_csv(self, writer):
        writer.writerow(
            [
                self.dataset,
                self.sha256,
                self.package_name,
                1 if self.is_adware else 0,
                # ";".join(self.sdk_names),
                self.sdk_names,
                self.min_sdk,
                self.target_sdk,
                self.compile_sdk,
            ]
        )

    def is_equal(self, other):
        return self.sha256 == other.sha256 or self.package_name == other.package_name


def remove_apk_info_duplication(apk_info_list):
    unique_list = list(set(apk_info_list))
    unique_res_list = []
    seen_package_name = set()

    for obj in unique_list:
        if obj.package_name not in seen_package_name:
            unique_res_list.append(obj)
            seen_package_name.add(obj.package_name)

    return unique_res_list


def get_ad_sdk_names():
    res = []
    with codecs.open(
        "/home/icespite_work/Work/Thesis/data/AD_Network_info.csv", encoding="utf-8-sig"
    ) as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            res.append(row["SDK_name"])
    f.close()
    return list(set(res))


def get_googleplay_apk_names():
    res = []
    with codecs.open(
        "/run/media/icespite_work/Expansion/apk/googleplay/gp_drop_list.csv",
        encoding="utf-8-sig",
    ) as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            res.append(
                ApkINFO(
                    dataset="google-play",
                    base_dir="/run/media/icespite_work/Expansion/apk/new/",
                    sha256=row["sha256"],
                )
            )
    f.close()
    return list(set(res))


def get_adware_apk_names():
    res = []
    with codecs.open(
        "/storage/Thesis/Data/adware_apks.csv",
        encoding="utf-8-sig",
    ) as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            res.append(
                ApkINFO(
                    dataset="adware",
                    base_dir="/storage/Thesis/Data/",
                    sha256=row["sha256"],
                )
            )
    f.close()
    return list(set(res))


def get_appchina_apk_names():
    res = []
    with codecs.open(
        "/storage/Thesis/Data/appchina_apks.csv",
        encoding="utf-8-sig",
    ) as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            res.append(
                ApkINFO(
                    dataset="appchina",
                    base_dir="/storage/Thesis/Data/",
                    sha256=row["sha256"],
                    sdk_names=row["andetect_ad"],
                )
            )
    f.close()
    return list(set(res))


def remove_A_from_B(A: List[ApkINFO], B: List[ApkINFO]):
    res = []
    for b in B:
        if not any([a.is_equal(b) for a in A]):
            res.append(b)
    return res


if __name__ == "__main__":
    a = []
    a.append(ApkINFO("123", package_name="12a3"))
    a.append(
        ApkINFO("12a3", package_name="12a3"),
    )
    b = remove_apk_info_duplication(a)
    print(b)
