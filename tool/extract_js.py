import json
import os

from bs4 import BeautifulSoup


def test():
    html = open(
        "/home/icespite_work/Work/Thesis/AutoClick/res/webcontent/com.shougang.shiftassistant/11b59686ce95bcbb1d5e3568a8eaafea.html",
        "r",
    ).read()

    js_objects = extract_js(html)
    print(js_objects)


def extract_js(html):
    soup = BeautifulSoup(html, "html.parser")
    script_tags = soup.find_all("script")

    js_objects = []
    for script_tag in script_tags:
        if script_tag.string:
            js_code = script_tag.string
            js_objects.append(js_code)

    return js_objects


def traverse_directory(directory):
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                all_files.append([file_path, file])
    return all_files


def main(source_dir, target_dir):
    filename_lists = traverse_directory(source_dir)
    for filelist in filename_lists:
        if not filelist[1].endswith(".html"):
            continue
        data = None
        with open(
            filelist[0],
            "r",
        ) as f:
            data = f.read()
        # print(data)
        js = extract_js(data)
        # print(js)

        # write to js
        print(filelist[1].split(".html"))
        target_dir_res = os.path.join(target_dir, filelist[1].split(".html")[0] + ".js")
        print(target_dir_res)
        with open(target_dir_res, "w") as f:
            f.write(
                "\n/**********************js抽取分界线********************************/\n".join(
                    js
                )
            )


if __name__ == "__main__":
    father_dir = "/home/icespite_work/Work/Thesis/AutoClick/res/webcontent"
    main(
        "/home/icespite_work/Work/Thesis/AutoClick/res/webcontent",
        "/home/icespite_work/Work/Thesis/data/frida_js",
    )
    # main("/home/icespite_work/Work/Thesis/data/extract_data_recover","/home/icespite_work/Work/Thesis/data/extract_js/")
    # test()
