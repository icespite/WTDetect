import json
import os


def cover_by_json(filename):
    try:
        data = None
        with open(
            r"/home/icespite_work/Work/Thesis/data/extract_data/" + filename,
            "r",
        ) as f:
            data = f.read()
        data = data.replace("\\u003\n", "")
        data = data.replace("\\\\\n", "\\\\")
        data = data.replace("\\\n\\", "\\\\")
        data = data.replace('\\\n"', '\\"')
        data = data.replace('\n"', '\\"')
        data = data.replace("\\\n", '\\"')  # 关键，注释与否会导致不同结果
        data = data.replace("\n", "")
        data = '{"html":' + data + "}"
        s = json.loads(data)
        with open(
            "/home/icespite_work/Work/Thesis/data/extract_data_recover/" + filename,
            "w",
        ) as f:
            f.write(s["html"])
    except Exception as e:
        print(filename, e)


def read_files(father_path):
    # father_path =

    files = os.listdir(father_path)
    s = []
    for file in files:
        if not os.path.isdir(file):
            s.append(file)
    print(s)
    return s


def main():
    filenames = read_files("/home/icespite_work/Work/Thesis/data/extract_data/")
    for filename in filenames:
        cover_by_json(filename)


if __name__ == "__main__":
    main()
