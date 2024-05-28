from extract_js import traverse_directory
from recover_html import read_files
from urlextract import URLExtract

extractor = URLExtract()


all_urls = []
# filenames = read_files("/home/icespite_work/Work/Thesis/data/extract_data/")
# for filename in filenames:
#     print(filename)
filename_lists = traverse_directory(
    "/home/icespite_work/Work/Thesis/AutoClick/res/webcontent"
)
for filelist in filename_lists:
    if not filelist[1].endswith(".json"):
        continue
    with open(
        filelist[0],
        "r",
    ) as f:
        data = f.read()
        urls = extractor.find_urls(data, with_schema_only=True)
        all_urls.extend(urls)
with open(
    r"/home/icespite_work/Work/Thesis/data/all_info.csv",
    "r",
) as f:
    data = f.read()
    urls = extractor.find_urls(data, with_schema_only=True)
    all_urls.extend(urls)

all_urls = list(set(all_urls))
print(all_urls)

from adblockparser import AdblockRules

raw_rules = []
row_files = read_files("/home/icespite_work/Work/Thesis/ExtractData/data/filterlist")
for row_file in row_files:
    with open(
        r"/home/icespite_work/Work/Thesis/ExtractData/data/filterlist/" + row_file,
        "r",
    ) as f:
        listOfLines = f.readlines()
        for line in listOfLines:
            data = line.strip()
            raw_rules.append(data)
# print(raw_rules)
rules = AdblockRules(raw_rules)
print(rules.should_block("https://ads.google.com/"))
blocked_num = 0
for url in all_urls:
    if rules.should_block(url):
        blocked_num += 1
print("urls_num:", len(all_urls))
print("blocked_num:", blocked_num)
print("blocked_rate:", blocked_num / len(all_urls))
