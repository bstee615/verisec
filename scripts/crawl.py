from pathlib import Path
import re
import json
import validators
import wget
import subprocess
import shutil

bug_id_regex = re.compile(r'(CVE|CA|BID)-[0-9-+]*')
id_regex = re.compile(rf'-= ({bug_id_regex.pattern}) =-')

def parse(readme):
    lines = readme.open().readlines()
    li = iter(lines)
    id_match = id_regex.match(next(li))
    # print(readme)
    while not id_match:
        id_match = id_regex.match(next(li))
    id = id_match.group(1)
    # print(id)
    vv_regex = re.compile(r'Vulnerable version(?:s)?:(.*)$')
    file_regex = re.compile(r'File(?:\(s\))?:(.*)$')
    link_regex = re.compile(r'Download from:(.*)$')

    # Match to vv header
    p = next(li)
    vv_match = vv_regex.match(p)
    while not (vv_match):
        p = next(li)
        vv_match = vv_regex.match(p)
    vv = []
    first_vv = vv_match.group(1).strip()
    if first_vv:
        vv.append(first_vv)

    # Match to files header and log vulnerable versions
    p = next(li)
    file_match = file_regex.match(p)
    while not file_match:
        vv.append(p.strip())
        p = next(li)
        file_match = file_regex.match(p)
    files = []
    firstfile = file_match.group(1).strip()
    if firstfile:
        files.append(firstfile)

    # Match to download from header and log files
    p = next(li)
    while not p.startswith('Download from:'):
        files.append(p.strip())
        p = next(li)
    
    downloadfrom_match = link_regex.match(p)
    while not downloadfrom_match:
        p = next(li)
        downloadfrom_match = link_regex.match(p)
    if downloadfrom_match.group(1):
        downloadfrom = downloadfrom_match.group(1).strip()
    else:
        downloadfrom = next(li).strip()
    if not downloadfrom:
        downloadfrom = None
    if not validators.url(downloadfrom):
        print('Invalid link', downloadfrom)
        downloadfrom = None

    return {
        "readme": str(readme),
        "program": readme.parent.parent.name,
        "id": id,
        "vulnerable_versions": vv,
        "files": files,
        "downloadfrom": downloadfrom,
    }


def print_bug(b):
    def clean(s):
        if isinstance(s, list):
            return ', '.join(s)
        else:
            return str(s)
    print('\t'.join(clean(f) for f in b.values()))


def setup_bug(repos_root, bug):
    assert repos_root.is_dir()
    program_root = repos_root / bug["program"]
    program_root.mkdir(exist_ok=True)
    bug_root = program_root / bug["id"]
    bug_root.mkdir(exist_ok=True)
    assert bug_root.is_dir()
    bug["root"] = bug_root


def dl_bug(bug):
    if bug["downloadfrom"] is None:
        raise Exception(f'no link for {bug["program"]} {bug["id"]}')
    else:
        bug["archive"] = bug["root"] / bug["downloadfrom"].split('/')[-1]
        if bug["archive"].is_file():
            print('Already downloaded')
        else:
            wget.download(bug["downloadfrom"], out=str(bug["archive"]))
            print()


def unpack_bug(bug):
    if bug["archive"].is_file():
        if any('gz' in s for s in bug["archive"].suffixes):
            subprocess.check_call(f'tar zxf {bug["archive"]} -C {bug["root"]}'.split())
        elif bug["archive"].name == 'download':
            subprocess.check_call(f'tar jxf {bug["archive"]} -C {bug["root"]}'.split())
        else:
            raise Exception(f"Couldn't handle file {bug['archive']}")
    else:
        print('File', bug["archive"], 'is not downloaded')


if __name__ == '__main__':
    bug_readmes = list(p for p in Path('programs/apps').glob('**/README') if bug_id_regex.match(p.parent.name))
    bugs = []
    repos = Path('programs/repos')
    errored_rm = []
    for rm in bug_readmes:
        try:
            bug = parse(rm)
            bugs.append(bug)
        except Exception as e:
            print(e)
            errored_rm.append(rm)

    with open('manifest.json', 'w') as f:
        json.dump(bugs, f, indent=4, sort_keys=True)
    
    succeeded_bugs = []
    errored_bugs = []
    for b in bugs:
        try:
            print_bug(b)
            setup_bug(repos, b)
            dl_bug(b)
            succeeded_bugs.append(b)
        except Exception as e:
            print(e)
            errored_bugs.append((b, e))
    print('Could not download:')
    for b, e in errored_bugs:
        print(b["program"], b["id"], b["downloadfrom"], e)
        shutil.rmtree(b["root"])
        if not any(b["root"].parent.iterdir()):
            shutil.rmtree(b["root"].parent)
    
    errored_bugs = []
    for b in succeeded_bugs:
        try:
            unpack_bug(b)
        except Exception as e:
            print(e)
            errored_bugs.append((b, e))
    print('Could not unpack:')
    for b, e in errored_bugs:
        print(b["program"], b["id"], b["archive"], e)
