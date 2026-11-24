import csv
import hashlib
import sys
from datetime import datetime
from pathlib import Path
def hashes_check(v):#check if the hash is a SHA-256
    if len(v) != 64:
        return False
    for chara in v:
        if chara not in "0123456789abcdef":
            return False
    return True

def njoin(n):#make the names list into one string
    text = ""
    for name in n:
        if text != "":
            text = text + ", "
        text = text + name
    return text

def hashes_dwnl(csv_path):#load the hashes into a dictionary
    ref = {}
    warn = []
    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as file:#read the whole file first, check it after
            reader = csv.DictReader(file)
            col = reader.fieldnames
            rows = list(reader)
    except FileNotFoundError:#so it doesnt crash
        warn.append("Reference file '" + str(csv_path) + "' not found - all files will be UNKNOWN.")
        return ref, warn

    if col is None or "sha256" not in col:
        warn.append("Reference file '" + str(csv_path) + "' has no 'sha256' column - all files will be UNKNOWN.")
        return ref, warn

    for line_number, row in enumerate(rows, start=2):
        hash_value = (row.get("sha256") or "").strip().lower()#lowerscase and no spaces
        if hashes_check(hash_value):
            ref[hash_value] = (row.get("label") or "").strip()
        else:
            warn.append("Reference line " + str(line_number) + ": '" + hash_value[:20] + "' is not a valid SHA-256 hash - row skipped.")
    return ref, warn
def hashcalc(path):#calculate the hash
    sha256 = hashlib.sha256()
    with open(path, "rb") as file:
        while True:
            chunk = file.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def fileinfo(path, folder): #get all the data tied to the file
    details = {"file": str(path.relative_to(folder)), "extension": path.suffix.lower(),
               "size_bytes": None, "modified": None, "sha256": None, "error": None}
    try:
        info = path.stat()
        details["size_bytes"] = info.st_size
        details["modified"] = datetime.fromtimestamp(info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        details["sha256"] = hashcalc(path)
    except PermissionError:#so it doesnt crash
        details["error"] = "Permission denied"
    except OSError:
        details["error"] = "Could not read file"
    return details

def dupecheck(res):#checks for duplicates in results
    groups = {}
    for r in res:
        if r["sha256"]:
            if r["sha256"] not in groups:
                groups[r["sha256"]] = []
            groups[r["sha256"]].append(r["file"])

    dupes = {}
    for file_hash in groups:
        if len(groups[file_hash]) > 1:
            dupes[file_hash] = groups[file_hash]
    return dupes
def file_type(r, ref, dupes):#give the file its classification
    if r["error"]:
        r["status"] = "ERROR"
        r["note"] = "Coudn't be read so it hasn't been checked."
    elif r["sha256"] in ref:
        r["status"] = "KNOWN"
        r["note"] = "Hash is the same as reference sample '" + ref[r["sha256"]] + "'."
    else:
        r["status"] = "UNKNOWN"
        r["note"] = "No reference match. Doesn't mean it's malicious. Investigate further."

    if r["sha256"] in dupes:
        twins = []
        for name in dupes[r["sha256"]]:
            if name != r["file"]:
                twins.append(name)
        r["note"] = r["note"] + " Same content as: " + njoin(twins) + "."

def report(res, dupes, warn):#build the report as a list
    lines = ["HOW TO READ THIS REPORT","  - KNOWN - hash is the same as in the reference sample.", "  - UNKNOWN - doesn't match the reference sample.","  - ERROR - couldn't be run",""]

    if warn:
        lines.append("WARNINGS")
        for warning in warn:
            lines.append("  ! " + warning)
        lines.append("")

    known = []#sort the files into three lists
    unknown = []
    error = []
    for r in res:
        if r["status"] == "KNOWN":
            known.append(r)
        elif r["status"] == "UNKNOWN":
            unknown.append(r)
        else:
            error.append(r)

    lines.append("SUMMARY")
    lines.append("  Files analysed     : " + str(len(res)))
    lines.append("  KNOWN              : " + str(len(known)))
    lines.append("  UNKNOWN            : " + str(len(unknown)))
    lines.append("  ERROR              : " + str(len(error)))
    lines.append("  Duplicate groups   : " + str(len(dupes)))
    for file_hash, names in dupes.items():
        lines.append("    - " + njoin(names)+ " - hash: " +file_hash)
    lines.append("")

    lines.append("FILES (unknown first)")
    for r in unknown + error + known:#unknown first
        lines.append("  " + r["file"])
        lines.append("      Status    : " + r["status"])
        lines.append("      Extension : " + r["extension"] + "   Size: " + str(r["size_bytes"]) + " bytes   Modified: " + str(r["modified"]))
        lines.append("      SHA-256   : " + (r["sha256"] or "-"))
        if r["error"]:
            lines.append("      Error     : " + r["error"])
        lines.append("      Note      : " + r["note"])
    return lines

def save_reports(lines, res):#make a csv and txt
    output = Path("reports")
    output.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = output / ("triage_report_" + stamp + ".txt")
    csv_path = output / ("triage_report_" + stamp + ".csv")

    with open(txt_path, "w", encoding="utf-8") as file:
        for line in lines:
            file.write(line + "\n")

    rows = [["status", "file", "extension", "size_bytes", "modified", "sha256", "note", "error"]]#build the rows first, then write them
    for r in res:
        rows.append([r["status"], r["file"], r["extension"], r["size_bytes"], r["modified"], r["sha256"], r["note"], r["error"]])

    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        csv.writer(file).writerows(rows)
    return txt_path, csv_path
def main():
    folder = Path('samples')
    ref_path = Path("hashes_reference.csv")
    if len(sys.argv) > 1:
        folder = Path(sys.argv[1])
    if len(sys.argv) > 2:
        ref_path = Path(sys.argv[2])

    if not folder.is_dir():
        print("ERROR: folder '" + str(folder) + "' does not exist or is not a folder. Check the path and try again.")
        return

    ref, warn = hashes_dwnl(ref_path)

    res = []
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.resolve() != ref_path.resolve():
            res.append(fileinfo(path, folder))

    dupes = dupecheck(res)
    for r in res:
        file_type(r, ref, dupes)

    lines = report(res, dupes, warn)
    for line in lines:
        print(line)

    txt_path, csv_path = save_reports(lines, res)
    print()
    print("Reports saved:")
    print(' ', txt_path)
    print(" ", csv_path)

main()
