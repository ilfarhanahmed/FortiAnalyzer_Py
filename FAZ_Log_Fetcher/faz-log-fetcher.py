"""
FortiAnalyzer Log Search, Fetch and Download.
Logs into FAZ, lets you pick ADOM and device(s),
Add search criteria.
Saves logs as CSV, JSON or TXT as zipped or normal.

by: Farhan Ahmed - www.farhan.ch
"""

import json
import os
import time
import urllib.request
import ssl
import csv
import zipfile
import re
import sys
from datetime import datetime

# -- Global Configuration --
POLL_INTERVAL = 2
API_TIMEOUT = 60

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def c(color: str, text: str) -> str:
    """Wrap text in a color code."""
    return f"{color}{text}{Colors.END}"


def read_password(label):
    import getpass
    in_pycharm = 'PYCHARM_HOSTED' in os.environ or 'PYDEV_CONSOLE_EXECUTE_HOOK' in os.environ
    if in_pycharm:
        return input(label)
    try:
        return getpass.getpass(label)
    except Exception:
        return input(label)


def _post(host: str, payload: dict) -> dict:
    url = f"https://{host}/jsonrpc"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=API_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"\n  {c(Colors.RED, '[ERROR]')} Connection failed: {c(Colors.YELLOW, str(e))}")
        sys.exit(1)


def _header(text: str):
    print(f"\n{c(Colors.CYAN, '─' * 60)}")
    print(f"  {c(Colors.BOLD + Colors.HEADER, text)}")
    print(f"{c(Colors.CYAN, '─' * 60)}")


def _prompt(label: str, default: str = "") -> str:
    hint = f" {c(Colors.CYAN, f'[{default}]')}" if default else ""
    val = input(f"  {c(Colors.BLUE, label)}{hint}: ").strip()
    return val if val else default


def _parse_selection(raw: str, max_idx: int) -> list:
    indices = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                indices.update(range(int(a), int(b) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            indices.add(int(part))
    return sorted(i for i in indices if 0 <= i <= max_idx)


def validate_date(date_str: str) -> bool:
    pattern = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
    if not re.match(pattern, date_str):
        return False
    try:
        datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        return True
    except ValueError:
        return False


# -- FAZ Logic Steps --

def login(host: str, user: str, password: str) -> str:
    _header("Step 1 / 10 — Login")
    payload = {"id": 1, "method": "exec", "apiver": 3,
               "params": [{"data": {"user": user, "passwd": password}, "url": "/sys/login/user"}]}
    resp = _post(host, payload)
    results = resp.get("result")
    status = results[0].get("status", {}) if results and isinstance(results, list) else {}
    if status.get("code") != 0 or not resp.get("session"):
        print(f"\n  {c(Colors.RED, '[ERROR]')} Login failed. Check IP/Credentials.")
        sys.exit(1)
    session = resp.get("session")
    print(f"  {c(Colors.GREEN, '+')} Login Successful. Session: {c(Colors.CYAN, session[:12])}...")
    return session


def select_adoms(host: str, session: str) -> list:
    _header("Step 2 / 10 — ADOM Selection")
    res = _post(host,
                {"id": 1, "session": session, "method": "get",
                 "params": [{"url": "/dvmdb/adom", "fields": ["name"]}]})
    all_adoms = [a['name'] for a in res["result"][0].get("data", []) if a['name'] != 'rootp']
    print(f"\n  {c(Colors.BOLD, '#'):<4} {c(Colors.BOLD, 'ADOM Name')}")
    print(f"  {'─' * 4} {'─' * 30}")
    for i, name in enumerate(all_adoms):
        print(f"  {c(Colors.YELLOW, str(i)):<4} {name}")
    while True:
        raw = _prompt("\n  Select ADOM(s) (e.g. 0, 2-5)")
        indices = _parse_selection(raw, len(all_adoms) - 1)
        if indices:
            return [all_adoms[i] for i in indices]


def prompt_time_range() -> dict:
    _header("Step 3 / 10 — Time Range")
    trange = {"start": "", "end": ""}
    # Using dynamic current year for defaults
    curr_year = datetime.now().year
    start_def = f"{curr_year}-04-01 00:00:00"
    end_def = f"{curr_year}-04-13 23:59:59"
    while True:
        v = _prompt("Enter start time", start_def)
        if validate_date(v):
            trange["start"] = v
            break
        print(f"  {c(Colors.RED, '[!]')} Invalid syntax. Use {c(Colors.YELLOW, 'yyyy-mm-dd hh:mm:ss')}")
    while True:
        v = _prompt("Enter end time", end_def)
        if validate_date(v):
            trange["end"] = v
            break
        print(f"  {c(Colors.RED, '[!]')} Invalid syntax. Use {c(Colors.YELLOW, 'yyyy-mm-dd hh:mm:ss')}")
    return trange


def fetch_logtypes(host: str, session: str, adom: str) -> list:
    resp = _post(host, {
        "id": 1, "session": session, "method": "get", "jsonrpc": "2.0",
        "params": [{"url": f"/logview/adom/{adom}/logtypes", "apiver": 3}]
    })
    data = resp.get("result", {}).get("data") or []

    entries = []
    for devtype in data:
        dev_name = devtype.get("name", "Unknown")
        for lt in devtype.get("logtypes", []):
            name = lt["name"]
            if name == "event":
                entries.append({
                    "display": f"{'event':<20} [{dev_name}]",
                    "logtype": "event",
                    "devtype": dev_name
                })
            elif "logtypes" in lt:
                for sub in lt.get("logtypes", []):
                    entries.append({
                        "display": f"{sub['name']:<20} [{dev_name}]",
                        "logtype": sub["name"],
                        "devtype": dev_name
                    })
            else:
                entries.append({
                    "display": f"{name:<20} [{dev_name}]",
                    "logtype": name,
                    "devtype": dev_name
                })
    return entries


def prompt_logtype(host: str, session: str, adom: str) -> str:
    _header("Step 4 / 10 — Log Type")
    entries = fetch_logtypes(host, session, adom)

    if not entries:
        print(f"  {c(Colors.YELLOW, '[!]')} Could not fetch log types. Using common defaults.")
        entries = [{"display": "traffic              [FortiGate]", "logtype": "traffic", "devtype": "FortiGate"}]

    print(f"\n  {c(Colors.BOLD, '#'):<4}  {c(Colors.BOLD, 'Log Type'):<20}  {c(Colors.BOLD, 'Device')}")
    print(f"  {'─' * 4}  {'─' * 20}  {'─' * 22}")

    current_dev = None
    for i, entry in enumerate(entries):
        if entry["devtype"] != current_dev:
            current_dev = entry["devtype"]
            print(f"\n  {c(Colors.HEADER + Colors.BOLD, f'── {current_dev} ──')}")
        print(f"  {c(Colors.YELLOW, str(i)):<4}  {entry['display']}")

    raw = _prompt("\n  Select log type #", "0")
    idx = int(raw) if raw.isdigit() and 0 <= int(raw) < len(entries) else 0
    selected = entries[idx]["logtype"]
    print(f"  {c(Colors.GREEN, '+')} Selected: {c(Colors.CYAN, selected)}")
    return selected


def prompt_filter() -> str:
    _header("Step 5 / 10 — Log Filter")
    raw = _prompt('\n  Filter string (e.g. srcip=1.1.1.1)', "")
    if raw and "=" in raw and '"' not in raw:
        key, val = raw.split("=", 1)
        return f'{key}=\"{val}\"'
    return raw


def select_devices(host: str, session: str, adom: str) -> list:
    _header(f"Step 6 / 10 — Device Selection ({c(Colors.CYAN, adom)})")
    resp = _post(host, {"id": 1, "session": session, "method": "get",
                        "params": [{"url": f"/dvmdb/adom/{adom}/device", "fields": ["name", "sn", "vdom"]}]})
    devices = resp["result"][0].get("data", [])
    rows = [
        {"label": "All Devices",    "devid": "All_Devices"},
        {"label": "All FortiGates", "devid": "All_FortiGate"}
    ]
    for dev in devices:
        name, sn = dev.get("name", ""), dev.get("sn", "")
        for vdom in dev.get("vdom", [{}]):
            rows.append({
                "label": f"{name:<25} SN: {sn:<20} VDOM: {vdom.get('name', 'root')}",
                "devid": f"{sn}[{vdom.get('name', 'root')}]"
            })
    for i, r in enumerate(rows):
        print(f"  {c(Colors.YELLOW, str(i)):<5} {r['label']}")
    indices = _parse_selection(_prompt("\n  Selection", "0"), len(rows) - 1)
    return [{"devid": rows[i]["devid"]} for i in indices]


def logsearch_run(host: str, session: str, adom: str, logtype: str, log_filter: str,
                  time_range: dict, devices: list) -> str:
    _header(f"Step 7 / 10 — Starting Search [{c(Colors.CYAN, adom)}]")
    payload = {
        "id": "2", "jsonrpc": "2.0", "method": "add",
        "params": [{
            "filter": log_filter, "logtype": logtype, "time-order": "desc",
            "time-range": time_range, "url": f"/logview/adom/{adom}/logsearch/",
            "device": devices, "apiver": 3
        }], "session": session
    }
    resp = _post(host, payload)
    return resp.get("result", {}).get("tid")


def logsearch_wait_for_index(host: str, session: str, adom: str, tid: str) -> int:
    _header(f"Step 8 / 10 — Indexing Logs [{c(Colors.CYAN, adom)}]")
    while True:
        resp = _post(host, {"id": "3", "jsonrpc": "2.0", "method": "get",
                            "params": [{"url": f"/logview/adom/{adom}/logsearch/count/{tid}", "apiver": 3}],
                            "session": session})
        res = resp.get("result", {})
        percent = res.get("progress-percent", 0)
        matched = res.get("matched-logs", 0)

        print(f"  {c(Colors.BLUE, '[Indexing]')} {percent}% complete... Matched: {c(Colors.CYAN, f'{matched:,}')} logs", end="\r", flush=True)

        if percent == 100:
            print(f"\n  {c(Colors.GREEN, '+')} Final Index Match Count: {c(Colors.BOLD + Colors.GREEN, f'{matched:,}')}")
            return matched
        time.sleep(POLL_INTERVAL)


def logsearch_stream_fetch(host: str, session: str, adom: str, tid: str, matched_count: int, file_path: str, fmt: str):
    """Streams data from FAZ and writes directly to disk with clear progress printing."""
    _header(f"Step 9 / 10 — Downloading Data [{c(Colors.CYAN, adom)}]")
    PAGE, offset, total_downloaded = 1000, 0, 0

    # Pre-fetch headers for CSV
    headers = []
    if fmt == "csv":
        resp = _post(host, {"id": "1", "jsonrpc": "2.0", "method": "get", "params": [
            {"url": f"/logview/adom/{adom}/logsearch/{tid}", "offset": 0, "limit": 5, "apiver": 3}],
                            "session": session})
        sample = resp.get("result", {}).get("data") or [{}]
        headers = sorted(list(set().union(*(d.keys() for d in sample))))

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = None
        if fmt == "csv":
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

        while offset < matched_count:
            while True:
                resp = _post(host, {"id": "1", "jsonrpc": "2.0", "method": "get", "params": [
                    {"url": f"/logview/adom/{adom}/logsearch/{tid}", "offset": offset, "limit": PAGE, "apiver": 3}],
                                    "session": session})
                result = resp.get("result", {})

                if result.get("percentage") == 100:
                    logs = result.get("data") or []

                    if fmt == "csv":
                        writer.writerows(logs)
                    elif fmt == "json":
                        for l in logs:
                            f.write(json.dumps(l) + "\n")
                    else:
                        for l in logs:
                            f.write(str(l) + "\n")

                    total_downloaded += len(logs)

                    # This is the line-by-line progress you preferred:
                    print(
                        f"  {c(Colors.GREEN, '+')} Downloaded offset {c(Colors.YELLOW, str(offset))} "
                        f"({c(Colors.CYAN, str(len(logs)))} logs). "
                        f"Total Saved: {c(Colors.BOLD + Colors.GREEN, f'{total_downloaded:,}')}"
                    )
                    break

                time.sleep(POLL_INTERVAL)
            offset += PAGE
    print(f"\n  {c(Colors.GREEN, 'Done!')} File is fully written to disk.")


def main():
    _header("FAZ Log Fetcher")
    host = _prompt("FAZ IP")
    user = _prompt("Admin Username", "admin")
    pw = read_password(f"  {c(Colors.BLUE, f'Password for {user}')}: ")
    session = login(host, user, pw)

    try:
        while True:
            adoms = select_adoms(host, session)
            trange = prompt_time_range()
            ltype = prompt_logtype(host, session, adoms[0])
            lfilter = prompt_filter()

            _header("Step 10 / 10 — Export Config")
            print(f"  {c(Colors.YELLOW, '1')}: CSV  {c(Colors.YELLOW, '|')}  "
                  f"{c(Colors.YELLOW, '2')}: JSON  {c(Colors.YELLOW, '|')}  "
                  f"{c(Colors.YELLOW, '3')}: Text")
            fmt = {"1": "csv", "2": "json", "3": "text"}.get(_prompt("Selection", "1"), "csv")
            do_zip = _prompt("Zip output? (y/n)", "y").lower() == 'y'

            for adom in adoms:
                devs = select_devices(host, session, adom)
                tid = logsearch_run(host, session, adom, ltype, lfilter, trange, devs)
                if tid:
                    matched = logsearch_wait_for_index(host, session, adom, tid)

                    if matched == 0:
                        print(f"  {c(Colors.YELLOW, '[!]')} No logs found for this criteria.")
                    else:
                        # Safety check for accidental huge downloads
                        confirm = _prompt(f"Proceed to download {c(Colors.BOLD + Colors.CYAN, f'{matched:,}')} logs? (y/n)", "y")

                        if confirm.lower() == 'y':
                            os.makedirs("logs", exist_ok=True)
                            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                            ext = "csv" if fmt == "csv" else "json" if fmt == "json" else "txt"
                            filename_base = f"logs/faz_{adom}_{ltype}_{ts}"
                            full_path = f"{filename_base}.{ext}"

                            logsearch_stream_fetch(host, session, adom, tid, matched, full_path, fmt)

                            if do_zip:
                                with zipfile.ZipFile(f"{filename_base}.zip", 'w', zipfile.ZIP_DEFLATED) as z:
                                    z.write(full_path, os.path.basename(full_path))
                                os.remove(full_path)
                                print(f"  {c(Colors.GREEN, '+')} Zipped: {c(Colors.BOLD + Colors.CYAN, f'{filename_base}.zip')}")
                            else:
                                print(f"  {c(Colors.GREEN, '+')} Saved: {c(Colors.BOLD + Colors.CYAN, full_path)}")

                    _post(host, {"id": 1, "method": "delete",
                                 "params": [{"url": f"/logview/adom/{adom}/logsearch/{tid}", "apiver": 3}],
                                 "session": session})

            if _prompt("\n  Fetch more logs? (y/n)", "n").lower() != 'y':
                break
    finally:
        _post(host, {"id": 1, "method": "exec", "params": [{"url": "/sys/logout"}], "session": session})
        print(f"\n  {c(Colors.GREEN, 'Session closed.')} {c(Colors.BOLD, 'Goodbye!')}")


if __name__ == "__main__":
    main()