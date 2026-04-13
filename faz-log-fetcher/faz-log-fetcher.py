"""
FortiAnalyzer Log Search, Fetch and Download.
Logs into FAZ, lets you pick ADOM and device(s),
Add search criteria.
Saves logs as CSV, JSON or TXT.

by: Farhan Ahmed - www.farhan.ch
"""

import json
import os
import time
import urllib.request
import ssl
import argparse
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
        print(f"\n  [ERROR] Connection failed: {e}")
        sys.exit(1)


def _header(text: str):
    print(f"\n{'─' * 60}\n  {text}\n{'─' * 60}")


def _prompt(label: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    val = input(f"  {label}{hint}: ").strip()
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
        print(f"\n  [ERROR] Login failed. Check IP/Credentials.")
        sys.exit(1)
    session = resp.get("session")
    print(f"  + Login Successful. Session: {session[:12]}...")
    return session


def select_adoms(host: str, session: str) -> list:
    _header("Step 2 / 10 — ADOM Selection")
    res = _post(host,
                {"id": 1, "session": session, "method": "get", "params": [{"url": "/dvmdb/adom", "fields": ["name"]}]})
    all_adoms = [a['name'] for a in res["result"][0].get("data", []) if a['name'] != 'rootp']
    print(f"\n  {'#':<4} {'ADOM Name'}\n  {'─' * 4} {'─' * 30}")
    for i, name in enumerate(all_adoms): print(f"  {i:<4} {name}")
    while True:
        raw = _prompt("\n  Select ADOM(s) (e.g. 0, 2-5)")
        indices = _parse_selection(raw, len(all_adoms) - 1)
        if indices: return [all_adoms[i] for i in indices]


def prompt_time_range() -> dict:
    _header("Step 3 / 10 — Time Range")
    trange = {"start": "", "end": ""}
    start_def = "2026-04-01 00:00:00"
    end_def = "2026-04-13 23:59:59"
    while True:
        v = _prompt("Enter start time", start_def)
        if validate_date(v): trange["start"] = v; break
        print("  [!] Invalid syntax. Use yyyy-mm-dd hh:mm:ss")
    while True:
        v = _prompt("Enter end time", end_def)
        if validate_date(v): trange["end"] = v; break
        print("  [!] Invalid syntax. Use yyyy-mm-dd hh:mm:ss")
    return trange


def prompt_logtype() -> str:
    _header("Step 4 / 10 — Log Type")
    types = ["traffic", "event", "webfilter", "ssl", "app-ctrl"]
    for i, lt in enumerate(types): print(f"    {i}  {lt}")
    raw = _prompt("\n  Select log type #", "0")
    idx = int(raw) if raw.isdigit() and 0 <= int(raw) < len(types) else 0
    return types[idx]


def prompt_filter() -> str:
    _header("Step 5 / 10 — Log Filter")
    raw = _prompt('\n  Filter string', "")
    if raw and "=" in raw and '"' not in raw:
        key, val = raw.split("=", 1)
        return f'{key}=\"{val}\"'
    return raw


def select_devices(host: str, session: str, adom: str) -> list:
    _header(f"Step 6 / 10 — Device Selection ({adom})")
    resp = _post(host, {"id": 1, "session": session, "method": "get",
                        "params": [{"url": f"/dvmdb/adom/{adom}/device", "fields": ["name", "sn", "vdom"]}]})
    devices = resp["result"][0].get("data", [])
    rows = [{"label": "All FortiGates", "devid": "All_FortiGate"}]
    for dev in devices:
        name, sn = dev.get("name", ""), dev.get("sn", "")
        for vdom in dev.get("vdom", [{}]):
            rows.append({"label": f"{name:<25} SN: {sn:<20} VDOM: {vdom.get('name', 'root')}",
                         "devid": f"{sn}[{vdom.get('name', 'root')}]"})
    for i, r in enumerate(rows): print(f"  {i:<5} {r['label']}")
    indices = _parse_selection(_prompt("\n  Selection", "0"), len(rows) - 1)
    return [{"devid": rows[i]["devid"]} for i in indices]


def logsearch_run(host: str, session: str, adom: str, logtype: str, log_filter: str, time_range: dict,
                  devices: list) -> str:
    _header(f"Step 7 / 10 — Starting Search [{adom}]")
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
    _header(f"Step 8 / 10 — Indexing Logs [{adom}]")
    while True:
        resp = _post(host, {"id": "3", "jsonrpc": "2.0", "method": "get",
                            "params": [{"url": f"/logview/adom/{adom}/logsearch/count/{tid}", "apiver": 3}],
                            "session": session})
        res = resp.get("result", {})
        percent = res.get("progress-percent", 0)
        matched = res.get("matched-logs", 0)
        print(f"  [Indexing] {percent}% complete... Matched: {matched:,} logs", end="\r", flush=True)
        if percent == 100:
            print(f"\n  + Final Index Match Count: {matched:,}")
            return matched
        time.sleep(POLL_INTERVAL)


def logsearch_fetch_all(host: str, session: str, adom: str, tid: str, matched_count: int) -> list:
    _header(f"Step 9 / 10 — Downloading Data [{adom}]")
    if matched_count == 0: return []
    PAGE, all_logs, offset = 1000, [], 0
    while offset < matched_count:
        while True:
            resp = _post(host, {"id": "1", "jsonrpc": "2.0", "method": "get", "params": [
                {"url": f"/logview/adom/{adom}/logsearch/{tid}", "offset": offset, "limit": PAGE, "apiver": 3}],
                                "session": session})
            result = resp.get("result", {})
            if result.get("percentage") == 100:
                logs = result.get("data") or []
                all_logs.extend(logs)
                print(f"  + Fetched offset {offset} ({len(logs)} logs). Total: {len(all_logs):,}")
                break
            time.sleep(POLL_INTERVAL)
        offset += PAGE
    return all_logs


def save_logs(logs: list, filename_base: str, fmt: str, do_zip: bool):
    temp_file = f"{filename_base}.{fmt if fmt != 'text' else 'txt'}"
    if fmt == "csv":
        keys = sorted(list(set().union(*(d.keys() for d in logs))))
        with open(temp_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(logs)
    elif fmt == "json":
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
    else:
        with open(temp_file, 'w', encoding='utf-8') as f:
            for l in logs: f.write(str(l) + "\n")
    if do_zip:
        with zipfile.ZipFile(f"{filename_base}.zip", 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(temp_file, os.path.basename(temp_file))
        os.remove(temp_file)
        print(f"  + Saved: {filename_base}.zip")
    else:
        print(f"  + Saved: {temp_file}")


def main():
    _header("FAZ Log Fetcher Pro")
    host = _prompt("FAZ IP")
    user = _prompt("Admin Username", "admin")
    pw = read_password(f"  Password for {user}: ")
    session = login(host, user, pw)

    try:
        while True:
            adoms = select_adoms(host, session)
            trange = prompt_time_range()
            ltype = prompt_logtype()
            lfilter = prompt_filter()

            _header("Step 10 / 10 — Export Config")
            print("  1: CSV | 2: JSON | 3: Text")
            fmt = {"1": "csv", "2": "json", "3": "text"}.get(_prompt("Selection", "1"), "csv")
            do_zip = _prompt("Zip output? (y/n)", "n").lower() == 'y'

            for adom in adoms:
                devs = select_devices(host, session, adom)
                tid = logsearch_run(host, session, adom, ltype, lfilter, trange, devs)
                if tid:
                    matched = logsearch_wait_for_index(host, session, adom, tid)
                    logs = logsearch_fetch_all(host, session, adom, tid, matched)
                    if logs:
                        os.makedirs("logs", exist_ok=True)
                        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                        base = f"logs/faz_{adom}_{ltype}_{ts}"
                        save_logs(logs, base, fmt, do_zip)
                    _post(host, {"id": 1, "method": "delete",
                                 "params": [{"url": f"/logview/adom/{adom}/logsearch/{tid}", "apiver": 3}],
                                 "session": session})

            if _prompt("\n  Fetch more logs? (y/n)", "n").lower() != 'y': break
    finally:
        _post(host, {"id": 1, "method": "exec", "params": [{"url": "/sys/logout"}], "session": session})
        print("\n  Session closed. Goodbye!")


if __name__ == "__main__":
    main()