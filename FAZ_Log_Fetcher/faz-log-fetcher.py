"""
FortiAnalyzer Log Search, Fetch and Download.
Logs into FAZ, lets you pick ADOM and device(s),
Add search criteria.
Saves logs as JSON or TXT as zipped or normal.

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

DEVTYPE_DISPLAY_NAMES = {
    "SIM": "Fabric Logs",
}

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
    _header("Step 1 / 11 — Login")
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
    _header("Step 2 / 11 — ADOM Selection")
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


def select_device_type(host: str, session: str, adom: str) -> tuple:
    _header("Step 3 / 11 — Device Type Selection")

    # Single fetch — get os_type and platform_str for all devices in this ADOM
    dev_resp = _post(host, {"id": 1, "session": session, "method": "get", "verbose": 1,
                            "params": [{"url": f"/dvmdb/adom/{adom}/device",
                                        "fields": ["name", "os_type", "platform_str"]}]})
    all_devices = dev_resp["result"][0].get("data", [])

    # Build map: product_name → os_type
    # platform_str format: "FortiGate-60E", "FortiAnalyzer-VM64-KVM" etc.
    # First segment before "-" matches the "name" field in logtypes response exactly
    name_to_os_type = {}
    for d in all_devices:
        os_type      = d.get("os_type", "").lower()
        platform_str = d.get("platform_str", "")
        if not os_type or not platform_str:
            continue
        product_name = platform_str.split("-")[0]   # e.g. "FortiGate", "FortiAnalyzer"
        name_to_os_type[product_name] = os_type

    # Fetch available log device types for this ADOM
    lt_resp = _post(host, {
        "id": 1, "session": session, "method": "get", "jsonrpc": "2.0",
        "params": [{"url": f"/logview/adom/{adom}/logtypes", "apiver": 3}]
    })
    lt_data = lt_resp.get("result", {}).get("data") or []

    # Only include devtypes that have actual devices registered in this ADOM
    # SIEM/Fabric logs (SIM) may not have a physical device entry — include if present in logtypes
    available = []
    for entry in lt_data:
        product_name = entry.get("name", "")
        devtype      = entry.get("devtype", "")
        if product_name in name_to_os_type:
            available.append((entry, name_to_os_type[product_name]))
        elif devtype == "SIM":
            available.append((entry, "sim"))

    if not available:
        print(f"  {c(Colors.YELLOW, '[!]')} No device types with registered devices found in ADOM.")
        sys.exit(1)

    print(f"\n  {c(Colors.BOLD, '#'):<4}  {c(Colors.BOLD, 'Device Type'):<30}  {c(Colors.BOLD, 'os_type')}")
    print(f"  {'─' * 4}  {'─' * 30}  {'─' * 10}")
    for i, (entry, os_type) in enumerate(available):
        devtype = entry.get("devtype", "")
        display = DEVTYPE_DISPLAY_NAMES.get(devtype, entry.get("name", devtype))
        print(f"  {c(Colors.YELLOW, str(i)):<4}  {display:<30}  {c(Colors.CYAN, os_type)}")

    raw = _prompt("\n  Select device type #", "0")
    idx = int(raw) if raw.isdigit() and 0 <= int(raw) < len(available) else 0
    chosen_entry, chosen_os_type = available[idx]

    devtype = chosen_entry.get("devtype", "")
    display = DEVTYPE_DISPLAY_NAMES.get(devtype, chosen_entry.get("name", devtype))
    print(f"  {c(Colors.GREEN, '+')} Selected: {c(Colors.CYAN, display)}  [{c(Colors.CYAN, chosen_os_type)}]")
    return chosen_entry, chosen_os_type


def prompt_logtype(devtype_entry: dict) -> tuple:
    """
    Returns (logtype, extra_filter).
    extra_filter is e.g. 'subtype="vpn"' when an event sub-type is selected, else "".
    """
    _header("Step 4 / 11 — Log Type")
    raw_name = devtype_entry.get("name", "")
    devtype  = devtype_entry.get("devtype", "")
    display  = DEVTYPE_DISPLAY_NAMES.get(devtype, raw_name)

    entries = []
    for lt in devtype_entry.get("logtypes", []):
        name = lt["name"]
        if name == "event":
            # event itself is selectable; subtypes prompted separately
            entries.append({
                "display":  f"{'event':<20} [{display}]",
                "logtype":  "event",
                "subtypes": [s["name"] for s in lt.get("logtypes", [])]
            })
        elif "logtypes" in lt:
            # Groups like utm — children are the real selectable logtypes
            for sub in lt["logtypes"]:
                entries.append({
                    "display":  f"{sub['name']:<20} [{display}] (via {name})",
                    "logtype":  sub["name"],
                    "subtypes": []
                })
        else:
            entries.append({
                "display":  f"{name:<20} [{display}]",
                "logtype":  name,
                "subtypes": []
            })

    if not entries:
        print(f"  {c(Colors.YELLOW, '[!]')} No log types found. Defaulting to 'traffic'.")
        return "traffic", ""

    print(f"\n  {c(Colors.BOLD, '#'):<4}  {c(Colors.BOLD, 'Log Type')}")
    print(f"  {'─' * 4}  {'─' * 40}")
    for i, entry in enumerate(entries):
        print(f"  {c(Colors.YELLOW, str(i)):<4}  {entry['display']}")

    raw      = _prompt("\n  Select log type #", "0")
    idx      = int(raw) if raw.isdigit() and 0 <= int(raw) < len(entries) else 0
    selected = entries[idx]
    logtype  = selected["logtype"]
    extra_filter = ""

    # If event selected and subtypes exist, prompt for subtype
    if logtype == "event" and selected["subtypes"]:
        print(f"\n  {c(Colors.BOLD, 'Event Subtypes')} (added as filter, press Enter to skip):")
        print(f"  {'─' * 4}  {'─' * 30}")
        subtypes = selected["subtypes"]
        for i, st in enumerate(subtypes):
            print(f"  {c(Colors.YELLOW, str(i)):<4}  {st}")
        raw2 = _prompt("\n  Select subtype # (or Enter to skip)", "")
        if raw2.isdigit() and 0 <= int(raw2) < len(subtypes):
            subtype      = subtypes[int(raw2)]
            extra_filter = f'subtype="{subtype}"'
            print(f"  {c(Colors.GREEN, '+')} Subtype filter: {c(Colors.CYAN, extra_filter)}")
        else:
            print(f"  {c(Colors.YELLOW, '[!]')} No subtype selected — fetching all event logs.")

    print(f"  {c(Colors.GREEN, '+')} Log type: {c(Colors.CYAN, logtype)}")
    return logtype, extra_filter


def prompt_time_range() -> dict:
    _header("Step 5 / 11 — Time Range")
    trange    = {"start": "", "end": ""}
    curr_year = datetime.now().year
    start_def = f"{curr_year}-04-01 00:00:00"
    end_def   = f"{curr_year}-04-13 23:59:59"
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


def prompt_filter(extra_filter: str = "") -> str:
    _header("Step 6 / 11 — Log Filter")
    raw = _prompt('\n  Filter string (e.g. srcip=1.1.1.1)', "")
    if raw and "=" in raw and '"' not in raw:
        key, val = raw.split("=", 1)
        raw = f'{key}="{val}"'

    # Merge subtype filter from event selection with any additional user filter
    if extra_filter and raw:
        return f"{extra_filter} {raw}"
    return extra_filter or raw


def select_devices(host: str, session: str, adom: str, devtype_entry: dict, os_type: str) -> list:
    _header(f"Step 7 / 11 — Device Selection ({c(Colors.CYAN, adom)})")

    resp = _post(host, {"id": 1, "session": session, "method": "get", "verbose": 1,
                        "params": [{"url": f"/dvmdb/adom/{adom}/device",
                                    "fields": ["name", "os_type", "platform_str", "vdom"]}]})
    devices = resp["result"][0].get("data", [])

    devtype      = devtype_entry.get("devtype", "")
    display_name = DEVTYPE_DISPLAY_NAMES.get(devtype, devtype_entry.get("name", devtype))

    # Filter using the os_type string discovered dynamically in select_device_type()
    matched = [d for d in devices if d.get("os_type", "").lower() == os_type.lower()]

    if not matched:
        print(f"  {c(Colors.YELLOW, '[!]')} No devices found for os_type: {c(Colors.CYAN, os_type)}")
        return []

    product_name = devtype_entry.get("name", devtype)
    rows = [{"label": f"All {display_name} Devices", "devid": f"All_{product_name}"}]
    for dev in matched:
        name         = dev.get("name", "")
        platform_str = dev.get("platform_str", "")
        for vdom in dev.get("vdom", [{}]):
            vdom_name = vdom.get("name", "root")
            rows.append({
                "label": f"{name:<25} {platform_str:<35} VDOM: {vdom_name}",
                "devid": f"{name}[{vdom_name}]"
            })

    print(f"\n  {c(Colors.BOLD, '#'):<5} {c(Colors.BOLD, 'Device')}")
    print(f"  {'─' * 5} {'─' * 70}")
    for i, r in enumerate(rows):
        tag = c(Colors.HEADER, "  ← select all") if i == 0 else ""
        print(f"  {c(Colors.YELLOW, str(i)):<5} {r['label']}{tag}")

    indices = _parse_selection(_prompt("\n  Selection (e.g. 0, 1, 3-5)", "0"), len(rows) - 1)
    return [{"devid": rows[i]["devid"]} for i in indices]


def logsearch_run(host: str, session: str, adom: str, logtype: str, log_filter: str,
                  time_range: dict, devices: list) -> str:
    _header(f"Step 8 / 11 — Starting Search [{c(Colors.CYAN, adom)}]")
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
    _header(f"Step 9 / 11 — Indexing Logs [{c(Colors.CYAN, adom)}]")
    while True:
        resp = _post(host, {"id": "3", "jsonrpc": "2.0", "method": "get",
                            "params": [{"url": f"/logview/adom/{adom}/logsearch/count/{tid}", "apiver": 3}],
                            "session": session})
        res     = resp.get("result", {})
        percent = res.get("progress-percent", 0)
        matched = res.get("matched-logs", 0)

        print(f"  {c(Colors.BLUE, '[Indexing]')} {percent}% complete... Matched: {c(Colors.CYAN, f'{matched:,}')} logs",
              end="\r", flush=True)

        if percent == 100:
            print(f"\n  {c(Colors.GREEN, '+')} Final Index Match Count: {c(Colors.BOLD + Colors.GREEN, f'{matched:,}')}")
            return matched
        time.sleep(POLL_INTERVAL)


def logsearch_stream_fetch(host: str, session: str, adom: str, tid: str,
                           matched_count: int, file_path: str, fmt: str):
    """Streams data from FAZ and writes directly to disk with clear progress printing."""
    _header(f"Step 10 / 11 — Downloading Data [{c(Colors.CYAN, adom)}]")
    PAGE, offset, total_downloaded = 1000, 0, 0

    # Pre-fetch headers for CSV
    headers = []
    if fmt == "csv":
        resp = _post(host, {"id": "1", "jsonrpc": "2.0", "method": "get", "params": [
            {"url": f"/logview/adom/{adom}/logsearch/{tid}", "offset": 0, "limit": 5, "apiver": 3}],
                            "session": session})
        sample  = resp.get("result", {}).get("data") or [{}]
        headers = sorted(list(set().union(*(d.keys() for d in sample))))

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = None
        if fmt == "csv":
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

        while offset < matched_count:
            while True:
                resp = _post(host, {"id": "1", "jsonrpc": "2.0", "method": "get", "params": [
                    {"url": f"/logview/adom/{adom}/logsearch/{tid}",
                     "offset": offset, "limit": PAGE, "apiver": 3}],
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
    pw   = read_password(f"  {c(Colors.BLUE, f'Password for {user}')}: ")
    session = login(host, user, pw)

    try:
        while True:
            adoms                         = select_adoms(host, session)
            devtype_entry, chosen_os_type = select_device_type(host, session, adoms[0])
            ltype, extra_filter           = prompt_logtype(devtype_entry)
            trange                        = prompt_time_range()
            lfilter                       = prompt_filter(extra_filter)

            _header("Step 11 / 11 — Export Config")
            print(
                f"  {c(Colors.YELLOW, '1')}: JSON  {c(Colors.YELLOW, '|')}  "
                f"{c(Colors.YELLOW, '2')}: Text")
            fmt    = {"1": "json", "2": "text"}.get(_prompt("  Selection", "1"), "json")
            do_zip = _prompt("  Zip output? (y/n)", "y").lower() == 'y'

            for adom in adoms:
                devs = select_devices(host, session, adom, devtype_entry, chosen_os_type)
                if not devs:
                    continue

                tid = logsearch_run(host, session, adom, ltype, lfilter, trange, devs)
                if tid:
                    matched = logsearch_wait_for_index(host, session, adom, tid)

                    if matched == 0:
                        print(f"  {c(Colors.YELLOW, '[!]')} No logs found for this criteria.")
                    else:
                        confirm = _prompt(
                            f"  Proceed to download {c(Colors.BOLD + Colors.CYAN, f'{matched:,}')} logs? (y/n)", "y"
                        )
                        if confirm.lower() == 'y':
                            os.makedirs("logs", exist_ok=True)
                            ts            = datetime.now().strftime('%Y%m%d_%H%M%S')
                            ext           = "json" if fmt == "json" else "txt"
                            filename_base = f"logs/faz_{adom}_{ltype}_{ts}"
                            full_path     = f"{filename_base}.{ext}"

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