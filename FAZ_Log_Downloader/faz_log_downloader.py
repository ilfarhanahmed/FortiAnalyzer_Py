#!/usr/bin/env python3
"""
FAZ Log Downloader
Logs into FortiAnalyzer, lets you pick ADOM, device and date range,
then downloads selected or all log files to a local folder.

by: Farhan Ahmed - www.farhan.ch
"""

import requests
import urllib3
import json
import os
import re
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUTPUT_DIR = "./faz_logs"


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def print_banner():
    print("\n" + "═" * 55)
    print("       FortiAnalyzer Log Downloader")
    print("═" * 55 + "\n")


def prompt_date(label, example, suffix):
    while True:
        val = input(f"  {label} (YYYY-MM-DD) e.g. {example}: ").strip()
        try:
            datetime.strptime(val, "%Y-%m-%d")
            return val + suffix
        except ValueError:
            print("  ⚠️  Invalid date format. Please use YYYY-MM-DD.\n")


def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>|]', "_", name)


# ─────────────────────────────────────────────
#  STEP 1 — CONNECTION DETAILS
# ─────────────────────────────────────────────
def get_connection_details():
    print("── Step 1: FAZ Connection ──────────────────────\n")
    host     = input("  FAZ IP or hostname: ").strip()
    username = input("  Admin username    : ").strip()
    password = input("  Admin password    : ").strip()
    return host, username, password


# ─────────────────────────────────────────────
#  STEP 2 — LOGIN
# ─────────────────────────────────────────────
def login(session, host, username, password):
    print("\n── Step 2: Logging in ──────────────────────────\n")
    url = f"https://{host}/cgi-bin/module/flatui_auth"
    payload = {
        "url": "/gui/userauth",
        "method": "login",
        "params": {
            "username": username,
            "secretkey": password,
            "logintype": 0
        }
    }
    resp = session.post(url, json=payload, verify=False)
    resp.raise_for_status()

    csrf_token = session.cookies.get("HTTP_CSRF_TOKEN")
    if not csrf_token:
        raise Exception("Login failed — no CSRF token received. Check credentials.")

    data   = resp.json()
    result = data.get("result", [{}])[0]
    status = result.get("status", {})
    if status.get("code") != 0:
        raise Exception(f"Login failed — {status.get('message', 'Unknown error')}")

    session.headers.update({
        "XSRF-TOKEN": csrf_token,
        "Origin":     f"https://{host}",
        "Referer":    f"https://{host}/ui/logview/logbrowse"
    })

    print("  ✅ Login successful.\n")
    return csrf_token


# ─────────────────────────────────────────────
#  STEP 3 — FETCH & SELECT ADOM
# ─────────────────────────────────────────────
def fetch_adoms(session, host):
    print("\n── Step 3: Fetching ADOM list ──────────────────\n")
    url = f"https://{host}/cgi-bin/module/flatui_proxy"
    payload = {
        "url":    "/gui/switch/adoms/list",
        "method": "get",
        "params": {}
    }
    resp = session.post(url, json=payload, verify=False)
    resp.raise_for_status()

    data = resp.json()
    try:
        adoms = data["result"][0]["data"]
    except (KeyError, IndexError, TypeError):
        raise Exception("Could not parse ADOM list from response.")

    if not adoms:
        raise Exception("No ADOMs found.")

    return adoms


def select_adom(adoms):
    print(f"  {'#':<4} {'ADOM Name':<25} {'Type':<20} OID")
    print("  " + "─" * 55)
    for i, adom in enumerate(adoms):
        print(f"  {i:<4} {adom.get('name',''):<25} {adom.get('type_name',''):<20} {adom.get('oid','')}")
    print()

    while True:
        choice = input(f"  Select ADOM [0–{len(adoms)-1}]: ").strip()
        try:
            idx = int(choice)
            if 0 <= idx < len(adoms):
                selected = adoms[idx]
                print(f"\n  → Selected ADOM: {selected['name']} (OID: {selected['oid']})\n")
                return selected
            else:
                print(f"  ⚠️  Enter a number between 0 and {len(adoms)-1}.")
        except ValueError:
            print("  ⚠️  Invalid input.")


# ─────────────────────────────────────────────
#  STEP 4 — SWITCH ADOM
# ─────────────────────────────────────────────
def switch_adom(session, host, adom):
    print(f"\n── Step 4: Switching to ADOM '{adom['name']}' ─────\n")
    url = f"https://{host}/cgi-bin/module/flatui_proxy"
    payload = {
        "url":    "/gui/session/adom",
        "method": "change",
        "params": {
            "oid": adom["oid"]
        }
    }
    resp = session.post(url, json=payload, verify=False)
    resp.raise_for_status()

    data   = resp.json()
    result = data.get("result", [{}])[0]
    status = result.get("status", {})

    if status.get("code") != 0:
        raise Exception(f"ADOM switch failed — {status.get('message', 'Unknown error')}")

    print(f"  ✅ Switched to ADOM: {adom['name']}\n")


# ─────────────────────────────────────────────
#  STEP 5 — FETCH AVAILABLE DEVICES
# ─────────────────────────────────────────────
def fetch_devices(session, host, adom_oid):
    print(f"\n── Step 5: Fetching devices in ADOM ────────────\n")
    url = f"https://{host}/cgi-bin/module/flatui_proxy"
    payload = {
        "method": "get",
        "url":    f"/gui/adoms/{adom_oid}/devices/log-stats"
    }
    resp = session.post(url, json=payload, verify=False)
    resp.raise_for_status()

    data = resp.json()
    try:
        devs = data["result"][0]["data"]["devs"]
    except (KeyError, IndexError, TypeError):
        print("  ⚠️  Could not parse device list. Will default to all devices.\n")
        return []

    if not devs:
        print("  ⚠️  No devices found in this ADOM.\n")
        return []

    return devs


# ─────────────────────────────────────────────
#  STEP 6 — SELECT DEVICE
# ─────────────────────────────────────────────
def select_device(devs):
    print("\n── Step 6: Select Device ───────────────────────\n")

    if not devs:
        print("  No device list available — defaulting to ALL devices.\n")
        return ""

    print(f"  {'#':<4} {'Device ID (Serial)':<28} {'Device Name':<22} VDOMs")
    print("  " + "─" * 75)
    for i, dev in enumerate(devs):
        devid   = dev.get("devid", "N/A")
        devname = dev.get("devname", "N/A")
        vdoms   = ", ".join(v.get("vdom", "") for v in dev.get("vdoms", []))
        print(f"  {i:<4} {devid:<28} {devname:<22} {vdoms}")

    print(f"\n  {len(devs):<4} {'ALL DEVICES':<28} (downloads from every device)")
    print()

    while True:
        choice = input(f"  Select number [0–{len(devs)}]: ").strip()
        try:
            idx = int(choice)
            if idx == len(devs):
                print("  → Selected: ALL DEVICES\n")
                return ""
            elif 0 <= idx < len(devs):
                selected = devs[idx]["devid"]
                print(f"  → Selected: {selected}\n")
                return selected
            else:
                print(f"  ⚠️  Enter a number between 0 and {len(devs)}.")
        except ValueError:
            print("  ⚠️  Invalid input.")


# ─────────────────────────────────────────────
#  STEP 7 — DATE RANGE
# ─────────────────────────────────────────────
def get_date_range():
    print("\n── Step 7: Date Range ──────────────────────────\n")
    start = prompt_date("Start date", "2025-10-01", " 00:00:00")
    end   = prompt_date("End date  ", "2026-03-31", " 23:59:59")
    print(f"\n  → Range: {start}  to  {end}\n")
    return start, end


# ─────────────────────────────────────────────
#  STEP 8 — SEARCH FOR LOG FILES
# ─────────────────────────────────────────────
def search_logs(session, host, devid, start_time, end_time):
    print("\n── Step 8: Searching for log files ────────────\n")
    url = f"https://{host}/p/logview/browsefiles/"
    payload = {
        "devid":      devid,
        "filter":     "device_name!=\".self\"",
        "sort_asc":   0,
        "sort_by":    "device_name",
        "start_time": start_time,
        "end_time":   end_time
    }
    resp = session.post(url, json=payload, verify=False)
    resp.raise_for_status()

    data    = resp.json()
    records = data.get("records", [])

    if not records:
        print("  ⚠️  No log files found for the given filters.\n")
        return []

    print(f"  ✅ Found {len(records)} file(s):\n")
    print(f"  {'#':<4} {'Filename':<20} {'Device ID':<28} {'VDOM':<10} {'Size':<15} {'Begin Time':<22} {'End Time':<22} Filepath")
    print("  " + "─" * 145)
    for i, r in enumerate(records):
        print(f"  {i:<4} {r.get('filename',''):<20} {r.get('device_id',''):<28} "
              f"{r.get('vdom_name',''):<10} {str(r.get('size','')):<15} "
              f"{r.get('begintime',''):<22} {r.get('endtime',''):<22} {r.get('filepath','')}")
    print()
    return records


# ─────────────────────────────────────────────
#  STEP 9 — SELECT FILES TO DOWNLOAD
# ─────────────────────────────────────────────
def select_files(records):
    print("\n── Step 9: Select Files to Download ───────────\n")
    print("  Options:")
    print("    A         → Download ALL files")
    print("    0,1,2     → Download specific files by index (comma separated)")
    print("    0-3       → Download a range of files")
    print()

    total = len(records)

    while True:
        choice = input("  Your selection: ").strip().lower()

        if choice == "a":
            print(f"\n  → Downloading all {total} file(s).\n")
            return records

        # Range e.g. 0-3
        if "-" in choice and "," not in choice:
            try:
                parts = choice.split("-")
                start_i = int(parts[0].strip())
                end_i   = int(parts[1].strip())
                if 0 <= start_i <= end_i < total:
                    selected = records[start_i:end_i+1]
                    print(f"\n  → Downloading {len(selected)} file(s) (index {start_i}–{end_i}).\n")
                    return selected
                else:
                    print(f"  ⚠️  Range must be within 0–{total-1}.")
            except (ValueError, IndexError):
                print("  ⚠️  Invalid range format. Use e.g. 0-3")
            continue

        # Comma separated e.g. 0,2,4
        try:
            indices = [int(x.strip()) for x in choice.split(",")]
            if all(0 <= i < total for i in indices):
                selected = [records[i] for i in indices]
                names    = ", ".join(r.get("filename","") for r in selected)
                print(f"\n  → Downloading {len(selected)} file(s): {names}\n")
                return selected
            else:
                print(f"  ⚠️  All indices must be within 0–{total-1}.")
        except ValueError:
            print("  ⚠️  Invalid input. Enter 'A', a range like '0-3', or indices like '0,2,4'.")


# ─────────────────────────────────────────────
#  SUBMIT + DOWNLOAD EACH FILE
# ─────────────────────────────────────────────
def submit_download(session, host, record):
    url = f"https://{host}/p/logview/downloadLogSubmit/"
    params = {
        "downloadtype":   "logbrowse",
        "download_token": "12345",
        "logformat":      "text",
        "logzip":         "0",
        "devoid":         record["device_id"],
        "filename":       record["filename"],
        "filepath":       record["filepath"],
        "vdom":           record["vdom_name"]
    }
    resp = session.get(url, params=params, verify=False)
    resp.raise_for_status()

    data = resp.json()
    if data.get("status") != "ok":
        raise Exception(f"Submit failed: {json.dumps(data)}")

    temp_filepath      = data.get("filepath", "")
    temp_download_name = data.get("download_name", "")

    if not temp_filepath:
        raise Exception("Submit returned empty filepath — check devoid value.")

    return temp_filepath, temp_download_name


def download_file(session, host, temp_filepath, temp_download_name, save_path):
    url = f"https://{host}/p/logview/fileDownload/logbrowse/"
    params = {
        "filepath":       temp_filepath,
        "del":            "1",
        "download_name":  temp_download_name,
        "download_token": "99999"
    }
    resp = session.get(url, params=params, verify=False, stream=True)

    if resp.status_code != 200:
        raise Exception(f"Download returned HTTP {resp.status_code}")

    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def download_all(session, host, selected_records):
    print("\n── Downloading ─────────────────────────────────\n")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total    = len(selected_records)
    success  = 0
    failures = []

    for i, record in enumerate(selected_records):
        filename  = record.get("filename", f"file_{i}")
        device_id = record.get("device_id", "unknown")
        vdom      = record.get("vdom_name", "root")

        print(f"  [{i+1}/{total}] {filename}  |  {device_id}  |  vdom: {vdom}")

        try:
            temp_filepath, temp_download_name = submit_download(session, host, record)
            print(f"           ✅ Submit OK → {temp_filepath}")

            safe_name = sanitize_filename(f"{device_id}_{vdom}_{filename}")
            save_path = os.path.join(OUTPUT_DIR, safe_name)

            download_file(session, host, temp_filepath, temp_download_name, save_path)
            size_kb = os.path.getsize(save_path) / 1024
            print(f"           ✅ Saved  → {save_path}  ({size_kb:.1f} KB)\n")
            success += 1

        except Exception as e:
            print(f"           ❌ Failed: {e}\n")
            failures.append({"file": filename, "error": str(e)})

    print("── Download Summary ────────────────────────────\n")
    print(f"  ✅ Downloaded : {success} / {total}")
    if failures:
        print(f"  ❌ Failed     : {len(failures)}")
        for f in failures:
            print(f"     • {f['file']} — {f['error']}")
    print(f"\n  📁 Files saved to: {os.path.abspath(OUTPUT_DIR)}\n")


# ─────────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────────
def logout(session, host):
    try:
        session.post(f"https://{host}/p/logout-api/", verify=False)
        print("  ✅ Logged out. Goodbye!\n")
    except Exception:
        pass


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()
    session = requests.Session()

    try:
        # Step 1 — Connection details
        host, username, password = get_connection_details()

        # Step 2 — Login
        login(session, host, username, password)

        # Step 3 — Fetch & select ADOM
        adoms = fetch_adoms(session, host)
        adom  = select_adom(adoms)

        # Step 4 — Switch to selected ADOM
        switch_adom(session, host, adom)

        # Step 5 — Fetch devices in selected ADOM
        devs = fetch_devices(session, host, adom["oid"])

        # ── Main loop — keep session alive for multiple downloads ──
        while True:

            # Step 6 — Select device
            devid = select_device(devs)

            # Step 7 — Date range
            start_time, end_time = get_date_range()

            # Step 8 — Search logs
            records = search_logs(session, host, devid, start_time, end_time)

            if records:
                # Step 9 — Select which files to download
                selected = select_files(records)

                # Download
                download_all(session, host, selected)

            # Ask if user wants to download more
            print("── What's next? ────────────────────────────────\n")
            print("  1 → Search & download more logs (same ADOM)")
            print("  2 → Switch to a different ADOM")
            print("  3 → Logout and exit")
            print()

            while True:
                next_action = input("  Your choice [1/2/3]: ").strip()
                if next_action in ("1", "2", "3"):
                    break
                print("  ⚠️  Enter 1, 2, or 3.")

            if next_action == "1":
                # Loop back to device selection
                print()
                continue

            elif next_action == "2":
                # Re-fetch and switch ADOM
                adoms = fetch_adoms(session, host)
                adom  = select_adom(adoms)
                switch_adom(session, host, adom)
                devs  = fetch_devices(session, host, adom["oid"])
                continue

            else:
                # Logout and exit
                break

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user.\n")
    except Exception as e:
        print(f"\n  ❌ Error: {e}\n")
    finally:
        logout(session, host)


if __name__ == "__main__":
    main()
