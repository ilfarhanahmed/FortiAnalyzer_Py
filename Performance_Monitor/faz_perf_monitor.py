#!/usr/bin/env python3

"""
FortiAnalyzer System Performance Monitor
Author: Farhan Ahmed - www.farhan.ch
"""

import argparse
import configparser
import os
import sys
import time
import shutil
from datetime import datetime

import requests
import urllib3


PERFORMANCE_API_PATH = "/fazsys/monitor/system/performance/status"
LOG_FORWARD_API_PATH = "/fazsys/monitor/logforward-status"


# Helper functions
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def color(text, code, enabled=True):
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(text, enabled=True):
    return color(text, "31", enabled)


def yellow(text, enabled=True):
    return color(text, "33", enabled)


def green(text, enabled=True):
    return color(text, "32", enabled)


def cyan(text, enabled=True):
    return color(text, "36", enabled)


def bold(text, enabled=True):
    return color(text, "1", enabled)


def safe_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


def kb_to_gib(value):
    return safe_float(value) / 1024 / 1024


def percent(used, total):
    used = safe_float(used)
    total = safe_float(total)

    if total <= 0:
        return 0.0

    return used / total * 100


def health_label(value):
    value = safe_float(value)

    if value >= 90:
        return "CRITICAL"
    if value >= 80:
        return "WARNING"

    return "GOOD"


def health_color(text, value, enabled=True):
    value = safe_float(value)

    if value >= 90:
        return red(text, enabled)
    if value >= 80:
        return yellow(text, enabled)

    return green(text, enabled)


def make_bar(value, width=30, color_enabled=True):
    value = max(0, min(100, safe_float(value)))

    filled = int((value / 100) * width)
    empty = width - filled

    bar = "█" * filled + "░" * empty

    if value >= 90:
        return red(bar, color_enabled)
    if value >= 80:
        return yellow(bar, color_enabled)

    return green(bar, color_enabled)


def normalize_jsonrpc_url(url):
    url = url.strip().rstrip("/")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if not url.endswith("/jsonrpc"):
        url += "/jsonrpc"

    return url


def mask_api_key(api_key):
    if not api_key:
        return "N/A"

    if len(api_key) <= 8:
        return "****"

    return api_key[:4] + "..." + api_key[-4:]

def parse_verify_ssl(value):
    value = str(value).strip()

    if value.lower() in ("true", "yes", "1", "on"):
        return True

    if value.lower() in ("false", "no", "0", "off"):
        return False

    # Anything else is treated as CA certificate file path
    if not os.path.exists(value):
        raise FileNotFoundError(f"SSL CA certificate file not found: {value}")

    return value

def load_config(config_file):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")

    config = configparser.ConfigParser()
    config.read(config_file)

    if "faz" not in config:
        raise ValueError("Missing [faz] section in config file")

    faz = config["faz"]

    url = faz.get("url", "").strip()
    api_key = faz.get("api_key", "").strip()
    verify_ssl = parse_verify_ssl(faz.get("verify_ssl", fallback="false"))
    interval = faz.getint("interval", fallback=5)

    if not url:
        raise ValueError("Missing 'url' under [faz] in config file")

    if not api_key:
        raise ValueError("Missing 'api_key' under [faz] in config file")

    return {
        "url": normalize_jsonrpc_url(url),
        "api_key": api_key,
        "verify_ssl": verify_ssl,
        "interval": interval
    }


def build_api_body(api_path):
    return {
        "id": "3",
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": api_path,
                "apiver": 3
            }
        ]
    }


def fetch_api_data(url, api_key, api_path, verify_ssl, timeout):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    response = requests.post(
        url,
        headers=headers,
        json=build_api_body(api_path),
        verify=verify_ssl,
        timeout=timeout
    )

    response.raise_for_status()

    payload = response.json()

    result = payload.get("result")

    if isinstance(result, list):
        result = result[0] if result else None

    if not result:
        raise RuntimeError(f"Missing result in API response: {payload}")

    status = result.get("status", {})

    if status.get("code") != 0:
        raise RuntimeError(f"FAZ API error for {api_path}: {status}")

    if "data" not in result:
        raise RuntimeError(f"Missing result.data in API response: {payload}")

    return result.get("data")


def print_log_forward_status(log_forward_data, color_enabled=True):
    print()
    print(bold("Log Forwarding Status", color_enabled))
    print("-" * 120)

    if log_forward_data is None:
        print(yellow("Log forwarding status unavailable.", color_enabled))
        return

    if not isinstance(log_forward_data, list):
        print(yellow("Unexpected log forwarding data format.", color_enabled))
        return

    connected = 0
    disconnected = 0
    total_lograte = 0.0

    for item in log_forward_data:
        status = str(item.get("status", "unknown")).lower()
        lograte = safe_float(item.get("lograte"))

        total_lograte += lograte

        if status == "connected":
            connected += 1
        elif status == "disconnected":
            disconnected += 1

    total_visible_forwarders = connected + disconnected

    print(f"Visible Forwarders : {total_visible_forwarders}")
    print(f"Connected          : {green(str(connected), color_enabled)}")
    print(f"Disconnected       : {red(str(disconnected), color_enabled)}")
    print(f"Total Lograte      : {total_lograte:.4f} logs/sec")

    print()
    print(f"{'ID':<8} {'Status':<16} {'Lograte':>16}  Comment")
    print("-" * 120)

    for item in log_forward_data:
        forwarder_id = item.get("id", "N/A")
        status = str(item.get("status", "unknown")).lower()
        lograte = safe_float(item.get("lograte"))

        if status == "connected":
            status_text = green("connected", color_enabled)

            if lograte == 0:
                comment = "Connected, but current forwarding rate is 0"
            else:
                comment = "Forwarding logs"

        elif status == "disconnected":
            status_text = red("disconnected", color_enabled)
            comment = "Disconnected - check destination/connectivity"

        else:
            # In case FAZ returns any unexpected status in future
            status_text = yellow(status, color_enabled)
            comment = "Unknown status returned by FAZ"

        print(
            f"{str(forwarder_id):<8} "
            f"{status_text:<16} "
            f"{lograte:>12.4f} logs/sec  "
            f"{comment}"
        )

# DASHBOARD
def print_dashboard(perf_data, log_forward_data, url, masked_api_key, interval, color_enabled=True):
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    line_width = min(terminal_width, 120)

    cpu = perf_data.get("cpu", {})
    mem = perf_data.get("mem", {})
    disk = perf_data.get("disk", {})
    receive_lograte = perf_data.get("receive-lograte", {})
    insert_lograte = perf_data.get("insert-lograte", {})

    cpu_used = safe_float(cpu.get("used"))
    cpu_used_ex_nice = safe_float(cpu.get("used-excluded-nice"))
    cores = cpu.get("cores", [])

    mem_total = safe_float(mem.get("total"))
    mem_used = safe_float(mem.get("used"))
    mem_used_pct = percent(mem_used, mem_total)

    hard_disk = disk.get("hard-disk", {})
    flash_disk = disk.get("flash-disk", {})

    hard_total = safe_float(hard_disk.get("total"))
    hard_used = safe_float(hard_disk.get("used"))
    hard_used_pct = percent(hard_used, hard_total)

    flash_total = safe_float(flash_disk.get("total"))
    flash_used = safe_float(flash_disk.get("used"))
    flash_used_pct = percent(flash_used, flash_total)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(bold("FortiAnalyzer System Performance Monitor", color_enabled))
    print("=" * line_width)
    print(f"FAZ URL      : {cyan(url, color_enabled)}")
    print(f"API Key      : {masked_api_key}")
    print(f"Last Updated : {cyan(now, color_enabled)}")
    print(f"Refresh      : {cyan(str(interval) + ' seconds', color_enabled)}")
    print()

    print(bold("System Summary", color_enabled))
    print("-" * line_width)

    print(
        f"CPU Used       : {cpu_used:>8.2f}%  "
        f"{make_bar(cpu_used, 30, color_enabled)}  "
        f"{health_color(health_label(cpu_used), cpu_used, color_enabled)}"
    )

    print(
        f"CPU Excl Nice  : {cpu_used_ex_nice:>8.2f}%  "
        f"{make_bar(cpu_used_ex_nice, 30, color_enabled)}  "
        f"{health_color(health_label(cpu_used_ex_nice), cpu_used_ex_nice, color_enabled)}"
    )

    print(
        f"Memory Used    : {mem_used_pct:>8.2f}%  "
        f"{make_bar(mem_used_pct, 30, color_enabled)}  "
        f"{health_color(health_label(mem_used_pct), mem_used_pct, color_enabled)}  "
        f"({kb_to_gib(mem_used):.2f} GiB / {kb_to_gib(mem_total):.2f} GiB)"
    )

    print(
        f"Hard Disk Used : {hard_used_pct:>8.2f}%  "
        f"{make_bar(hard_used_pct, 30, color_enabled)}  "
        f"{health_color(health_label(hard_used_pct), hard_used_pct, color_enabled)}  "
        f"({kb_to_gib(hard_used):.2f} GiB / {kb_to_gib(hard_total):.2f} GiB)"
    )

    print(
        f"Flash Used     : {flash_used_pct:>8.2f}%  "
        f"{make_bar(flash_used_pct, 30, color_enabled)}  "
        f"{health_color(health_label(flash_used_pct), flash_used_pct, color_enabled)}  "
        f"({kb_to_gib(flash_used):.2f} GiB / {kb_to_gib(flash_total):.2f} GiB)"
    )

    print()
    print(bold("Lograte", color_enabled))
    print("-" * line_width)

    receive_5 = safe_float(receive_lograte.get("last-5sec"))
    receive_30 = safe_float(receive_lograte.get("last-30sec"))
    receive_60 = safe_float(receive_lograte.get("last-60sec"))
    insert_5 = safe_float(insert_lograte.get("last-5sec"))
    insert_60 = safe_float(insert_lograte.get("last-60sec"))

    print(f"Receive Lograte Last 5 sec  : {receive_5:.4f} logs/sec")
    print(f"Receive Lograte Last 30 sec : {receive_30:.4f} logs/sec")
    print(f"Receive Lograte Last 60 sec : {receive_60:.4f} logs/sec")
    print(f"Insert Lograte Last 5 sec   : {insert_5:.4f} logs/sec")
    print(f"Insert Lograte Last 60 sec  : {insert_60:.4f} logs/sec")

    if receive_60 > 0 and insert_60 < receive_60 * 0.5:
        print()
        print(yellow("WARNING: Insert lograte is much lower than receive lograte. Possible insertion backlog.", color_enabled))

    print()
    print(bold("Disk I/O Utilization", color_enabled))
    print("-" * line_width)
    print(f"Hard Disk iostat-util  : {safe_float(hard_disk.get('iostat-util')):.6f}%")
    print(f"Flash Disk iostat-util : {safe_float(flash_disk.get('iostat-util')):.6f}%")

    print()
    print(bold("CPU Core Details", color_enabled))
    print("-" * line_width)
    print(f"{'Core':<8} {'Used':>8} {'User':>8} {'System':>8} {'Nice':>8} {'Idle':>8} {'IOWait':>8}  Usage")
    print("-" * line_width)

    busiest_core = None

    for index, core in enumerate(cores, start=1):
        user = safe_float(core.get("user"))
        system = safe_float(core.get("system"))
        nice = safe_float(core.get("nice"))
        idle = safe_float(core.get("idle"))
        iowait = safe_float(core.get("iowait"))
        used = 100 - idle

        if busiest_core is None or used > busiest_core["used"]:
            busiest_core = {
                "core": index,
                "used": used
            }

        used_text = f"{used:.2f}%"

        print(
            f"CPU {index:<4} "
            f"{used_text:>8} "
            f"{user:>7.2f}% "
            f"{system:>7.2f}% "
            f"{nice:>7.2f}% "
            f"{idle:>7.2f}% "
            f"{iowait:>7.2f}%  "
            f"{make_bar(used, 25, color_enabled)}"
        )

    if busiest_core:
        print()
        msg = f"Busiest Core: CPU {busiest_core['core']} at {busiest_core['used']:.2f}%"
        print(health_color(msg, busiest_core["used"], color_enabled))

    print_log_forward_status(log_forward_data, color_enabled=color_enabled)

    print()
    print("Press Ctrl+C to stop.")

# MAIN
def main():
    parser = argparse.ArgumentParser(
        description="FortiAnalyzer live performance and log forwarding monitor using API key authentication"
    )

    parser.add_argument(
        "--config",
        default="faz_config.ini",
        help="Path to config file. Default: faz_config.ini"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds. Default: 10"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override refresh interval from config file"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors"
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Config error: {e}")
        sys.exit(1)

    url = config["url"]
    api_key = config["api_key"]
    verify_ssl = config["verify_ssl"]
    interval = args.interval if args.interval is not None else config["interval"]

    color_enabled = not args.no_color
    masked_api_key = mask_api_key(api_key)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        while True:
            try:
                perf_data = fetch_api_data(
                    url=url,
                    api_key=api_key,
                    api_path=PERFORMANCE_API_PATH,
                    verify_ssl=verify_ssl,
                    timeout=args.timeout
                )

                try:
                    log_forward_data = fetch_api_data(
                        url=url,
                        api_key=api_key,
                        api_path=LOG_FORWARD_API_PATH,
                        verify_ssl=verify_ssl,
                        timeout=args.timeout
                    )
                except Exception as log_forward_error:
                    log_forward_data = None

                clear_screen()

                print_dashboard(
                    perf_data=perf_data,
                    log_forward_data=log_forward_data,
                    url=url,
                    masked_api_key=masked_api_key,
                    interval=interval,
                    color_enabled=color_enabled
                )

            except Exception as e:
                clear_screen()
                print(red("Error fetching FortiAnalyzer performance data:", color_enabled))
                print(str(e))
                print()
                print("Retrying... Press Ctrl+C to stop.")

            if args.once:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        print("Stopped.")


if __name__ == "__main__":
    main()