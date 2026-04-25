# FortiAnalyzer Log Fetcher

A high-reliability Python utility designed for forensic-grade log retrieval from FortiAnalyzer (FAZ). Optimized for large datasets, this tool ensures no logs are missed by strictly adhering to backend indexing states.

## 🚀 Advanced Features

- **"Verify-Before-Fetch" Logic**: 
  Standard scripts often request data as soon as the global search starts. This script uses a two-tier verification:
    * **Index Polling**: Waits for the FAZ to locate all matching records.
    * **Chunk Validation**: For every 1,000 logs, it verifies the specific memory offset is 100% ready before downloading, preventing "empty page" errors common in high-load environments.
- **Environment Intelligence**:
  Automatically detects `PYCHARM_HOSTED`. In PyCharm, it uses standard input to avoid the "GetPass Warning" hang; in standard terminals, it uses masked input for security.
- **Resilient Multi-ADOM Loops**:
  If fetching multiple ADOMs, the script cleans up the Search ID (`tid`) after each one to manage FAZ memory usage effectively.

## 📋 Technical Workflow



1. **Authentication**: Establishes a session and retrieves a token.
2. **Indexing (Step 8)**: The FAZ builds a temporary index of matches. The script polls `/count/` until `progress-percent` is 100.
3. **Sequential Retrieval (Step 9)**: 
   - Requests logs from `offset 0` to `1000`.
   - Checks the JSON response for `"percentage": 100`.
   - If less than 100, it waits and retries the same offset.
   - Once 100, it saves and moves to `offset 1000`.
4. **Cleanup**: Explicitly calls the `delete` method for the search task to free up FAZ system resources.

## 🔍 Log Filter Cheat Sheet

When prompted in **Step 5**, you can use FortiAnalyzer filter syntax:

| Objective         | Filter String Example         |
|:------------------|:------------------------------|
| **Specific IP**   | `srcip=192.168.1.50`          |
| **Action & Port** | `action=deny and dstport=443` |
| **User Search**   | `user="j.doe"`                |
| **Threat Level**  | `level=warning`               |
| **Exclusion**     | `dstip!=10.0.0.1`             |
| **Sub Type**      | `subtype=VPN`                 |

## 🛠️ Configuration & Defaults

- **POLL_INTERVAL**: Set to 2 seconds. Balancing between speed and API overhead.
- **API_Timeout**: 60 seconds for API responses to handle slow database queries.

## 📦 Output Structure

Files are saved in the `./logs/` directory with the following naming convention:
`faz_[ADOM]_[LogType]_[Timestamp].[Ext]`

*Example: `faz_root_traffic_20260413_143005.csv`*

---
**Note:** This script uses `ssl._create_unverified_context()`. Ensure your network path is secure when connecting over public networks.
