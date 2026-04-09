# FortiAnalyzer Log Downloader (FAZ_Log_Downloader)

A Python-based utility to download logs from FortiAnalyzer using its API. This script simplifies log extraction for analysis, auditing, and reporting purposes. It connects to the FortiAnalyzer system, authenticates using user credentials, retrieves logs based on defined parameters, and stores them locally for further use.

## Project Structure
FAZ_Log_Downloader/
│── faz_log_downloader.py   (Main script)
│── README.md               (Documentation)

## Requirements

- Python 3.x  
- `requests` library  

Install dependencies:

```bash
pip install requests

## Usage
Before running the script, update the configuration variables inside faz_log_downloader.py such as:
FAZ_IP = "your_fortianalyzer_ip"
USERNAME = "your_username"
PASSWORD = "your_password"

To run the script, use:
python faz_log_downloader.py

The script connects to the FortiAnalyzer API, authenticates using the provided credentials, sends a log query request, retrieves logs (handling batching if necessary), and saves the output locally.

Ensure that API access is enabled on your FortiAnalyzer device and that the user account being used has sufficient permissions to access logs. Large log queries may take time to process and may require pagination adjustments depending on the volume of data.

The script can be customized to include filters such as time range, source, destination, or specific log types. Output formats can also be adjusted to CSV, JSON, or other preferred structures. 

## Notes
Contributions are welcome. You can fork the repository, make improvements, and submit pull requests.

Author: Farhan Ahmed
Website: www.farhan.ch
GitHub: https://github.com/ilfarhanahmed

If you find this project useful, consider giving it a star on GitHub.
