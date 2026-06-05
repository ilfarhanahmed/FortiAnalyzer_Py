# FortiAnalyzer_Py

Python utilities for FortiAnalyzer automation, log retrieval, log file downloads, and live performance monitoring.

This repository contains practical scripts for working with FortiAnalyzer APIs from a terminal. The tools are useful for support, troubleshooting, log collection, auditing, and quick visibility into FortiAnalyzer system health.


## Requirements

General requirements:

- Python 3.x
- FortiAnalyzer reachable over HTTPS
- FortiAnalyzer admin/API access
- Required permissions to read ADOMs, devices, logs, and system monitor data

Python packages used by some tools:

```bash
pip install requests urllib3
```


## FortiAnalyzer Access Notes

Depending on the script, you may need one of the following authentication methods:

- Username and password login.
- API key / bearer token.
- JSON-RPC permission enabled for the FortiAnalyzer admin account.
- Trusted host configured for the admin/API user.
- Sufficient permissions to access logs, ADOMs, devices, and monitor endpoints.


## SSL Verification

Some scripts are designed for lab or internal FortiAnalyzer environments where self-signed certificates are common. In those cases, SSL verification may be disabled by default.

For production or customer environments, it is recommended to enable SSL verification.


## Author

***Farhan Ahmed***  
Website: [www.farhan.ch](https://www.farhan.ch)  
GitHub: [@ilfarhanahmed](https://github.com/ilfarhanahmed)
Postman: [@ilfarhanahmed](https://postman.com/ilfarhanahmed)

## License

This project is licensed under the MIT License. See the [`LICENSE`](./LICENSE) file for details.
