# FortiAnalyzer Performance Monitor

A Python terminal monitor for FortiAnalyzer system performance and log forwarding status.

## Features

- CPU usage
- Per-core CPU usage
- Memory usage
- Disk usage
- Disk I/O utilization
- Receive and insert lograte
- Log forwarding connected/disconnected status
- Auto-refresh every few seconds

## API Endpoints Used

```text
/fazsys/monitor/system/performance/status
/fazsys/monitor/logforward-status
```

## Usage

- On FAZ create an API Admin user with JSON-RPC permission set to atleast 'Read'.
- Set trusted host subnet for the admin user.

### Install Requirements
```text
pip install -r requirements.txt
```
### Copy the example config
```text
cp faz_config.example.ini faz_config.ini
```
### Edit faz_config.ini
- Set the FAZ IP or FQDN 
- Set the API KEY
- Set the "internal" in seconds - monitor refresh rate
```text
[faz]
url = https://<FAZ_IP_or_FQDN>/jsonrpc
api_key = <API_KEY>
verify_ssl = false
interval = 5
```
### Run
```python
python faz_perf_monitor.py
```
Run Once:
```python
python faz_perf_monitor.py --once
```
Use a different config file:
```python
python faz_perf_monitor.py --config /path/to/faz_config.ini
```

Override refresh interval:
```python
python faz_perf_monitor.py --interval 10
```


## ⚠️ Security

SSL verification is disabled by default (`verify=False`) to support self-signed
certificates. To enable verification, in the **faz_config** file:

#### If using the FQDN - make sure it matches the certificate, not just the IP:
```text
verify_ssl = true
```

#### OR
Set the path to FortiAnalyzer Certificate
```text
verify_ssl = certs/faz-ca.pem
```

replace with your
FortiAnalyzer's CA certificate path :

```python
session.verify = "/path/to/ca-cert.pem"
```