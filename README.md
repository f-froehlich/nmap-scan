Nmap scan
=========
Nmap wrapper for python with ***full Nmap DTD support***, parallel scans and threaded callback methods support for faster analytics. You can also save your report to xml, json and html.

Copyright (c) 2020 Fabian Fröhlich <mail@nmap-scan.de> [https://nmap-scan.de](https://nmap-scan.de)

Full License Information see  [LICENSE](https://github.com/f-froehlich/nmap-scan/blob/master/LICENSE) file in root directory of this source code and License section of this File.

# Donate
This project needs donations. Please check out [https://nmap-scan.de/Donate](https://nmap-scan.de/Donate) for details.


# Quick setup
See our [documentation](https://nmap-scan.de) for details.

## Required
* install python 3.7 (other versions may also work)
* install python3-pip
* install [Nmap](https://github.com/nmap/nmap) 
* `pip3 install nmap-scan`

## Basic usage
Simple script to scan a network with parallel TCP and UDP scan and save the report into a file. Note that the `callback_method` is called asynchronous in the scanning thread of each scan method. If you don't need a callback on report finishing just remove the function call argument.
```python
from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.NmapScanMethods import NmapScanMethods
from nmap_scan.Scanner import Scanner

args = NmapArgs(['192.168.0.1/24'])
scanner = Scanner(args)

def callback_method(report, scan_method):
    filename = {
        NmapScanMethods.TCP: 'tcp',
        NmapScanMethods.UDP: 'udp',
    }

    report.save('reports/scan-' + filename.get(scan_method) + '.xml')
    report.save_html('reports/scan-' + filename.get(scan_method) + '.html')
    report.save_json('reports/scan-' + filename.get(scan_method) + '.json')


scanner.scan_udp_background(callback_method)
scanner.scan_tcp_background(callback_method)

# Do other stuff here

scanner.wait_all()

```

## Advanced usage
Simple script to scan multiple networks with different configurations. Each configuration is executed parallel and also each host will be scanned parallel. You can set up the maximum parallel threads per configuration (default 32) so in the following example it will execute nmap within 64 threads. To do so we first will create for each configuration a ping scan with your given hosts and even set `pn` from your `args` but all other arguments are ignored for the ping scan. Afterwords for each host it will create a scan thread with your `args` but update the hosts to the ip of the host resulted by the ping scan. You even can choose, if you want to scan every ip from the host or only the first (default). Of each executed scan (except the ping scan) we will call the `callback_method` asynchronous as in the **simple usage** mentored. If you don't need a callback on report finishing just remove the argument in the `MultiScannerConfiguration`. You can simply get all reports after execution with `get_reports()`it will automatically wait until the complete scan is finished.

```python
from nmap_scan.MultiScanner import MultiScanner
from nmap_scan.MultiScannerConfiguration import MultiScannerConfiguration
from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.NmapScanMethods import NmapScanMethods

args = NmapArgs(['192.168.0.10/24'])

def callback_method(ip, report, scan_method):
    filename = {
        NmapScanMethods.TCP: 'tcp',
        NmapScanMethods.UDP: 'udp',
    }
    report.save('reports/' + ip + '_' + filename.get(scan_method) + '.xml')
    report.save_html('reports/' + ip + '_' + filename.get(scan_method) + '.html')
    report.save_json('reports/' + ip + '_' + filename.get(scan_method) + '.json')


configs = [
    MultiScannerConfiguration(nmap_args=args, scan_method=NmapScanMethods.TCP, callback_method=callback_method),
    MultiScannerConfiguration(nmap_args=args, scan_method=NmapScanMethods.UDP, callback_method=callback_method),
]
scanner = MultiScanner(configs)
scanner.scan_background()

# Do other stuff here

reports = scanner.get_reports()

```

## Debugging

```python
import logging

logging.basicConfig(level=logging.DEBUG, filename='debug.log')
```

# License
This section contains the additional terms of the AGPLv3 license agreement, a copy of the AGPLv3 is included in the [LICENSE](https://github.com/f-froehlich/nmap-scan/blob/master/LICENSE) file.

1. Security analytic / "White had" use only.
2. You are only allowed to use this tool, if you don't act against a law of your Country and if you don't planning a cyber attack on the scanned servers.
3. You are only allowed to scan your own Servers and those, where you have the permission to do so.
4. Adaptation of the [README.md](https://github.com/f-froehlich/nmap-scan/blob/master/README.md) is prohibited. The file must also be included with each copy without any modification. 

5. Adjustments of any kind must be listed in the attached [CHANGELOG.md](https://github.com/f-froehlich/monitoring-utils/blob/master/CHANGELOG.md) file. It is sufficient to name the change and the reason for the change here and to give appropriate references to the processing in the source code at the appropriate place.

6. All edited copies must be made available on [github](https://github.com). You have to fork the original repository or use a fork from the original repository.

7. You have to place the following link on your Homepage in a suitable place, if you using this software in a commercial way:

    ```html
    We using server scan tools from <a href="https://nmap-scan.de">Fabian Fr&ouml;hlich</a>
   ```

    The wording is decisive here, so another language may be used. Attributes of the link may also be adjusted, but the link must be followable by web crawlers (e.g. Googlebot).

    Furthermore, the imprint has to include a clear reference to the original github repository [https://github.com/f-froehlich/nmap-scan](https://github.com/f-froehlich/nmap-scan) as well as the link mentioned above in the body text.
    
8. You are not allowed to earn money with this tool.

