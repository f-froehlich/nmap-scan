Nmap scan
=========
Nmap wrapper for python with ***full Nmap DTD support***, parallel scans and threaded callback methods support for faster analytics.

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


scanner.scan_udp_background(callback_method)
scanner.scan_tcp_background(callback_method)

scanner.wait_all()

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

