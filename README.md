# Check Version of Microsoft Exchange 
Easy way to check Microsoft Exchange version and find vulnerable host. 
To compare version and patch use the site: https://buildnumbers.wordpress.com/exchange/
To search for Microsoft Exchange around the world use our service https://netlas.io/

# Code
[NSE](exchange-version.nse) for one host check.

[Python script](check_version.py) with nelas API for mass check. set netlas api key (https://netlas.io/) in code and install netlas-sdk (pip3 install netlas)

# Working Principle 

One request to url /owa for OWA detection
## Microsoft Exchange 2019, 2016
One request to url /ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application
## Microsoft Exchange 2013
Brute $version to URL /ecp/$VERSION/exporttool/microsoft.exchange.ediscovery.exporttool.application
## Old Microsoft Exchange
Version is the same as version OWA

# Proxylogon
Versions not vulnerable for Proxylogon (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065):

may_update = ["15.2.858.12", "15.2.792.15", "15.1.2242.10", "15.1.2176.14", "15.0.1497.18"]

april_update = ["15.2.858.9","15.2.792.13","15.1.2242.8", "15.1.2176.12", "15.0.1497.15", "15.1.2242.5"]

march_update = ["15.2.858.5",
            "15.2.792.10",
            "15.2.721.13",
            "15.2.659.12",
            "15.2.595.8",
            "15.2.529.13",
            "15.2.464.15",
            "15.2.397.11",
            "15.2.330.11",
            "15.2.221.18",
            "15.1.2242.4",
            "15.1.2176.9",
            "15.1.2106.13",
            "15.1.2044.13",
            "15.1.1979.8",
            "15.1.1913.12",
            "15.1.1847.12",
            "15.1.1779.8",
            "15.1.1713.10",
            "15.1.1591.18",
            "15.1.1531.12",
            "15.1.1466.16",
            "15.1.1415.10",
            "15.0.1497.12",
            "15.0.1473.6",
            "15.0.1395.12",
            "15.0.847.64",
            "14.3.513.0",
            "15.2.858.2"]