# DNS Rebinder

Lightweight DNS Server to perform DNS rebinding attacks.

# How it works

The desired answers to DNS queries are encoded into the hostname. This way, no additional communication is required while also staying flexible (i.e. no hardcoded IP addresses). The expected hostname format is `randstring_ip1_ip2.domain` where randstring could e.g. be the current timestemp. The IP addresses are encoded as 32-bit values in hexadecimal representation, thus e.g. 127.0.0.1 becomes 7f000001. A complete DNS request that will first resolve to 216.58.208.46 (Google), then to 127.0.0.1 could thus look like this: `1337_d83ad02e_7f000001.dnsrebinder.whatever.net`.

Upon seing a hostname for the first time, the server will respond with IP1. Subsequent requests for the same hostname will be answered with IP2. Additionally, the format `randstring_ip.domain` is supported, in which case the server will always respond with the provided IP address. All other requests will be answered with a hardcoded IP address (currently 1.3.3.7).

To avoid overly high memory usage, seen entries will be flushed on a regular basis (currently once per hour).
