# orca

                  ,pW"Wq.  `7Mb,od8   ,p6"bo     ,6"Yb.  
                 6W'   `Wb   MM' "  '6M'  OO    8)   MM  
                 8M     M8   MM      8M          ,pm9MM  
                 YA.   ,A9   MM      YM.    ,   8M   MM  
                  `Ybmd9'  .JMML.     YMbmd'    `Moo9^Yo.

A Padding Oracle exploitation script in Python because I love PadBuster, but I always wanted to have my own version in Python.
## Features
 - Standard detection methods: HTTP status code, response length, keyword searches, location header
 - Advanced detection methods: HTTP/1.1 and HTTP/2 Time-based detection mechanisms for semi-blind padding oracles 
## Requirements
 - h2spacex - HTTP/2 low level library based on Scapy which can be used for Single Packet Attack (Race Condition on H2) https://github.com/nxenon/h2spacex
 - requests - HTTP for Humans™ https://requests.readthedocs.io/en/latest/
## Installation
```
pip install h2spacex
pip install requests
```
