# orca

                  ,pW"Wq.   `7Mb,od8    ,p6"bo     ,6"Yb.  
                 6W'   `Wb    MM' "   '6M'  OO    8)   MM  
                 8M     M8    MM       8M          ,pm9MM  
                 YA.   ,A9    MM       YM.    ,   8M   MM  
                  `Ybmd9'   .JMML.      YMbmd'    `Moo9^Yo.

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
## Usage
```
usage: orca.py [-h] [--headers HEADERS] [--keyword KEYWORD] [--noiv NOIV] [--lengthvariation LENGTHVARIATION]
               [--allow302redirects ALLOW302REDIRECTS] [--protocol PROTOCOL] [--repeatruns REPEATRUNS]
               [--delayiftimebased DELAYIFTIMEBASED] [--http2groupsize HTTP2GROUPSIZE]
               url ciphertext encoding method blocksize body

A Padding Oracle exploitation toolkit in python.

positional arguments:
  url                   Target URL - examples https://example.com:8081/page.aspx, http://example.com,
                        https://127.0.0.1:8080
  ciphertext            The ciphertext to attack - can be base64 encoded or a string of hex bytes. Provide a URL-
                        decoded version. URL-encoding will be applied on output.
  encoding              base64 / None
  method                GET / POST
  blocksize             8 / 16 / etc
  body                  This is the POST body OR the GET query - it will have all the parameter names and values
                        needed for the request and the ciphertext must match the provided ciphertext. A JSON body can
                        also be provided.

options:
  -h, --help            show this help message and exit
  --headers HEADERS     Dictionary format: {'Cookie': '123561762351635'} - Note: Content-Type: application/x-www-form-
                        urlencoded OR application/json headers are auto-added for POST method.
  --keyword KEYWORD     A custom keyword to search responses for.
  --noiv NOIV           e.g. True - Activate 'no IV mode'.
  --lengthvariation LENGTHVARIATION
                        e.g. 20 / 30 / 40 Provide a number of bytes for the detection engine to ignore when the
                        content length varies. Set to 99999 to disable length checking altogether.
  --allow302redirects ALLOW302REDIRECTS
                        e.g. True / False. The requests engine will allow redirects by default, but you can disable
                        them by passing this flag. (HTTP1 only)
  --protocol PROTOCOL   HTTP1 / HTTP2 (Time-based only). This selects between the two time comparison engines. HTTP1
                        is a simple, orthodox response time comparison based detection engine, while HTTP2 is a Single
                        Packet Attack base advanced timing engine.
  --repeatruns REPEATRUNS
                        e.g. 1 / 2 / 4 / 8 (Time-based only, HTTP/1 only). How many times to repeat the measurement
                        for each byte. The HTTP1 engine can perform multiple scans and average the time difference
                        over these. Increases accuracy, but increases scan time also.
  --delayiftimebased DELAYIFTIMEBASED
                        Add a delay to HTTP1 time-based attack. (Time-based only, HTTP/1 only). Increases accuracy,
                        but increases scan time also.
  --http2groupsize HTTP2GROUPSIZE
                        e.g. 4 / 8 / 16 - Number of requests to include in each SPA. (Time-based only, HTTP/2 only).
                        Sets the number of requests to send per SPA. 4 is the mose accurate, but will also take the
                        longest.
```
