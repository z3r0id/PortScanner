# PortScanner
 Threadable object-oriented Python port scanner

ARGUMENTS:
==============
[-h] -d DEST [-p PORT] [-T THREADS] [-t TIMEOUT] [-o OUTPUT] [--curl] [--wget] [--debug]

Usage: python portscanner.py [-d DESINATION IP/range] [-p PORT-RANGE] [-o FILENAME] [--curl]

optional arguments:
  -h, --help            show this help message and exit
  -d DEST, --dest DEST  IP of server
  -p PORT, --port PORT  Single port or range, i.e 1-65535
  -T THREADS, --threads THREADS
                        max number of threads to be created when scanning
  -t TIMEOUT, --timeout TIMEOUT
                        TCP Timeout
  -o OUTPUT, --output OUTPUT
                        File to output results to
  --curl                curl any HTTP/s hosted on discovered ports (IN DEVELOPMENT)
  --wget                wget any FTP hosted on discovered ports (IN DEVELOPMENT)
  --debug               True/False turn on verbose debugging


EXAMPLES:
=====================
# basic scan of network range
portscanner -d 192.168.1.1-254 

# threaded network range scan (10 threads)
portscanner -d 192.168.1.1-254 -T 10

# scan of all ports on single host
portscanner -d 192.168.1.10 -p 1-65535

# output results to specific file
portscanner -d 192.168.1-50 -o outputfile.txt

# set the tcp timeout
portscanner -d 192.168.1.10 -t 0.01