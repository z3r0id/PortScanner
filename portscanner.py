import argparse
import socket
import datetime
import threading
import os
import rich
from rich.tree import Tree
from rich import print
from rich.progress import track
from rich.progress import Progress
import Scanners
import datetime

parser = argparse.ArgumentParser(
    prog='''
     _______  _______  _______ _________ _______  _______  _______  _        _        _______  _______ 
    (  ____ )(  ___  )(  ____ )\__   __/(  ____ \(  ____ \(  ___  )( (    /|( (    /|(  ____ \(  ____ )
    | (    )|| (   ) || (    )|   ) (   | (    \/| (    \/| (   ) ||  \  ( ||  \  ( || (    \/| (    )|
    | (____)|| |   | || (____)|   | |   | (_____ | |      | (___) ||   \ | ||   \ | || (__    | (____)|
    |  _____)| |   | ||     __)   | |   (_____  )| |      |  ___  || (\ \) || (\ \) ||  __)   |     __)
    | (      | |   | || (\ (      | |         ) || |      | (   ) || | \   || | \   || (      | (\ (   
    | )      | (___) || ) \ \__   | |   /\____) || (____/\| )   ( || )  \  || )  \  || (____/\| ) \ \__
    |/       (_______)|/   \__/   )_(   \_______)(_______/|/     \||/    )_)|/    )_)(_______/|/   \__/
                                                                                                                       
    ''',
    description='''
    Usage: python portscanner.py [-d DESINATION IP/range] [-p PORT-RANGE] [-o FILENAME] [--curl]\n
    ''',
    epilog='\nI am not responsible for your dumb ass \n')

parser.add_argument("dest", help="IP or range of target(s)")
parser.add_argument("-p", "--port", help="Single port or range, i.e 1-65535")
parser.add_argument("-T", "--threads", help="max number of threads to be created when scanning", default=1)
parser.add_argument("-t", "--timeout", help="TCP Timeout",default="0.05")
parser.add_argument("-o", "--output", help="File to output results to",default="scan_transcript.txt")
parser.add_argument("--web", help="links any HTTP/s hosted on discovered ports", default=False, action="store_true")
parser.add_argument("--debug", help="True/False turn on verbose debugging",default=False,action="store_true")


args = parser.parse_args()

#####################
#    GET IP RANGE   #
#####################

def get_ip_range(ip_arg):
    addresses = []

    splitaddr = str(ip_arg).split(".")
    # create the head and tail part of the addresses (i.e. head 192.168.1 | tail 1-254)
    head = splitaddr[0:3]
    head = str('.'.join(head))
    tail = splitaddr[-1]
    # use the tail to create the range and generate final list
    addr_range = tail.split('-')

    for i in range(int(addr_range[0]),int(addr_range[-1])+1):
        addresses.append(head +'.'+str(i))
    if args.debug:
        print("DEBUG: " +"[red]address list: "  +str(addresses))

    return addresses


#####################
#  GET PORT RANGE   #
#####################

def get_port_range(port_input):
    ports = []
    if port_input:
        portlist = str(port_input).split("-")
        porttotal = int(portlist[-1]) - int(portlist[0])

        # create port range list
        for i in range(int(portlist[0]),int((portlist[-1]))+1):
            ports.append(i)
        
    else:
        # IF NO PORT ARGS GIVEN:
        ports = [20,21,22,80,443,3389]
        if args.debug:
            print("DEBUG: " +"[red]Using default ports")
    return ports

########################
# FILE OUTPUT FUNCTION #
########################

def output(results,banners,fname):
    """Outputs scan results into given file.
    :param results: dict - dictionary of host:port combos
    :param banners: list - banner grabs from any port that responded
    :param fname: str - name of file to be written to
    """
    ## expects results as a dict

    f = open("{}".format(fname),'a')
    if args.debug:
        print("DEBUG: " +"[red]opened file " + f.name)

    for k in results:
        f.write(k +": "+ str(results.get(k)) + "\n")
    for b in banners:
        f.write(b + "\n")
    f.write("""\n =======================================================\n
    """)
    f.close()
    if args.debug:
        print("DEBUG: " +"[red]closed file " + f.name)
    print("SAVED RESULTS TO: " + str(fname))




##################################################################################
#                     __  __          _____ _   _ 
#                    |  \/  |   /\   |_   _| \ | |
#                    | \  / |  /  \    | | |  \| |
#                    | |\/| | / /\ \   | | | . ` |
#                    | |  | |/ ____ \ _| |_| |\  |
#                    |_|  |_/_/    \_\_____|_| \_|
#
##################################################################################

print("Initializing port scanner...")
start_time = datetime.datetime.now()

addresses = get_ip_range(args.dest)
print("Scanning " + str(len(addresses)) + " total addresses")
ports = get_port_range(args.port)
print("INFO: Scanning "+ str(len(ports)) + " ports per host")

#
# CREATE THE SCANNER OBJECT
#
scanner = Scanners.Scanner(args.threads,args.timeout,addresses,ports)
if args.debug:
    scanner.debug = True
#   scanner.Scanner(hosts_and_ports, num_threads, tcp_timeout, q, addresses, ports, debug)

#
# GENERATE THE THREADS
#
scanner.gen_threads(args.threads)


#
### ITERATE AND SCAN PORTS
#
for d in track(addresses,description='[green bold] COMPILING THREAD QUEUE '):
    for p in ports:
        # generate queue items encoded into a list of host:port combos
        qitem = "{}:{}".format(d,p)
        scanner.q.put(qitem)


scanner.q.join()
print("[green bold blink]WAITING FOR SCAN COMPLETION...")

end_time = datetime.datetime.now()

print('''
###########
# RESULTS #
###########
''')

print("""Live hosts found: 
==================""")
#iterate through dict and create results tree
tree = Tree("+ Scan Results +")
for k,v in scanner.hosts_and_ports.items():
    t = tree.add('[green]' + k)
    p = t.add('[blue]' + str(v))



#print results
print(tree)
if args.web:
    for k,v in scanner.hosts_and_ports.items():
        if '80' in v:
            print("[blue bold]Web interface identified: "+"[green bold]http://{}".format(k))
        if '443' in v:
            print("[blue bold]Web interface identified: "+"[green bold]https://{}".format(k))

#print completion time
print("\n[green bold]SCAN COMPLETED IN: " + str(end_time - start_time)+"\n")

#save the final results to a transcript file
output(scanner.hosts_and_ports, scanner.banners, args.output)

