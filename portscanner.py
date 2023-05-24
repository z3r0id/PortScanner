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
import scanner
import datetime

parser = argparse.ArgumentParser(
    prog='''
     ______   ______     _______  _______  _______ _________ _______  _______  _______  _        _        _______  _______ 
    (  __  \ (  ___ \   (  ____ )(  ___  )(  ____ )\__   __/(  ____ \(  ____ \(  ___  )( (    /|( (    /|(  ____ \(  ____ )
    | (  \  )| (   ) )  | (    )|| (   ) || (    )|   ) (   | (    \/| (    \/| (   ) ||  \  ( ||  \  ( || (    \/| (    )|
    | |   ) || (__/ /   | (____)|| |   | || (____)|   | |   | (_____ | |      | (___) ||   \ | ||   \ | || (__    | (____)|
    | |   | ||  __ (    |  _____)| |   | ||     __)   | |   (_____  )| |      |  ___  || (\ \) || (\ \) ||  __)   |     __)
    | |   ) || (  \ \   | (      | |   | || (\ (      | |         ) || |      | (   ) || | \   || | \   || (      | (\ (   
    | (__/  )| )___) )  | )      | (___) || ) \ \__   | |   /\____) || (____/\| )   ( || )  \  || )  \  || (____/\| ) \ \__
    (______/ |/ \___/   |/       (_______)|/   \__/   )_(   \_______)(_______/|/     \||/    )_)|/    )_)(_______/|/   \__/
                                                                                                                       
    ''',
    description='''
    Usage: python portscanner.py [-d DESINATION IP/range] [-p PORT-RANGE] [-o FILENAME] [--curl]\n
    ''',
    epilog='\nI am not responsible for your dumb ass \n')

parser.add_argument("-d", "--dest", help="IP of server", required=True)
parser.add_argument("-p", "--port", help="Single port or range, i.e 1-65535")
parser.add_argument("-T", "--threads", help="max number of threads to be created when scanning", default=1)
parser.add_argument("-t", "--timeout", help="TCP Timeout",default="0.05")
parser.add_argument("-o", "--output", help="File to output results to",default="scan_transcript.txt")
parser.add_argument("--curl", help="curl any HTTP/s hosted on discovered ports", default=False, action="store_true")
parser.add_argument("--wget", help="wget any FTP hosted on discovered ports", default=False, action="store_true")
parser.add_argument("--debug", help="True/False turn on verbose debugging",default=False,action="store_true")


args = parser.parse_args()


########################
# FILE OUTPUT FUNCTION #
########################

def output(results,banners,fname):
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




#################
# WGET FUNCTION #
#################


def wget(dest,port):
    
    #format the URL
    ftpstring = "ftp://" + str(dest) +":"+str(port)

    #exec the wget command 
    stream = os.popen('wget -r -q {}'.format(ftpstring))
    #read the stream
    output = stream.read()
    #save the screen-printed results to our output file
    if args.debug:
        print(output)
    return output       




#################
# CURL FUNCTION #
#################

def curl(dest,port):

    #format the URL
    httpstring = "http://" + str(dest) +":"+str(port)

    stream = os.popen('curl {} --silent'.format(httpstring))
    #read the stream
    output = stream.read()
    #return the screen-printed results to our output file
    if args.debug:
        print(output)
    return str(output)


##########
# SPIDER #
##########

def spider(host,port):
   return






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

addresses =[]
live_addresses =[]
ports =[]
curl_values ={}
addresses_and_ports = []

#split and get the pieces of the address
splitaddr = str(args.dest).split(".")
#create the head and tail part of the addresses
head = splitaddr[0:3]
head = str('.'.join(head))
tail = splitaddr[-1]
addr_range = tail.split('-')

for i in range(int(addr_range[0]),int(addr_range[-1])+1):
    addresses.append(head +'.'+str(i))
if args.debug:
    print("DEBUG: " +"[red]address list: "  +str(addresses))


print("Scanning " + str(len(addresses)) + " total addresses")
if args.port:
    portlist = str(args.port).split("-")
    porttotal = int(portlist[-1]) - int(portlist[0])

    #create port range list
    for i in range(int(portlist[0]),int((portlist[-1]))+1):
        ports.append(i)
    print("INFO: Scanning "+ str(porttotal) + " ports per host")
else:
    ports = [20,21,22,80,443,3389]
    if args.debug:
        print("DEBUG: " +"[red]Using default ports")
    print("INFO: Scanning "+ str(len(ports)) + " ports per host")


#
# CREATE THE SCANNER OBJECT
#
scanner = scanner.Scanner(args.threads,args.timeout,None,addresses,ports)
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


#
# CHECK FOR AND EXECUTE CURL/WGET
# 
    if args.curl:
        if args.debug:
            print("DEBUG: [red]Executing curl()")
        for h in scanner.hosts_and_ports.keys():
            #format and curl the target addr:port
            response = curl(h,'80')

            #write results to an html file
            f = open("{}-80.html".format(h),'w')
            if args.debug:
                print("DEBUG: [red]writing curl results to {}".format(f.name))
            f.write(response)
            f.close()

    if args.wget:
        if args.debug:
            print("DEBUG: [red]Executing wget()")
        for h in scanner.hosts_and_ports.keys():
            #format and curl the target addr:port
            response = wget(h,'21')
            #write results to file
            f = open("{}-21".format(h),'w')

            if args.debug:
                print("DEBUG: [red]writing wget results to {}".format(f.name))

            f.write(response)
            f.close()


print("[green bold blink]WAITING FOR SCAN COMPLETION...")
scanner.q.join()


end_time = datetime.datetime.now()

print('''
###########
# RESULTS #
###########
''')

print("""Live hosts found: 
==================""")
#iterate through dict and format results into output file
tree = Tree("+ Scan Results +")
for k,v in scanner.hosts_and_ports.items():
    t = tree.add('[green]' + k)
    p = t.add('[blue]' + str(v))




print(tree)

for k,v in scanner.hosts_and_ports.items():
    if '80' in v:
        print("[blue bold]Web interface identified: "+"[green bold]http://{}".format(k))
    if '443' in v:
        print("[blue bold]Web interface identified: "+"[green bold]https://{}".format(k))


print("\n[green bold]SCAN COMPLETED IN: " + str(end_time - start_time)+"\n")
#save the final results to a transcript file
output(scanner.hosts_and_ports, scanner.banners, args.output)

