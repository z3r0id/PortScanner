from queue import Queue
from threading import Thread
import socket
from rich import print
from rich.progress import track

class Scanner:
    """Primary Scanner class for basic TCP scanning.
:attribute num_threads: int - number of threads for execution
:attribute tcp_timeout: float - TCP connect timeout
:attribute addresses: list - IP addresses to scan
:attribute ports: list - TCP ports to scan

:method scan(target,port,tcp_timeout)
:method gen_threads(num_threads)
:method process_queue(q,i) 
#i is an int within range to track the number of threads
    """
    # TO IMPLEMENT Queue/Threads:
    # ====================================
    # scanner.gen_threads(num_threads)
    # qitem = "{}:{}".format(destination,port)
    # scanner.q.put(qitem)
    # scanner.q.join()

    # TO EXTEND TO NEW SCANNER SCAN TYPE
    #=====================================
    # overwrite scanner.gen_threads() to point to a new scan() 
    # (only necessary because may have different # of args)
    # overwrite the scan() function with new scanning code

                  ################
                  #  ATTRIBUTES  #
######################################################

    def __init__(self,num_threads,tcp_timeout,addresses,ports):
        self.addresses = []
        self.ports = []
        self.hosts_and_ports = {}
        self.tcp_timeout = 0.05
        self.q = Queue(maxsize=0)
        self.num_threads = 1
        self.debug = False
        self.banners = []



                  ################
                  # METHODS HERE #
######################################################

    def scan(self,target,port,tcp_timeout):
        if self.debug==True:
            ("scanning...{} PORT: {} ".format(target,port))
    
        try:
            #create the connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(tcp_timeout))
        except: 
            pass
        try:
            #get the resulting connection
            result = sock.connect_ex((target,int(port)))
        except:
            pass
           
        try:
            #check if port was open, then print and append to ports list
            if result == 0:
                result = True

                # add the found host and/or port to the hosts_and_ports dict
                self.update_results(target,port)

                #perform a banner grab if the port is open
                try:
                        banner = sock.recv(1024)
                        if banner:
                            self.banners.append(str(target)+":"+str(port)+" -- "+ str(banner).strip("\\b,\\n,\',\\r'"))
                except:
                    pass
                #now close it up
                try:
                    sock.close()
                except:
                    pass
                if self.debug:
                    print("DEBUG: " + "Port {}:     [green]OPEN".format(port))

            else:
                result = False
                if self.debug:
                    print("DEBUG: " + "Port {}:     [red]CLOSED".format(port))
                

        #CATCH ERRORS HERE
        except KeyboardInterrupt:
            print("you pressed CTRL-C")
            
        except socket.gaierror:
            print("ERROR: Hostname could not be resolved.")
            
        except socket.error:
            print("ERROR: Could not connect to server.")
            pass

        return result
  


    def update_results(self,target,port):
        #if the host isn't there, add it
        if target not in self.hosts_and_ports.keys():
            self.hosts_and_ports[target] = [port]
        else:
            #if the host is there, append the port
            self.hosts_and_ports[target].append(port)

        if self.debug==True:
            print("updating{}:{}".format(target,port))


    def gen_threads(self,num_threads):
        for i in range(int(num_threads)):
            worker = Thread(target=self.process_queue,args=(self.q,i),daemon=True)
            worker.start()
        return
    

    def process_queue(self,q,i):
        while q.qsize:
            if self.debug == True:
                print("[red bold] Getting item from thread" + str(i))

            item = q.get()
            split = item.split(":")
            addr = split[0]
            port = split[1]

            self.scan(addr,port,self.tcp_timeout)
            q.task_done()
        return
    

#############################################################################
#############################################################################

class UDP_Scanner(Scanner):
    """Basic UDP scan of IP/port range || Inherits from Scanner class.
    """
    def __init__(self,num_threads,tcp_timeout,addresses,ports):
        pass

    def udpscan(self, target, port):

        # UDP SCAN FUNCTION HERE
        self.update_results(target,port)