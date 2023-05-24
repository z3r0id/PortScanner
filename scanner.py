from queue import Queue
from threading import Thread
import socket
from rich import print
from rich.progress import track

class Scanner:
    
    # DEFINE ATTRIBUTES
    def __init__(self,num_threads,tcp_timeout,q,addresses,ports):
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

                # add findings to hosts_and_ports
                if target not in self.hosts_and_ports.keys():
                    self.hosts_and_ports[target] = [port]
                    try:
                        banner = sock.recv(1024)
                        if banner:
                            self.banners.append(str(target)+":"+str(port)+" -- "+ str(banner).strip("\\b,\\n,\',\\r'"))
                    except:
                        pass
                else:
                    self.hosts_and_ports[target].append(port)
                
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

    def update_results(self,target,ports):
        self.hosts_and_ports[target] = ports
        if self.debug==True:
            print("updating{}:{}".format(target,ports))


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
    
    # to implement Queue/Threads:
    # scanner.gen_threads(num_threads,q)
    # scanner.q.put(function())
    # scanner.q.join()