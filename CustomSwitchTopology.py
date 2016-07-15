
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Controller, Switch,UserSwitch, RemoteController
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.cli import CLI
import os
import sys
import socket
import thread
import time
import pycap.capture
from construct.protocols.ipstack import ip_stack
import pcap
import sys
import string
import time
import socket
import struct
import pycap.capture
import getopt, dpkt
import socket,struct
import ipaddress
import pycap.constants, pycap.protocol, pycap.inject
import RoutingModule
import sys
import time
from scapy.all import sniff, sendp, ARP, Ether
from cStringIO import StringIO
from Queue import Queue
from RoutingModule import RoutingModule
from RoutingModule import RoutingDecisionVariables
import logging
class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self
    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        sys.stdout = self._stdout
class UserSwitchTemp( Switch ):
    "User-space switch."

    dpidLen = 12

    def __init__( self, name, dpopts='--no-slicing', **kwargs ):
        """Init.
           name: name for the switch
           dpopts: additional arguments to ofdatapath (--no-slicing)"""
        Switch.__init__( self, name, **kwargs )
     
        if self.listenPort:
            self.opts += ' --listen=ptcp:%i ' % self.listenPort
        else:
            self.opts += ' --listen=punix:/tmp/%s.listen' % self.name
        self.dpopts = dpopts

  

    @staticmethod
    def TCReapply( intf ):
        """Unfortunately user switch and Mininet are fighting
           over tc queuing disciplines. To resolve the conflict,
           we re-create the user switch's configuration, but as a
           leaf of the TCIntf-created configuration."""
        if isinstance( intf, TCIntf ):
            ifspeed = 10000000000  # 10 Gbps
            minspeed = ifspeed * 0.001

            res = intf.config( **intf.params )

            if res is None:  # link may not have TC parameters
                return

            # Re-add qdisc, root, and default classes user switch created, but
            # with new parent, as setup by Mininet's TCIntf
            parent = res['parent']
            intf.tc( "%s qdisc add dev %s " + parent +
                     " handle 1: htb default 0xfffe" )
            intf.tc( "%s class add dev %s classid 1:0xffff parent 1: htb rate "
                     + str(ifspeed) )
            intf.tc( "%s class add dev %s classid 1:0xfffe parent 1:0xffff " +
                     "htb rate " + str(minspeed) + " ceil " + str(ifspeed) )

    def start( self, controllers ):
        """Start OpenFlow reference user datapath.
           Log to /tmp/sN-{ofd,ofp}.log.
           controllers: list of controller objects"""
        # Add controllers
        clist = ','.join( [ 'tcp:%s:%d' % ( c.IP(), c.port )
                            for c in controllers ] )
        ofdlog = '/tmp/' + self.name + '-ofd.log'
        ofplog = '/tmp/' + self.name + '-ofp.log'
        intfs = [ str( i ) for i in self.intfList() if not i.IP() ]
        self.cmd( 'ofdatapath -i ' + ','.join( intfs ) +
                  ' punix:/tmp/' + self.name + ' -d %s ' % self.dpid +
                  self.dpopts +
                  ' 1> ' + ofdlog + ' 2> ' + ofdlog + ' &' )
        self.cmd( 'ofprotocol unix:/tmp/' + self.name +
                  ' ' + clist +
                  ' --fail=closed ' + self.opts +
                  ' 1> ' + ofplog + ' 2>' + ofplog + ' &' )
        if "no-slicing" not in self.dpopts:
            # Only TCReapply if slicing is enable
            sleep(1)  # Allow ofdatapath to start before re-arranging qdisc's
            for intf in self.intfList():
                if not intf.IP():
                    self.TCReapply( intf )

    def stop( self, deleteIntfs=True ):
        """Stop OpenFlow reference user datapath.
           deleteIntfs: delete interfaces? (True)"""
        self.cmd( 'kill %ofdatapath' )
        self.cmd( 'kill %ofprotocol' )
        super( UserSwitch, self ).stop( deleteIntfs )

    def listenOnPort(self,  ip,portNumber):
        print ip, portNumber
        HOST = ip   # Symbolic name, meaning all available interfaces
        PORT = portNumber # Arbitrary non-privileged port
         
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'
         
        #Bind socket to local host and port
        try:
            s.bind((HOST, PORT))
        except socket.error as msg:
            print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
             
        print 'Socket bind complete'
        self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt","Socket binding complete")
        #Start listening on socket
        s.listen(10)
        print 'Socket now listening'        
        #now keep talking with the client
        while 1:
            #wait to accept a connection - blockngi call
            self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt","waiting for connection")
            conn, addr = s.accept()
            print 'Connected with ' + addr[0] + ':' + str(addr[1]), addr
            self.writeDataToFile(str(HOST) +"-" +str(PORT)+".txt",addr)
            data = conn.recv(1024)
            self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt",data)
             
        s.close()
        print "Closing thread"

    def writeDataToFile(self,fileName,data):
        with open("Logs/"+fileName, "a") as myfile:
            print "Writing data "+ fileName + " " + data
            myfile.write(data+"\n")
def assignMACToHosts(network):
    listOfHostNames =['h1','h2']
    listOfMacs=['10:10:10:10:10:10','22:22:22:22:22:22']
    count  = 0
    for hostName in listOfHostNames:
        hostNode = network.getNodeByName(hostName)
        hostNode.setMAC(listOfMacs[count])
        count  = count + 1

class CustomSwitchTopology( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        firstHost = self.addHost( 'h1' )
        secondHost = self.addHost( 'h2' )
        thirdHost = self.addHost( 'h3' )
        fourthHost = self.addHost( 'h4' ) 
        fifthHost = self.addHost( 'h5' )

        firstSwitch = self.addSwitch( 's1' )
        secondSwitch = self.addSwitch( 's2' )
        thirdSwitch = self.addSwitch( 's3' )
        fourthSwitch =self.addSwitch( 's4' )
        fifthSwitch = self.addSwitch( 's5' )
        sixthSwitch = self.addSwitch( 's6' )
        seventhSwitch = self.addSwitch( 's7' )

        # Add links

        self.addLink( firstSwitch, secondSwitch )
        self.addLink( firstSwitch, thirdSwitch )
        self.addLink( secondSwitch,fourthSwitch )
        self.addLink( secondSwitch, fifthSwitch )
        self.addLink( thirdSwitch, sixthSwitch )
        self.addLink( thirdSwitch, seventhSwitch )
        
        self.addLink( firstHost, firstSwitch )
        self.addLink( secondHost, fourthSwitch )
        self.addLink( thirdHost, fifthSwitch )
        self.addLink( fourthHost, sixthSwitch ) 
        self.addLink( fifthHost, seventhSwitch )

class CustomSwitch( Switch ):
    dpidLen = 12

    def __init__( self, name, dataPathOptions='--no-slicing', **kwargs ):
        Switch.__init__( self, name, **kwargs )
        self.packetQueue  = Queue()
        self.CustomSwitchLogger = self.get_logger("CustomSwitch")
    def start( self, controllers ):
        print "\n"
        count = 0
        routingModule = RoutingModule(self)
        for portNumber,interface in self.intfs.items():
            if interface.IP():
                continue
            else:
                count = count +1
            try:
               
               thread.start_new_thread( self.sniffPackets,(interface,portNumber,routingModule,) )
            except Exception,e :
               print "Error: unable to start thread here" 
               print e
        thread.start_new_thread(self.sendPacketFunction,())
    def packetDecision(self,routingDecisionVariables):
        self.CustomSwitchLogger.info("Packet Decision " + str(routingDecisionVariables))
        self.packetQueue.put(routingDecisionVariables)
    def sendPacketFunction(self):
        with Capturing() as output:
            self.CustomSwitchLogger.info("Starting sendingPacketFunction")
        while True:

            packetDecision = self.packetQueue.get()
            self.CustomSwitchLogger.info("Packet getted for sending" + str(packetDecision))
            if packetDecision is None:
                continue
            self.CustomSwitchLogger.info("Getted after None")

            if packetDecision.inputPort == -1: # Broadcast
                for interface in self.ports.keys():
                    if interface.name == str(packetDecision.interface):
                        continue
                    iface = interface.name
                    try:
                        with Capturing() as output:
                            sendp(packetDecision.packet, iface=iface)
                        self.CustomSwitchLogger.info("Packet SentCent "+ iface+"\n\n")
                    except Exception, e:
                        self.CustomSwitchLogger.info("SentCent " +str(iface)+"  "+str(e)) 
                continue
            if self.intfs.get(packetDecision.inputPort) is None:
                continue
            iface =  self.intfs.get(packetDecision.inputPort).name

            try:
                    # pycap.inject.inject(self.intfs.get(outputPort).name).inject(packet)
                with Capturing() as output:
                    sendp(packetDecision.packet, iface=iface)
                    self.CustomSwitchLogger.info("Packet SentCent\n\n")
            except Exception, e:
                # raise e  
                self.CustomSwitchLogger.info(str(iface)+"  "+str(e)) 
    def sniffPackets(self, interface,portNumber,routingModule):
        p = pycap.capture.capture(interface.name)
        while True:
            packet = p.next()
            # print packet
            # self.writeDataToFile(interface.name,packet)
            if packet is None:
                logging.info("Sniffed Packet None")
                continue
            sourceMAC = self.getSourceAddress(packet)
            destinationMAC = self.getDestinationAddress(packet)
            routingDecisionVariables = RoutingDecisionVariables(destinationMAC,sourceMAC,interface.name,portNumber,packet)
            routingModule.queuePacketForDecision(routingDecisionVariables)
            self.CustomSwitchLogger.info("Sniffed Packet sent for decision " + str(routingDecisionVariables))
            # self.writeDataToFile(interface.name,"Packet Recieved--------------")
            # self.writeDataToFile(interface.name,str(packet))
            # self.writeDataToFile(interface.name,"\n\n")
            # self.writeDataToFile(interface.name,"Output Interface "+str(self.intfs.get(outputPort)))
            # self.writeDataToFile(interface.name,"Source IP " + self.getSourceAddress(packet))
            # self.writeDataToFile(interface.name,"Destination IP "+self.getDestinationAddress(packet))
            # iface =  self.intfs.get(outputPort).name

            # try:
            #     # pycap.inject.inject(self.intfs.get(outputPort).name).inject(packet)
            #     with Capturing() as output:
            #         sendp(packet, iface=iface)
            # except Exception, e:
            #     # raise e  
            #     self.writeDataToFile(interface.name,str(e)) 

            
    def listenOnPort(self,  ip,portNumber):
        print ip, portNumber
        HOST = ip   # Symbolic name, meaning all available interfaces
        PORT = portNumber # Arbitrary non-privileged port
         
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'
         
        #Bind socket to local host and port
        try:
            s.bind((HOST, PORT))
        except socket.error as msg:
            print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
             
        print 'Socket bind complete'
        self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt","Socket binding complete")
        #Start listening on socket
        s.listen(10)
        print 'Socket now listening'        
        #now keep talking with the client
        while 1:
            #wait to accept a connection - blockngi call
            self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt","waiting for connection")
            conn, addr = s.accept()
            print 'Connected with ' + addr[0] + ':' + str(addr[1]), addr
            self.writeDataToFile(str(HOST) +"-" +str(PORT)+".txt",addr)
            data = conn.recv(1024)
            self.writeDataToFile(str(HOST) +"-"+ str(PORT)+".txt",data)
             
        s.close()
        print "Closing thread"

    def writeDataToFile(self,fileName,data):
        fileName = str(fileName)
        fileName = fileName +".txt"
        data  = str(data)
        with open("Logs/"+fileName, "a") as myfile:
            # print "Writing data "+ fileName + " " + data
            myfile.write(data+"\n")

    def decode_ip_packet(self,s):
        d={}
        d['version']=(ord(s[0]) & 0xf0) >> 4
        d['header_len']=ord(s[0]) & 0x0f
        d['tos']=ord(s[1])
        d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
        d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
        d['flags']=(ord(s[6]) & 0xe0) >> 5
        d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
        d['ttl']=ord(s[8])
        d['protocol']=ord(s[9])
        d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
        d['source_address']=self.Int2IP(struct.unpack('i',s[12:16])[0])
        d['destination_address']=self.Int2IP(struct.unpack('i',s[16:20])[0])
        # print Int2IP(struct.unpack('i',s[16:20])[0])
        if d['header_len']>5:
            d['options']=s[20:4*(d['header_len']-5)]
        else:
            d['options']=None
        d['data']=s[4*d['header_len']:]
        return d

    def Int2IP(self,ipnum):
        ipnum = abs(ipnum)
        o1 = int(ipnum / 16777216) % 256
        o2 = int(ipnum / 65536) % 256
        o3 = int(ipnum / 256) % 256
        o4 = int(ipnum) % 256
        return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

    def getSourceAddress(self,data):
        if not data:
            return
        return str(data[0])[22:40].replace(")", "")
        if data[12:14]=='\x08\x00':
            decoded=self.decode_ip_packet(data[14:])
            return decoded['source_address']

    def getDestinationAddress(self, data):
        if not data:
            return
        return str(data[0])[43:69].replace(")", "")
        if data[12:14]=='\x08\x00':
            decoded=self.decode_ip_packet(data[14:])
            return decoded['destination_address']
    def get_logger(self,name=None):
        default = "__app__"
        formatter = logging.Formatter('%(levelname)s: %(asctime)s %(funcName)s(%(lineno)d) -- %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
        log_map = {"CustomSwitch": "CustomSwitch.log"}
        if name:
            logger = logging.getLogger(name)
        else:
            logger = logging.getLogger(default)
        fh = logging.FileHandler(log_map[name])
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.setLevel(logging.INFO)
        console = logging.StreamHandler()
        console.setLevel(logging.ERROR)
        logging.getLogger('').addHandler(console)
        return logger
os.system('clear')
os.system('sudo mn -c')
topo = CustomSwitchTopology()
c0 = Controller( 'c0', port=6633 )
net = Mininet( topo=topo, switch=CustomSwitch, build=False )
# net.addController(c0)
net.build()
assignMACToHosts(net)
net.start()
CLI( net )
net.stop()

