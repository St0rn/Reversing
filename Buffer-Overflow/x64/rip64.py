#!/usr/bin/env python
#
# Author: St0rn
# Site: st0rn.anbu-pentest.com
#
# Platform: Linux x64
# Description:
# Generate cyclic pattern, find RIP control offset and generate exploit skeleton (vanilla RIP and Ret2Libc)
#

from sys import argv

infos="""Exploit skeleton generation:
1: Basic exploit
2: Ret into libc exploit 
Enter your choice: """

def generatebasic(junklen):
 sploit="""#!/usr/bin/env python
from struct import pack

junk=""
junk+="\\x90"*%s
rip=pack("<Q", 0x424242424242)
payload=junk+rip
print payload""" %junklen

 f=open("basicskeleton.py","w")
 f.write(sploit)
 f.close

def generateret2libc(junklen):
 sploit="""#!/usr/bin/env python
from struct import pack

junk=""
junk+="a"*%s
# pop rdi ; ret
prdi=pack("<Q", 0x424242424242)

# Pointer to /bin/sh
pbinsh=pack("<Q", 0x434343434343)

# System() libc address
addrsystem=pack("<Q", 0x444444444444)

payload=junk+prdi+pbinsh+addrsystem
print payload""" %junklen

 f=open("ret2libcskeleton.py","w")
 f.write(sploit)
 f.close

def generatejunk(length): 
 taba = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
 tabb = "abcdefghijklmnopqrstuvwxyz"
 tabc = "0123456789"
 
 junk = ""
 a = 0 
 b = 0
 c = 0
 
 while len(junk) < length:
  junk += taba[a] + tabb[b] + tabc[c]
  c += 1
  if c == len(tabc): 
   c = 0
   b += 1
  if b == len(tabb):
   b = 0
   a += 1
  if c == len(tabc):
   a = 0
 return junk

def getOffset(addr,payload):
 addr=addr[6]+addr[7]+addr[4]+addr[5]+addr[2]+addr[3]+addr[0]+addr[1]
 addr=addr.decode("hex")
 try:
  return payload.index(addr)
 except: 
  return False

pattern=list()
pattern=generatejunk(int(argv[1]))
print "Cyclic pattern generated:\n%s\n" %pattern
print "Info: use x/wx $rsp gdb command to get value"
rep=raw_input("Insert value here: ")
if getOffset(rep,pattern)!=False:
 print "\nRIP is at offset %s\n" %getOffset(rep,pattern)
 ans=raw_input(infos)
 if int(ans)==1:
  print "Generating Basic skeleton exploit"
  generatebasic(getOffset(rep,pattern))
 if int(ans)==2:
  print "Generating Ret2Libc skeleton exploit"
  generateret2libc(getOffset(rep,pattern))
