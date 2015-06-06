#!/usr/bin/env python
#
#Get PE functions with static analysis
#Author: St0rn
#Website: st0rn.anbu-pentest.com
#
#Usage:
#PEFunc.py [PE]

#
#Use pefile and pydasm
#
#Screen:
#http://prntscr.com/7dx9a6
#
#

##################################### Lib ###########################################

from sys import *
from pefile import *
import pydasm

##################################### Dico ##########################################

iatFunc=dict()
peFunc=dict()

##################################### Function ######################################

#Instanciate PE
def InitPE(exe):
 return PE(exe)

#Dump PE Import
def DumpIAT(pe, iatFuncList):
 for iat in pe.DIRECTORY_ENTRY_IMPORT:
  for api in iat.imports:
   iatFuncList[api.name]=api.address

#Get All functions used by PE
def GetFunc(pe,iatFuncList,peFuncList):
 temp=list()
 offset=int() 
 ep=pe.OPTIONAL_HEADER.AddressOfEntryPoint
 oep=pe.OPTIONAL_HEADER.ImageBase+ep
 dump=pe.get_memory_mapped_image()[ep:]
 while offset<len(dump):
  opcode=pydasm.get_instruction(dump[offset:], pydasm.MODE_32) 
  mnemo= pydasm.get_instruction_string(opcode, pydasm.FORMAT_INTEL, oep+offset) 
  if type(mnemo)!="NoneType":
   try:
    for name,addr in iatFuncList.items():
     if hex(addr) in mnemo and hex(addr) not in temp:
       temp.append(hex(addr))
       peFuncList[name]=addr
       print "\t",hex(addr),name
   except:
    break
   offset+= opcode.length


################################### Main ##############################################

pe=InitPE(argv[1])

print "[+] Dumping IAT"
DumpIAT(pe,iatFunc)

print "[+] Get PE functions"
GetFunc(pe,iatFunc,peFunc)

print "\n[*] Number of functions: %s" %(len(peFunc))
