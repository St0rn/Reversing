#!/usr/bin/env python
#
#Buffer Overflow Crash Report (BofCR)
#Author: St0rn
#Website: st0rn.anbu-pentest.com
#
#Usage:
#BofCR [Options] arggs
#Option: run;  args: pe_name junk_len
#Option: attach; arg:  pe_name
#Example: BofC run vuln.exe 1000 or BofCR attach vuln.exe
#
#Use pydbg
#
#Screen:
#Run test:    http://prntscr.com/7clfgx
#Attach test: http://prntscr.com/7clf5k
#
#


#Import
import sys

import os

from pydbg import *

from pydbg.defines import *

import utils


#Variable

junk=str()


#Get PID by PE name func
def GetPidByName(debug, exe):
 for (pid, exeName) in debug.enumerate_processes():
  if exeName == exe:
   return pid

#Crash record func

def segfault(dbg):

  crash_bin = utils.crash_binning.crash_binning()

  crash_bin.record_crash(dbg)

  print crash_bin.crash_synopsis()

  dbg.terminate_process()

  return DBG_EXCEPTION_NOT_HANDLED


#Instance of pydbg
dbg = pydbg()

#Usage raise
if len(sys.argv)<3:
 print "Usage: %s [Options] args" %sys.argv[0]
 print "Option: run;  args: pe_name junk_len"
 print "Option: attach; arg:  pe_name"
 sys.exit() 

#Run option
if len(sys.argv)==4:
 #Create junk
 if sys.argv[1].lower()=="run":

  for i in xrange(int(sys.argv[3])):

   if i%2:

    junk+="\x37\x13"


  #Create command

  cmd=str(sys.argv[1])+" "+junk
  #Clear CLI

  os.system("cls")


  #Print infos and launch debug

  print "\nPE name: %s " %sys.argv[2]

  print "Args Len: %s" %len(junk)

  dbg.load(sys.argv[2],junk)

  dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,segfault)

  print "\nLaunching PE \n\n{"

  dbg.debug_event_loop()

  print "}"
 else:
  print "Error!\n"

#Attach option
if len(sys.argv)==3:
 if sys.argv[1].lower()=="attach":
  os.system("cls")
  #Get pid by PE name, print and debug
  pid=GetPidByName(dbg,sys.argv[2])

  print "\nPE name: %s " %sys.argv[2]
  print "\nPE PID: %s " %pid

  dbg.attach(int(pid))

  dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,segfault)

  print "\nAttaching to PE \n\n{"

  dbg.debug_event_loop()

  print "}"

 else:
  print "Error!\n"
