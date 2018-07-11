#!/bin/env python
'''
General

General library of common handy functions
'''

import os
import os.path
import sys
import string
import socket
import struct

import time
import datetime

def mkdir(dir):
	mkdircmd="mkdir -p %s" % dir
	os.system(mkdircmd)

def rmdir(dir):
	rmcmd="rm -fr %s" % dir
	os.system(rmcmd)

def strip2dec(sip):
	ipgroup=[ "%d" % int(item) for item in sip.strip().split(".") ]
	stdip=".".join(ipgroup)
	decip=struct.unpack("!I",socket.inet_aton(stdip))[0]
	return decip

def testfile(fname):
	if (not os.path.exists(fname)):
		sys.stderr.write("%s does not exists!\n" % fname)
		sys.exit(1)

def filelen(fname):
	try:
		fp=open(fname,"r")
	except IOError:
		lines=[]
	else:	
		lines=fp.readlines()

		fp.close()

	return len(lines)

def openfile(fname,mode="r"):
	try:
		fp=open(fname,mode)
	except IOError:
		sys.stderr.write("Cannot open file %s\n" % fname)
		sys.exit(1)

	return fp

def closefile(fp):
	fp.flush()
	os.fsync(fp.fileno())
	fp.close()

def readfile(fname,header=False):
	try:
		fp=open(fname,"r")
	except IOError:
		sys.stderr.write("Cannot open file %s\n" % fname)
		sys.exit(1)

	if (header): fp.readline()	
	lines=fp.readlines()

	fp.close()

	return lines

def runcmd(cmd,errexit=False):
	try:
		fp=os.popen(cmd)
	except IOError:
		sys.stderr.write("Cannot run %s\n" % cmd)
		fp=None
		if (errexit):
			sys.exit(1)

	lines=[]
	if (fp):
		lines=fp.readlines()
		fp.close()

	return lines



#return UTC from time tuple
def convert_timetuple(t6):
	gtime=datetime.datetime(t6[0],t6[1],t6[2],t6[3],t6[4],t6[5],0,None).utctimetuple()
	utime=time.mktime(gtime) - time.timezone
	#utime=time.mktime(gtime)
	return int(utime)


#format "XXXX-XX-XX XX:XX:XX"
def convert_strtime(str6):
	group=str6.strip().split(" ")
	sdate=group[0]
	stime=group[1]
	group=sdate.strip().split("-")
	year=int(group[0])
	month=int(group[1])
	day=int(group[2])
	group=stime.strip().split(":")
	hour=int(group[0])
	minute=int(group[1])
	second=int(group[2])
	
	t6=[year,month,day,hour,minute,second]
	
	return convert_timetuple(t6)

def UTC2tuple(utc):
	tuple=time.gmtime(utc)
	t6=tuple[0:6]

	return t6

def regex_esc(s):
	escaped = []
	for c in s:
		if c.isalnum():
			escaped.append(c)
		elif c == ' ':
			escaped.append("\\ ")
		elif c == "\t":
			escaped.append("\\t")
		elif c == "\n":
			escaped.append("\\n")
		elif c == "\r":
			escaped.append("\\r")
		elif string.punctuation.find(c) >= 0:
			escaped.append("\\%s" % c)
		else:
			escaped.append("\\x%02x" % ord(c))
	
	return ''.join(escaped)



#debug
if __name__ == "__main__":
	if (len(sys.argv)<2):
		sys.stderr.write("%s utctime\n" % sys.argv[0])
		sys.exit(1)
	
	utc=int(sys.argv[1])
	gtime=datetime.datetime.utcfromtimestamp(utc).utctimetuple()
	utime=time.mktime(gtime)-time.timezone
	print "utc=%d, utime=%d,timezone=%d" % (utc,utime,time.timezone)

	print gtime

	utest=convert_strtime("2006-08-06 19:09:38")
	print "utest=%d" % utest
