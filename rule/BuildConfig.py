#!/bin/env python
'''
NetShield

Goal: Build a config.xml to describe the rules to NetShield, so that we can easily extend the rules or parsers

Input: the matcher-signature table

Output: a config.xml according to Gao Xia's format

'''
import string
import sys
import re
import os
import os.path
import copy

import Utility
debug=sys.stderr.write

sep="\t"
EMPTY='N'

indent=0

namemap={
	"method": ("Method",None),
	"filename": ("Filename",None),
	"anydirs": ("Dir","Any"),
	"dirs": ("Dir","NEGATIVE"),
	"Variable": ("Variable",None),
	"assignment": ("Assignment",None),
	"uri": ("Uri",None),
	"Headers":("Header",None)
}

typemap={
	"Method": "simple",
	"Filename": "simple",
	"Dir": "list",
	"Variable":"dict",
	"Assignment":"simple",
	"Uri":"simple",
	"Header":"dict"
}

FieldList=["Method","Filename","Dir","Variable","Assignment","Uri","Header"]
OpList=["AM","RE","LE"]
OpNamemap={
	"AM": "String",
	"RE": "Regex",
	"LE": "Length"
}

XMLSP={
	'>': '&lt;',
	'&': '&amp;',
	'>': '&gt;',
	'"': '&quot;',
	"'": '&apos;'
}

STRESCAPE='.*+?[]{}^'

def nametuple(name):
	group=name.split("_")
	if (len(group)==2):
		field=group[0]
		op=group[1]
		condid=1
	elif (len(group)==3):
		field=group[0]
		op=group[1]
		try:
			condid=int(group[2])
		except ValueError:
			condid=1
			debug("Warning:: parse matcher name error: condid=int(group[2])\n")
	return (field,op,condid)


def get_colmap(table,index,rindex):
	colmap={}
	for (name,col) in index.items():
		(field,op,condid)=nametuple(name)
		(tag,index)=namemap[field]
		if (index=="NEGATIVE"):
#			debug("DEBUG:: condid=%s\n" % condid)
			index="%d" % ((condid+1)*(-1))
#			debug("DEBUG:: index=%s\n" % index)

		type=typemap[tag]

		#properties available:
		#name,col,field,op,condid,tag,index,type
		if (tag not in colmap): colmap[tag]={}
		if (type=="simple"):
			if (op not in colmap[tag]): colmap[tag][op]=[]
			colmap[tag][op].append(col)
		elif(type=="list"):
			if (index is None): 
				debug("%s col=%d index is None\n" % (name,col))
				sys.exit(1)
			if (index not in colmap[tag]): colmap[tag][index]={}
			if (op not in colmap[tag][index]): colmap[tag][index][op]=[]
			colmap[tag][index][op].append(col)
			
		elif(type=="dict"):
			if (op not in colmap[tag]): colmap[tag][op]=[]
			colmap[tag][op].append(col)
		

	return colmap	
		
		
def get_fields(fp,table,index,rindex,indent=4):
	colmap=get_colmap(table,index,rindex)
	for tag in FieldList:
		if (tag in colmap):
			type=typemap[tag]
			if (type=="simple"): printSimple(tag,colmap[tag],fp,table,index,rindex,indent+1)
			if (type=="list"): printList(tag,colmap[tag],fp,table,index,rindex,indent+1)
			if (type=="dict"): printDict(tag,colmap[tag],fp,table,index,rindex,indent+1)

	
def printSimple(tag,colmaptag,fp,table,index,rindex,indent=5):
	indentprint(fp,indent,"<%s>" % tag)
	for op in OpList:
		if (op in colmaptag):
			collist=colmaptag[op]
			printColList(collist,op,fp,table,index,rindex,indent+1)
	indentprint(fp,indent,"</%s>" % tag)					
	
def printList(tag,colmaptag,fp,table,index,rindex,indent=5):
	myind1=indent+1
	myind2=indent+2
	indentprint(fp,indent,"<%ss>" % tag)
	for (index,colmaptagindex) in colmaptag.items():
		indentprint(fp,myind1,'<%s Index="%s">' % (tag,index))
		for op in OpList:
			if (op in colmaptagindex):
				collist=colmaptagindex[op]
				printColList(collist,op,fp,table,index,rindex,myind2)
		indentprint(fp,myind1,'</%s>' % tag)
	indentprint(fp,indent,"</%ss>" % tag)	
		
def printColList(collist,op,fp,table,index,rindex,indent=6):
	indentprint(fp,indent,"<%s>" % OpNamemap[op])

	nrules=len(table)
	outmap={}

	for col in collist:
		for i in xrange(nrules):
			if (table[i][col]!='N'):
				v=table[i][col]
				if (op=='AM'):
					out=outStr(v)
				elif(op=="RE"):
					out=outRe(v)
				elif(op=="LE"):
					out=v

				if (out not in outmap): outmap[out]=[]
				outmap[out].append((col,i))
			

	myind=indent+1
	myind2=indent+2
	for (out,v) in outmap.items():
		indentprint(fp,myind,'<Expression Exp="%s">' % out)
		for (col,ruleid) in v:
			indentprint(fp,myind2,'<Rule ColumnID="%d" RuleID="%d"></Rule>' % (col,ruleid))
		indentprint(fp,myind,'</Expression>')

	indentprint(fp,indent,"</%s>" % OpNamemap[op])

def printDict(tag,colmaptag,fp,table,index,rindex,indent=5):
	indentprint(fp,indent,"<%sDict>" % tag)

	maps={}
	remaps={}
	explists={}
	
	maplist=[]
	for op in OpList:
		if (op in colmaptag):
			collist=colmaptag[op]
			maps[op]=get_dictmap(op,collist,table)
			maplist.append(maps[op])
			(remaps[op],explists[op])=get_uniqgroup(maps[op])

	allkeys=get_allkeys(maplist)
	allkeys.sort()
	printAllkeys(tag,allkeys,maps,remaps,fp,indent+1)	

	for op in OpList:
		if (op in maps and len(maps[op])>0):
			printExplist(op,explists[op],fp,indent+1)
	
	indentprint(fp,indent,"</%sDict>" % tag)

def printExplist(op,explist,fp,indent=6):
	myind1=indent+1
	myind2=indent+2

	indentprint(fp,indent,'<%sGroups>' % OpNamemap[op])

	for expgroup in explist:
		indentprint(fp,myind1,'<%sGroup>' % OpNamemap[op])
		for exp in expgroup:
			if (op=='AM'):
				out=outStr(exp)
			elif(op=="RE"):
				out=outRe(exp)
			elif(op=="LE"):
				out=exp
			indentprint(fp,myind2,'<Expression Exp="%s"></Expression>' % out)
		indentprint(fp,myind1,'</%sGroup>' % OpNamemap[op])

	indentprint(fp,indent,'</%sGroups>' % OpNamemap[op])
	

def printAllkeys(tag,allkeys,maps,remaps,fp,indent=6):
	myind1=indent+1
	myind2=indent+2
	myind3=indent+3

	indentprint(fp,indent,'<%ss>' % tag)
	for name in allkeys:
		params=[]
		params.append('Name="%s"' % outStr(name))
		for op in OpList:
			if (op in maps and name in maps[op]):
				groupid=remaps[op][name]
				groupstr='%sGroup="%d"' % (OpNamemap[op],groupid)
				params.append(groupstr)
		indentprint(fp,myind1,'<%s %s>' % (tag,' '.join(params)))
		for op in OpList:
			if (op in maps and name in maps[op]):
				indentprint(fp,myind2,'<%s>' % OpNamemap[op])
				printDictrules(name,maps[op],fp,myind3)
				indentprint(fp,myind2,'</%s>' % OpNamemap[op])
		indentprint(fp,myind1,'</%s>' % tag)
		
	indentprint(fp,indent,'</%ss>' % tag)

def printDictrules(name,map,fp,indent=9):
	myind1=indent+1
	##### map[name][value]=a list of (col, sig)
	valuelist=copy.copy(map[name].keys())
	valuelist.sort() 
	for i in xrange(len(valuelist)):
#		debug('DEBUG:: map[%s][%s]=%s\n' % (name,valuelist[i],map[name][valuelist[i]]))
		indentprint(fp,indent,'<RuleGroup>')
		for (col,sig) in map[name][valuelist[i]]:	
			indentprint(fp,myind1,'<Rule ColumnID="%d" RuleID="%d"></Rule>' % (col,sig))
		indentprint(fp,indent,'</RuleGroup>')


def get_allkeys(dictlist):
	
	all=[]
	for dict in dictlist:
		all.extend(dict.keys())

	keyset=set(all)
	
	keylist=[]
	for key in keyset:
		keylist.append(key)

	return keylist
		

def get_dictmap(op,collist,table):
	map={}
	nrules=len(table)

	for i in xrange(nrules):
		for col in collist:
			cell=table[i][col]
			if (cell != 'N'):
				if (op=='AM' or op=='RE'):
					group=reparse(cell,'name="(.*)";value="(.*)"')
				elif (op=='LE'):
					group=reparse(cell,'name="(.*)";len.value.>(.*)$')
				
				if (group):
					name=group[0]
					value=group[1]
				else:
					debug("Debug:: cell cannot parse. cell=%s\n" % cell)
#debug code
#				if (i==780): 
#					print "%s : %s" % (name,value)
#					debugname=name
#					debugvalue=value
#				value=reparse(cell,';value="(.*)"')[0]
				if (name not in map):
					map[name]={}
				if (value not in map[name]):
					map[name][value]=[]
				map[name][value].append((col,i))

	return map


def escape(str):
	strlist=[]
	for i in xrange(len(str)):
		c=str[i]
		if (c=='/'):
			blackcnt=0
			for j in xrange(i-1,-1,-1):
				if (str[j]=='\\'):
					blackcnt+=1
				else:
					break;
			if (blackcnt % 2 == 0):
				strlist.append('\\')	
			strlist.append(c)
#		elif( c in XMLSP):
#			strlist.append(XMLSP[c])
		else: 
			strlist.append(c)

	return ''.join(strlist)

def XMLescape(str):
	strlist=[]

	for i in xrange(len(str)):
		c=str[i]
		if (c in XMLSP):
			strlist.append(XMLSP[c])
		else:
			strlist.append(c)
	return ''.join(strlist)

def strescape(str):
	strlist=[]
	for i in xrange(len(str)):
		c=str[i]
		if (c in STRESCAPE):
			blackcnt=0
			for j in xrange(i-1,-1,-1):
				if (str[j]=='\\'):
					blackcnt+=1
				else:
					break;
			if (blackcnt % 2 == 0):
				strlist.append('\\')	
			strlist.append(c)
		else:
			strlist.append(c)

	return ''.join(strlist)

def normalize(regex):
	if (len(regex)==0): return regex

#	if (regex[0]=='^'):
#		regex=regex[1:]
#	elif (not (len(regex)>=2 and regex[0:2]=='.*')):
#		regex='.*'+regex

#	if (regex[len(regex)-1]=='$'):
#		regex=regex[:(len(regex)-1)]
#	elif (not (len(regex)>=2 and regex[(len(regex)-2):len(regex)]=='.*')):
#		regex=regex+'.*'

	return regex

def outStr(str,sensitive=True):
	if (sensitive):
#		return str
		## change to this form according to Gao's request
#		newstr=escape(str)
		newstr=XMLescape(str)
#		newstr2=strescape(newstr)
		return newstr 
	else:
		newstr=escape(str)
#		newstr2=strescape(newstr)
		newstr3=XMLescape(newstr)
		return '/'+newstr3+'/i'
 
		

def outRe(regex,sensitive=True):
	# exregex=escape(regex)
	# nregex=normalize(exregex)
	xmlregex=XMLescape(regex)
	outregex=xmlregex

	# outregex='/'+xmlregex+'/'
	#if (not sensitive): outregex = outregex + 'i'

	# print outregex

	return outregex
# a general function which take a buf and RE ptn, parse out the (.) 
# in the re from the buf
def reparse (buf, ptn):
	prog=re.compile(ptn,re.DOTALL)
	result=prog.search(buf)

	if (result):
		return result.groups()
	else:
		return None


# load the signature-matcher table
# table is the 2D table
# index is the mapping from matcher's string name to the column index
# rindex is the  mappping from the column index to the matcher's string name
def load_table(fname):
	table=[]
	index={}
	rindex={}
	fp=Utility.openfile(fname)	
	
	headline=fp.readline()
	group=headline.strip().split(sep)
	for i in xrange(len(group)):
		h=group[i].strip()
		index[h]=i
		rindex[i]=h

	for l in fp:
		group=l.rstrip('\r\n').split(sep)
#		list=[ ele.strip() for ele in group]
		table.append(group)

	return (table,index,rindex)

# find all the element in the list which contain the substring `substr'
def findall(list,substr):
	out=[]
	for s in list:
		if (s.find(substr)>=0): out.append(s)
	
	return out
		
# produce the mapping between the condition ID and the actual column the 2D table	
def arraydict(index,substr):
	adict={}

	names=findall(index.keys(),substr)
	
	for n in names:
		group=n.split("_")
		id=int(group[len(group)-1])
		adict[id]=index[n]

	return adict
			

def reprocesscol(table,col,prefix):
	map={}
	refname="%s.re" % prefix
	mapfname="%s.map" % prefix

	for i in xrange(len(table)):
		sig=i+1
		key=table[i][col]
		if (key != 'N'):
			if (key not in map):
				map[key]=[]
			map[key].append(1)
			map[key].append(sig)
	
	relist=copy.copy(map.keys())
	relist.sort()
	
	refp=Utility.openfile(refname,"w")
	for re in relist:
		refp.write("%s\n" % re)

	mapfp=Utility.openfile(mapfname,"w")
	for re in relist:
		mapfp.write("%s\t" % re)
		vline="\t".join(["%d" % i for i in map[re]])
		mapfp.write("%s\n" % vline)

	refp.close()
	mapfp.close()	
		

#compare two (expressGroup, idx)
def remcmp(x,y):
	resx=x[0]
	resy=y[0]
	return recmp(resx,resy)

#compare two expression (re) group
def recmp(resx,resy):
	resxl=len(resx)
	resyl=len(resy)

	if (resxl>resyl): return 1
	if (resxl<resyl): return -1
	
	for i in xrange(resxl):
		c=cmp(resx[i],resy[i])
		if (c!=0): return c
		
	return 0

#def dremcmp(x,y):
#
#	resx=x[0]
#	resy=y[0]
#	resxl=len(resx)
#	resyl=len(resy)
#
#	if (resxl>resyl): return 1
#	if (resxl<resyl): return -1
#	
#	for i in xrange(resxl):
#		c=cmp(resx[i],resy[i])
#		print "%s -- %s --> %d" % (resx[i],resy[i],c)
#		if (c!=0): return c
#		
#	return 0




def get_uniqgroup(map):
	# get the mapping of name -> idx (regex group)			
	namelist=copy.copy(map.keys())
	namelist.sort()

	remlist=[]
	remap={}
	idx=0
	for name in namelist:
		res=copy.copy(map[name].keys())
		res.sort()
		remlist.append([res,idx])
		remap[name]=idx
		
		idx+=1
#debug code
#	print remlist[remap[debugname]]

	origremlist=copy.copy(remlist)

	idxmap={}
	for (res,idx) in remlist:
		idxmap[idx]=idx

	remlist.sort(remcmp)

	#get all the regex groups than find the duplication and more through idxmap (maping the group id)
#debug code	
#	for t in remlist: print t

	for i in xrange(len(remlist)):
		for j in xrange(i+1,len(remlist)):
			if (len(remlist[i][0])!=len(remlist[j][0])): break
			# if the regular expression group is same then try to update index to merge the group
			if (remlist[i][1]<remlist[j][1] and remcmp(remlist[i],remlist[j])==0):
#debug code#			print "%s <--> %s" % (remlist[i][0],remlist[j][0])
#debug code#			dremcmp(remlist[i],remlist[j])
				idxmap[remlist[j][1]]=remlist[i][1]
				remlist[j][1]=remlist[i][1]
				
	idxset=set([])
	for newidx in idxmap.values():
		idxset.add(newidx)
	mergeidxlist=[]
	for newidx in idxset:
		mergeidxlist.append(newidx)
	mergeidxlist.sort()

	reslist=[]
	outidxmap={}
	for i in xrange(len(mergeidxlist)):
		outidxmap[mergeidxlist[i]]=i
		res=origremlist[mergeidxlist[i]][0]
		reslist.append(res)
	
	for (name,oldidx) in remap.items():
		newidx=idxmap[oldidx]
		finalidx=outidxmap[newidx]
		remap[name]=finalidx	
	


	return (remap,reslist)

	
	
#parse the http matcher_signature table and generate the 
#fieldname.re and fieldname.map files
def gen_re(table,index,rindex):
	filecol=index['filename_RE']
	uricol=index['uri_RE']
	assigncol=index['assignment_RE']

	varcoldict=arraydict(index,'Variable_RE')
	headercoldict=arraydict(index,'Headers_RE')
		
	reprocesscol(table,filecol,'filename')
	reprocesscol(table,uricol,'URI')
	reprocesscol(table,assigncol,'assignment')
	reprocesscoldict(table,varcoldict,'variables')
	reprocesscoldict(table,headercoldict,'headers')
			
	
def get_startRuleID(table):
	nrules=len(table)
	ncols=len(table[0])

	
	startlist=[0]
	i=0
	for j in xrange(ncols-1):
		while (i< nrules and table[i][j]!=EMPTY): i+=1
		startlist.append(i)

	return startlist	
			
	
def get_bitmap(table):
	nrules=len(table)
	ncols=len(table[0])

	bitmaplist=[]
	for i in xrange(nrules):
		bitmap=[]
		for j in xrange(ncols):
			if (table[i][j]==EMPTY):
				bit="0"
			else:
				bit="1"
			bitmap.append(bit)
		bitmap.reverse()
		bitmaplist.append("".join(bitmap))

	return bitmaplist

###The following code is for generate the config.xml (printing)

def getindent(indent):
	a=["\t"] * indent
	return ''.join(a)

def indentprint(fp,indent,str):
	fp.write("%s%s\n" % (getindent(indent),str))

def printconfig(fp,table,index,rindex,indent=0):
	header='''<?xml version="1.0" encoding="ASCII" ?>
<NetShield>
	<HTTP>
		<Signature>
'''

	tail='''		</Signature>
	</HTTP>
</NetShield>
'''
	fp.write(header)
	printRules(fp,table,index,rindex)
	printFields(fp,table,index,rindex)
	fp.write(tail)

def printColumns(fp,table,indent=4):
	ncols=len(table[0])

	indentprint(fp,indent,'<Columns Num="%d">' % ncols)
	myind=indent+1
	startlist=get_startRuleID(table)
	for sri in startlist:
		indentprint(fp,myind,'<Column StartRuleID="%d"></Column>' % sri)	
	
	indentprint(fp,indent,'</Columns>')

def printBitmaps(fp,table,indent=4):	
	nrules=len(table)

	indentprint(fp,indent,'<Bitmaps Num="%d">' % nrules)
	myind=indent+1
	bitmaplist=get_bitmap(table)
	for bm in bitmaplist:
		indentprint(fp,myind,'<Bitmap Bmp="%s"></Bitmap>' % bm)
	indentprint(fp,indent,'</Bitmaps>')

def printRules(fp,table,index,rindex,indent=3):

	indentprint(fp,indent,"<Rules>")
	printColumns(fp,table)
	printBitmaps(fp,table)	
	indentprint(fp,indent,"</Rules>")
		
def printFields(fp,table,index,rindex,indent=3):
	indentprint(fp,indent,"<Fields>")
	get_fields(fp,table,index,rindex,indent+1)
	indentprint(fp,indent,"</Fields>")

if __name__ == "__main__":
	
	if (len(sys.argv)<2):
		sys.stderr.write("%s <matcher_table> <config.xml>\n" % sys.argv[0])
		sys.exit(1)
	
	tablefile=sys.argv[1];
	Utility.testfile(tablefile)
	(table,index,rindex)=load_table(tablefile)

	fp=Utility.openfile(sys.argv[2],"w")
	printconfig(fp,table,index,rindex)
#	print table[780]
#	gen_re(table,index,rindex)
	

