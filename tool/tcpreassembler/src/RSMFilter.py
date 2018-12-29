# -*- coding:gb2312 -*-
from sys import *
from string import *
import os
import struct

def isPrint(ch):
    if ch >= 0x20 and ch <= 0x7E:
        return True
    return False

if __name__ == '__main__':
    if len(argv) != 3:
        print "Usage: RSMExtractor.py <input file> <output file>"
    else:
        inputFile = open(argv[1], "rb")
        outputFile = open(argv[2], "wb")
        
        inputFile.seek(0, os.SEEK_SET)
        fileStart = inputFile.tell()
        inputFile.seek(0, os.SEEK_END)
        fileLength = inputFile.tell() - fileStart
        inputFile.seek(0, os.SEEK_SET)
        
        while inputFile.tell() - fileStart < fileLength:
            direction = struct.unpack("c", inputFile.read(1))[0]
            length = struct.unpack("I", inputFile.read(4))[0]
            # inputFile.seek(length, os.SEEK_CUR)
            # print length
            content = inputFile.read(length)
            
            if len(content) < 8:
                continue
            
            isTextProtocol = True
            i = 0
            while i < 8:
                if isPrint(ord(content[i])) == False:
                    isTextProtocol = False
                    break
                i += 1
            
            if isTextProtocol == False:
                # print "length = %u" % length
                outputFile.write(struct.pack("c",direction))
                outputFile.write(struct.pack("I", length))
                outputFile.write(content)
        
        inputFile.close()
        outputFile.close()
        