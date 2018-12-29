# -*- coding:gb2312 -*-
from sys import *
from string import *
import os
import struct

if __name__ == '__main__':
    if len(argv) != 4:
        print "Usage: RSMExtractor.py <input file> <segment number> <output file>"
    else:
        inputFile = open(argv[1], "rb")
        segNum = int(argv[2])
        outputFile = open(argv[3], "wb")
        
        i = 0
        while i < segNum:
            direction = struct.unpack("c", inputFile.read(1))[0]
            length = struct.unpack("I", inputFile.read(4))[0]
            inputFile.seek(length, os.SEEK_CUR)
            # content = inputFile.read(length)
            # print "length = %u" % length
            # outputFile.write(struct.pack("c",direction))
            # outputFile.write(struct.pack("I", length))
            # outputFile.write(content)
            if length > 0:
                i += 1
        
        exit = 0
        while exit == 0:
            direction = struct.unpack("c", inputFile.read(1))[0]
            length = struct.unpack("I", inputFile.read(4))[0]
            if length > 0:
                content = inputFile.read(length)
                print "length = %u" % length
                outputFile.write(struct.pack("c",direction))
                outputFile.write(struct.pack("I", length))
                outputFile.write(content)
                exit = 1
        
        inputFile.close()
        outputFile.close()
        