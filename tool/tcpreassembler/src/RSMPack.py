# -*- coding:gb2312 -*-
from sys import *
from string import *
import os
import struct

if __name__ == '__main__':
    if len(argv) != 4:
        print "Usage: RSMPack.py <input file> <direction: 0 or 1> <output file>"
    else:
        inputFile = open(argv[1], "rb")
        direction = int(argv[2])
        outputFile = open(argv[3], "wb")
        
        content = inputFile.read()
        length = len(content)
        
        if direction == 0:
            outputFile.write('\x00')
        elif direction == 1:
            outputFile.write('\x01')
        else:
            pass
        outputFile.write(struct.pack("I", length))
        outputFile.write(content)
        
        inputFile.close()
        outputFile.close()
        