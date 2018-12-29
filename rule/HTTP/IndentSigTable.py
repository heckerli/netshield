# -*- coding:gb2312 -*-
from sys import *
from string import *
import os
import re
import sys

def parse_line(line):
    result = []
    line = strip(line)
    line = strip(line, '\n')
    line = strip(line, '\r')
    line = strip(line, '\n')
    i = 0
    column = ""
    while i < len(line):
        if line[i] != '\t':
            column += line[i]
        else:
            result.append(column)
            column = ""
        i += 1
    else:
        if len(column) > 0:
            result.append(column)
    
    return result
    
def int2bin_string(integer):
    result = ""
    i = 0
    while i < 32:
        if integer & (1 << i) != 0:
            result = "1" + result
        else:
            result = "0" + result
        i += 1
    return result

def parse_variable(line):
    print line
    result = re.search(r"name=([^;\n]*);value[~=]([^\n]*)", line)
    name = ""
    value = ""
    if result != None:
        name = result.group(1)
        value = result.group(2)
        return name + ", " + pattern_normalize(value)
    else:
        return None

def pattern_normalize(pattern):
    pattern = re.sub(r"(?<!\\)\\d", r"\\\\d", pattern);
    pattern = re.sub(r"(?<!\\)\\\*", r"\\\\*", pattern);
    pattern = re.sub(r"(?<!\\)\\x", r"\\\\x", pattern);
    pattern = re.sub(r"(?<!\\)\\n", r"\\\\n", pattern);
    pattern = re.sub(r"(?<!\\)\\r", r"\\\\r", pattern);
    pattern = re.sub(r"(?<!\\)\\\?", r"\\\\?", pattern);
    pattern = re.sub(r"(?<!\\)\\s", r"\\\\s", pattern);
    pattern = re.sub(r"(?<!\\)\\\.", r"\\\.", pattern);
    pattern = re.sub(r"(?<!\\)\\\+", r"\\\\+", pattern);
    pattern = re.sub(r"(?<!\\)\\#", r"\\\\#", pattern);
    pattern = re.sub(r"(?<!\\)\\&", r"\\\\&", pattern);
    pattern = re.sub(r"\\\\\\/", r"\\\\/", pattern);
    pattern = re.sub(r"(?<!\\)\\/", r"/", pattern);
    pattern = re.sub(r"(?<!\\)\\w", r"\\\\w", pattern);
    pattern = re.sub(r"(?<!\\)\\]", r"\\\\]", pattern);
    pattern = re.sub(r"(?<!\\)\\;", r"\\\\;", pattern);
    pattern = re.sub(r"(?<!\\)\\<", r"\\\\<", pattern);
    pattern = re.sub(r"(?<!\\)\\-", r"\\\\-", pattern);
    pattern = re.sub(r"(?<!\\)\\~", r"\\\\~", pattern);
    pattern = re.sub(r"(?<!\\)\\=", r"\\\\=", pattern);
    pattern = re.sub(r"(?<!\\)\\h", r"\\\\h", pattern);
    pattern = re.sub(r"(?<!\\)\\\$", r"\\\\$", pattern);
    return pattern

if __name__ == '__main__':
    rule_list = []
    indent_list = []
    rule_sorted_list = []
    for line in open(argv[1], "r"):
        rule_list.append(parse_line(line))
    
    (file_path, file_name) = os.path.split(argv[1])
    (file_base, file_ext) = os.path.splitext(file_name)
    
    sorted_file = open(file_base + "-sorted.txt", "w")
    
    i = 0
    while i < len(rule_list[0]):
        # rule_list[0][i] = rule_list[0][i] + ":" + str(i)
        i += 1
    
    i = 0
    while i < len(rule_list[0]):
        max_indent = 0
        for rule in rule_list:
            if len(rule[i]) > max_indent:
                max_indent = len(rule[i])
        
        indent_list.append(max_indent)
        i += 1
    
    rule_sorted_list.append(rule_list[0])
    rule_list.remove(rule_list[0])
    max_column = len(rule_sorted_list[0])
    current_column = 0
    while current_column < max_column:
        current_rule = 0
        current_rule_list = []
        while current_rule < len(rule_list):
            if rule_list[current_rule][current_column] != "N":
                current_rule_list.append(rule_list[current_rule])
                rule_list.remove(rule_list[current_rule])
                current_rule = 0
            else:
                current_rule += 1     
        # current_rule_list.sort()
        n = 0
        while n < len(current_rule_list):
            rule_sorted_list.append(current_rule_list[n])
            n += 1
        current_column += 1
    
    # print "indent_list.len = %d" % len(indent_list)
    j = 0
    while j < len(rule_sorted_list):
        if j == 0:
            sorted_file.write("Rule  ")
        else:
            sorted_file.write("%3d   " % (j - 1))
        k = 0
        while k < len(rule_sorted_list[j]):
            sorted_file.write(rule_sorted_list[j][k])
            if k < len(rule_sorted_list[j]) - 1:
                m = 0
                while m + len(rule_sorted_list[j][k]) < indent_list[k] + 2:
                    sorted_file.write(' ')
                    m += 1
            k += 1
        sorted_file.write('\n')
        j += 1

    sorted_file.close()
    
    k = 0
    while k < len(rule_sorted_list[0]):
        column_file = open(file_base + "-" + str(k) + "-" + rule_sorted_list[0][k] +".txt", "w")
        column_file.write("Rule  " + rule_sorted_list[0][k] + "\n");
        j = 1
        while j < len(rule_sorted_list):
            if rule_sorted_list[j][k] != "N":
                column_file.write("%3d   " % (j - 1))
                column_file.write(rule_sorted_list[j][k])
                column_file.write('\n')
            j += 1
        k += 1
    