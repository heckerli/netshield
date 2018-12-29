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

def parse_column_name(column):
    result = re.search(r"([a-zA-Z]+)_([a-zA-Z]+)_?([0-9]+)?", column)
    if result != None:
        column_name = result.group(1)
        column_type = result.group(2)
        element_idx = result.group(3)
        # print (column_name, column_type)
        return (column_name, column_type, element_idx)
    else:
        print "parse_column_name error"
        sys.exit(0)
        
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

def parse_pair(line):
    result = re.search(r"name=([^;\n]*);value=([^\n]*)", line)
    name = ""
    value = ""
    if result != None:
        name = result.group(1)
        value = result.group(2)
        return (name, value)
    else:
        print "parse_pair error"
        return None

def parse_pair_length(line):
    # print line
    result = re.search(r"name=([^;\n]*);len\(value\)>(-?[0-9]+)", line)
    name = ""
    value = ""
    if result != None:
        name = result.group(1)
        value = result.group(2)
        return (name, value)
    else:
        print "parse_pair_length error"
        return None

def regex_normalize(pattern):
    pattern = re.sub(r"(?<!\\)\\d", r"\\\\d", pattern);
    pattern = re.sub(r"(?<!\\)\\\*", r"\\\\*", pattern);
    pattern = re.sub(r"(?<!\\)\\\/", r"\\\\/", pattern);
    pattern = re.sub(r"(?<!\\)\\x", r"\\\\x", pattern);
    pattern = re.sub(r"(?<!\\)\\n", r"\\\\n", pattern);
    pattern = re.sub(r"(?<!\\)\\r", r"\\\\r", pattern);
    pattern = re.sub(r"(?<!\\)\\\?", r"\\\\?", pattern);
    pattern = re.sub(r"(?<!\\)\\s", r"\\\\s", pattern);
    pattern = re.sub(r"(?<!\\)\\\.", r"\\\.", pattern);
    pattern = re.sub(r"(?<!\\)\\\,", r"\\\,", pattern);
    pattern = re.sub(r"(?<!\\)\\\(", r"\\\(", pattern);
    pattern = re.sub(r"(?<!\\)\\\)", r"\\\)", pattern);
    pattern = re.sub(r"(?<!\\)\\\%", r"\\\%", pattern);
    pattern = re.sub(r"(?<!\\)\\\~", r"\\\~", pattern);
    pattern = re.sub(r"(?<!\\)\\\|", r"\\\|", pattern);
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

def string_normalize(pattern):    
    pattern = re.sub(r"(?<!\\)\\\~", r"\\\~", pattern);
    pattern = re.sub(r"(?<!\\)\\\.", r"\\\.", pattern);
    return pattern
            
if __name__ == '__main__':
    rule_list = []
    indent_list = []
    rule_sorted_list = []
    for line in open(argv[1], "r"):
        rule_list.append(parse_line(line))
    
    (file_path, file_name) = os.path.split(argv[1])
    (file_base, file_ext) = os.path.splitext(file_name)
    
    cpp_file = open(argv[2], "w")
    
    cpp_file.write('#include "HTTPAnalyzerSeq.h"\n\n')
    cpp_file.write('#include "Global.h"\n\n')  
    
    rule_index = 1
    while rule_index < len(rule_list):
        
        column_index = 0
        while column_index < len(rule_list[0]):
            # cpp_file.write(rule_list[rule_index + 1][column_index])
            # cpp_file.write(" ")
            if rule_list[rule_index][column_index] != "N":
                (column_name, column_type, element_idx) = parse_column_name(rule_list[0][column_index])
                if column_name == "Variable" or column_name == "Headers":
                    if column_type == "AM":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("FieldPairStringMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "RE":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("FieldPairRegexMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        (name, value) = parse_pair_length(rule_list[rule_index][column_index])
                        cpp_file.write("FieldPairLengthMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                elif column_name == "anydirs":
                    if column_type == "AM":
                        cpp_file.write("AnyElementStringMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        cpp_file.write("AnyElementLengthMatcher * Rule%u_%s = NULL;" % (rule_index - 1, rule_list[0][column_index]))
                elif column_name == "dirs":
                    if column_type == "AM":
                        cpp_file.write("ElementStringMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                else:
                    if column_type == "AM":
                        cpp_file.write("StringMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "RE":
                        cpp_file.write("RegexMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        cpp_file.write("LengthMatcher * Rule%u_%s = NULL;\n" % (rule_index - 1, rule_list[0][column_index]))
            column_index += 1
        rule_index += 1
    
    cpp_file.write("""
void HTTPAnalyzerSeqInit()
{\n""")

    rule_index = 1
    while rule_index < len(rule_list):
        
        column_index = 0
        while column_index < len(rule_list[0]):
            # cpp_file.write(rule_list[rule_index + 1][column_index])
            # cpp_file.write(" ")
            if rule_list[rule_index][column_index] != "N":
                (column_name, column_type, element_idx) = parse_column_name(rule_list[0][column_index])
                if column_name == "Variable" or column_name == "Headers":
                    if column_type == "AM":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    Rule%u_%s = new FieldPairStringMatcher(%s, %s);\n" % (rule_index - 1, rule_list[0][column_index], name, string_normalize(value)))
                    elif column_type == "RE":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    Rule%u_%s = new FieldPairRegexMatcher(%s, %s);\n" % (rule_index - 1, rule_list[0][column_index], name, regex_normalize(value)))
                    elif column_type == "LE":
                        (name, value) = parse_pair_length(rule_list[rule_index][column_index])
                        cpp_file.write("    Rule%u_%s = new FieldPairLengthMatcher(%s, %s);\n" % (rule_index - 1, rule_list[0][column_index], name, value))
                elif column_name == "anydirs":
                    if column_type == "AM":
                        cpp_file.write("    Rule%u_%s = new AnyElementStringMatcher(\"%s\");\n" % (rule_index - 1, rule_list[0][column_index], string_normalize(rule_list[rule_index][column_index])))
                    elif column_type == "LE":
                        cpp_file.write("    Rule%u_%s = new AnyElementLengthMatcher(%s);\n" % (rule_index - 1, rule_list[0][column_index], rule_list[rule_index][column_index]))
                elif column_name == "dirs":
                    if column_type == "AM":
                        cpp_file.write("    Rule%u_%s = new ElementStringMatcher(%s, \"%s\");\n" % (rule_index - 1, rule_list[0][column_index], element_idx, string_normalize(rule_list[rule_index][column_index])))
                else:
                    if column_type == "AM":
                        cpp_file.write("    Rule%u_%s = new StringMatcher(\"%s\");\n" % (rule_index - 1, rule_list[0][column_index], string_normalize(rule_list[rule_index][column_index])))
                    elif column_type == "RE":
                        cpp_file.write("    Rule%u_%s = new RegexMatcher(\"%s\");\n" % (rule_index - 1, rule_list[0][column_index], regex_normalize(rule_list[rule_index][column_index])))
                    elif column_type == "LE":
                        cpp_file.write("    Rule%u_%s = new LengthMatcher(%s);\n" % (rule_index - 1, rule_list[0][column_index], rule_list[rule_index][column_index]))
            column_index += 1
        rule_index += 1
    cpp_file.write("""
    maxDFAStructTotalSize = currentDFAStructTotalSize;
    maxTrieStructTotalSize = currentTrieStructTotalSize;
}\n""")
    
    rule_index = 1
    while rule_index < len(rule_list):
        cpp_file.write("""
void Rule%u_Match(const Field & method, const Field & filename,
                 const vector<Field> & dirFieldVector, const vector<Field> & varNameVector, 
                 const vector<Field> & varValueVector, const vector<Field> & headerNameVector,
                 const vector<Field> & headerValueVector, const Field & assignment, const Field & uri)
{
""" % (rule_index - 1))
        
        column_index = 0
        while column_index < len(rule_list[0]):
            # cpp_file.write(rule_list[rule_index + 1][column_index])
            # cpp_file.write(" ")
            if rule_list[rule_index][column_index] != "N":
                (column_name, column_type, element_idx) = parse_column_name(rule_list[0][column_index])
                if column_name == "Variable":
                    if column_type == "AM":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(varNameVector, varValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "RE":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(varNameVector, varValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        (name, value) = parse_pair_length(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(varNameVector, varValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                elif column_name == "Headers":
                    if column_type == "AM":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(headerNameVector, headerValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "RE":
                        (name, value) = parse_pair(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(headerNameVector, headerValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        (name, value) = parse_pair_length(rule_list[rule_index][column_index])
                        cpp_file.write("    if(Rule%u_%s->match(headerNameVector, headerValueVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                elif column_name == "anydirs":
                    if column_type == "AM":
                        cpp_file.write("    if(Rule%u_%s->match(dirFieldVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                    elif column_type == "LE":
                        cpp_file.write("    if(Rule%u_%s->match(dirFieldVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                elif column_name == "dirs":
                    if column_type == "AM":
                        cpp_file.write("    if(Rule%u_%s->match(dirFieldVector) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index]))
                else:
                    if column_type == "AM":
                        cpp_file.write("    if(Rule%u_%s->match(%s) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index], column_name))
                    elif column_type == "RE":
                        cpp_file.write("    if(Rule%u_%s->match(%s) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index], column_name))
                    elif column_type == "LE":
                        cpp_file.write("    if(Rule%u_%s->match(%s) == false) { return; }\n" % (rule_index - 1, rule_list[0][column_index], column_name))
            column_index += 1
        
        cpp_file.write("""
    if(silent->count == 0)
    {
        if(ruleMap.find(%u) == ruleMap.end())
        {
            ruleMap[%u] = 1;
        }
        else
        {
            ruleMap[%u] += 1;
        }
        printf(\"Rule %s matched!\\n\");
    }
}\n\n""" % (rule_index - 1, rule_index - 1, rule_index - 1, rule_index - 1))
        
        rule_index += 1
    
    cpp_file.write("""
void HTTPAnalyzerSeqMatch(const Field & methodField, const Field & filenameField,
                          const vector<Field> & dirFieldVector, const vector<Field> & varNameVector, 
                          const vector<Field> & varValueVector, const vector<Field> & headerNameVector,
                          const vector<Field> & headerValueVector, const Field & assignmentField, const Field & uriField)
{\n""")
    
    rule_index = 1
    while rule_index < len(rule_list):
        cpp_file.write("""
    Rule%u_Match(methodField, filenameField, dirFieldVector, varNameVector, varValueVector,
                 headerNameVector, headerValueVector, assignmentField, uriField);
""" % (rule_index - 1))
        
        rule_index += 1
        
    cpp_file.write("}\n")

    cpp_file.close()
    