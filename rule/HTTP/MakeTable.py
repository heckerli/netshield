################################################################################
#                                                                              #
#   NetShield Signature Parser and Signature-Matcher Table Creator             #
#                                                                              #
#   Created by:    James West                                                  #
#   Last updated:  18 April 2008                                               #
#                                                                              #
#   This file contains a set of functions used to parse the NetShield          #
#   signatures and the make_table function, which reads the NetShield          #
#   signatures from an input file and writes the signature-matcher table       #
#   to an output file.                                                         #
#                                                                              #
#                                                                              #
#   Notes:                                                                     #
#                                                                              #
#   1. Signatures that are preceded by an "#" are ignored.                     #
#                                                                              #
#   2. When there are no parentheses to explicitly indicate the order of       #
#      operations, the "||" operation is always evaluated before the "&&"      #
#      operation.                                                              #
#                                                                              #
#   3. The only accepted conditional operators for the len() operation are     #
#      ">" and ">=".                                                           #
#                                                                              #
#   4. The following fields are handled by the parser:                         #
#        HTTP_RequestLine.method                                               #
#        HTTP_RequestLine.uri                                                  #
#        HTTP_RequestLine.uri.path.filename                                    #
#        HTTP_RequestLine.uri.path.dirs                                        #
#        any(HTTP_RequestLine.uri.path.dirs)                                   #
#        HTTP_RequestLine.uri.assignment_sequence                              #
#        HTTP_RequestLine.uri.assignment_sequence.variable                     #
#        any(HTTP_RequestLine.uri.assignment_sequence.variable.names)          #
#        HTTP_Headers                                                          #
#        any(HTTP_Headers.names)                                               #
#                                                                              #
################################################################################

import sys

################################################################################
#                                                                              #
#                              Parsing Functions                               #
#                                                                              #
################################################################################

def comment(signature):
    """ Returns true if signature is commented out and false otherwise. """
    # skip whitespace
    i = 0
    while signature[i:i+1].isspace():
        i = i + 1
    # return true if first non-whitespace character is "#" and false otherwise
    return signature[i:i+1] == '#'
    

def get_start_index(signature):
    """ Returns index of first condition or -1 on failure. """
    # skip whitespace
    i = 0
    while signature[i:i+1].isspace():
        i = i + 1
    # check if first non-whitespace characters are "Signature:" and return index
    # of character immediately following "Signature:"
    if signature[i:i+10] == 'Signature:':
        return i + 10
    # return -1 on failure
    return -1

def get_open_par(signature, i):
    """ Returns list with index of open parenthesis and new index or [-1, -1]
    on failure.
    """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # check if first non-whitespace character starting with i is "(" and return
    # index of "(" and index of character immediately following "("
    if signature[i:i+1] == '(':
        return [i, i + 1]
    # return [-1, -1] on failure
    return [-1, -1]
        
def get_close_par(signature, i):
    """ Returns list with index of close parenthesis and new index or [-1, -1]
    on failure.
    """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # check if first non-whitespace character starting with i is ")" and return
    # index of ")" and index of character immediately following ")"
    if signature[i:i+1] == ')':
        return [i, i + 1]
    # return [-1, -1] on failure
    return [-1, -1]
        
def get_comma(signature, i):
    """ Returns list with index of comma and new index or [-1, -1] on failure.
    """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # check if first non-whitespace character starting with i is "," and return
    # index of "," and index of character immediately following ","
    if signature[i:i+1] == ',':
        return [i, i + 1]
    # return [-1, -1] on failure
    return [-1, -1]

def get_operation(signature, i):
    """ Returns list with operation and new index or [-1, -1] on failure. """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # check if first non-whitespace characters starting with i are "len" or
    # "match_re" and return operation type and index of character immediately
    # following "len" or "match_re"
    if signature[i:i+3] == 'len':
        return ['length', i + 3]
    elif signature[i:i+8] == 'match_re':
        return ['reg_exp', i + 8]
    # if operation is not length checking or regular signature matching, then
    # assume it is exact matching and return exact matching operation type and
    # index of character immediately following whitespace
    else:
        return ['exact', i]

def get_field(signature, i):
    """ Returns list with field name and new index or [-1, -1] on failure. """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # Compare first non-whitespace characters against all known fields and
    # return field name and index of character immediately following field name.
    # Return [-1, -1] if the field is unknown or an unknown subfield of a known
    # field, which is indicated by a "." following the known field name.
    if signature[i:i+24] == 'HTTP_RequestLine.method.':
        return [-1, -1]
    if signature[i:i+23] == 'HTTP_RequestLine.method':
        return ['method', i + 23]
    elif signature[i:i+35] == 'HTTP_RequestLine.uri.path.filename.':
        return [-1, -1]
    elif signature[i:i+34] == 'HTTP_RequestLine.uri.path.filename':
        return ['filename', i + 34]
    elif signature[i:i+31] == 'HTTP_RequestLine.uri.path.dirs.':
        return [-1, -1]
    elif signature[i:i+30] == 'HTTP_RequestLine.uri.path.dirs':
        return ['dirs', i + 30]
    elif signature[i:i+50] == \
         'HTTP_RequestLine.uri.assignment_sequence.variable.':
        return [-1, -1]
    elif signature[i:i+49] == \
         'HTTP_RequestLine.uri.assignment_sequence.variable':
        return ['variable', i + 49]
    elif signature[i:i+41] == 'HTTP_RequestLine.uri.assignment_sequence.':
        return [-1, -1]
    elif signature[i:i+40] == 'HTTP_RequestLine.uri.assignment_sequence':
        return ['assignment_sequence', i + 40]
    elif signature[i:i+21] == 'HTTP_RequestLine.uri.':
        return [-1, -1]
    elif signature[i:i+20] == 'HTTP_RequestLine.uri':
        return ['uri', i + 20]
    elif signature[i:i+13] == 'HTTP_Headers.':
        return [-1, -1]
    elif signature[i:i+12] == 'HTTP_Headers':
        return ['HTTP_Headers', i + 12]
    elif signature[i:i+3] == 'any':
        i = i + 3
        # get open parenthesis
        [openPar, i] = get_open_par(signature, i)
        if openPar == -1:
            return [-1, -1]
        # skip whitespace
        while signature[i:i+1].isspace():
            i = i + 1
        # get field
        if signature[i:i+31] == 'HTTP_RequestLine.uri.path.dirs.':
            return [-1, -1]
        elif signature[i:i+30] == 'HTTP_RequestLine.uri.path.dirs':
            field = 'any_dirs'
            i = i + 30
        elif signature[i:i+56] == \
             'HTTP_RequestLine.uri.assignment_sequence.variable.names.':
            return [-1, -1]
        elif signature[i:i+55] == \
             'HTTP_RequestLine.uri.assignment_sequence.variable.names':
            field = 'any_variable_names'
            i = i + 55
        elif signature[i:i+19] == 'HTTP_Headers.names.':
            return [-1, -1]
        elif signature[i:i+18] == 'HTTP_Headers.names':
            field = 'any_header_names'
            i = i + 18
        # get close parentheses
        [closePar, i] = get_close_par(signature, i)
        if closePar == -1:
            return [-1, -1]
        return [field, i]
    else:
        return [-1, -1]

def get_string(signature, i):
    """ Returns list with string and new index or [-1, -1] on failure. """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # check for opening quotation mark
    if signature[i:i+1] == '"':
        i = i + 1
        # store index of first character of string
        startIndex = i
        # scan characters
        while i < len(signature):
            # check for non-escaped quotation mark
            if signature[i] == '"' and signature[i-1] != '\\':
                # store index following last character in string
                endIndex = i;
                # get string
                string = signature[startIndex:endIndex]
                # return string and index of character immediately
                # following closing quotation mark
                return [string, i + 1]
            i = i + 1
    # return [-1, -1] on failure
    return [-1, -1]

def get_number(signature, i):
    """ Returns list with number and new index or [-1, -1] on failure. """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    if signature[i:i+1].isdigit():
        startIndex = i
        while signature[i:i+1].isdigit():
            i = i + 1
        endIndex = i
        length = signature[startIndex:endIndex]
        return [length, i]
    # return [-1, -1] on failure
    return [-1, -1]
        
def get_name(signature, i):
    """ Returns list with associate array element name and new index or [-1, -1]
    on failure.
    """
    # Do not skip whitespace at the beginning since there should be no
    # whitespace between the field name and the opening bracket.
    # check for opening bracket
    if signature[i:i+1] == '[':
        i = i + 1
        # skip whitespace
        while signature[i:i+1].isspace():
            i = i + 1
        # get name and check if valid
        [name, i] = get_string(signature, i)
        if name != -1:
            # skip whitespace
            while signature[i:i+1].isspace():
                i = i + 1
            # check for closing bracket
            if signature[i:i+1] == ']':
                # return name and index of character immediately
                # following closing bracket
                return [name, i + 1]
    # return [-1, -1] on failure
    return [-1, -1]
        
def get_dirs_index(signature, i):
    """ Returns list with dirs index and new index or [-1, -1] on failure. """
    # The function looks for the x in the construction [len(dirs)-x] with
    # whitespace allowed as in [ len ( dirs ) - x ].
    # Do not skip whitespace at the beginning since there should be no
    # whitespace between the field name and the opening bracket.
    # check for opening bracket
    if signature[i:i+1] == '[':
        i = i + 1
        # skip whitespace
        while signature[i:i+1].isspace():
            i = i + 1
        # check for "len"
        if signature[i:i+3] == 'len':
            i = i + 3
            # skip whitespace
            while signature[i:i+1].isspace():
                i = i + 1
            # check for open parenthesis
            if signature[i:i+1] == '(':
                i = i + 1
                # skip whitespace
                while signature[i:i+1].isspace():
                    i = i + 1
                # check for "dirs"
                if signature[i:i+4] == 'dirs':
                    i = i + 4
                    # skip whitespace
                    while signature[i:i+1].isspace():
                        i = i + 1
                    # check for close parenthesis
                    if signature[i:i+1] == ')':
                        i = i + 1
                        # skip whitespace
                        while signature[i:i+1].isspace():
                            i = i + 1
                        # check for minus sign
                        if signature[i:i+1] == '-':
                            i = i + 1
                            # skip whitespace
                            while signature[i:i+1].isspace():
                                i = i + 1
                            # get dirs index and check if valid
                            [dirsIndex, i] = get_number(signature, i)
                            if dirsIndex != -1:
                                # skip whitespace
                                while signature[i:i+1].isspace():
                                    i = i + 1
                                # check for closing bracket
                                if signature[i:i+1] == ']':
                                    i = i + 1
                                    # return dirs index and index of character
                                    # immediately following closing bracket
                                    return [dirsIndex, i]
    # return [-1, -1] on failure
    return [-1, -1]
    
def get_bool_op(signature, i):
    """ Returns list with boolean operator and new index or [-1, -1] on failure.
    """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # Compare the first non-whitespace characters against boolean operators and
    # return the boolean operator and the index of character immediately
    # following the boolean operator.
    # Return [-1, -1] if the first non-whitespace characters are not a boolean
    # operator.
    if signature[i:i+2] == '&&':
        return ['&&', i + 2]
    elif signature[i:i+2] == '||':
        return ['||', i + 2]
    else:
        return [-1, -1]
    
def get_cond_op(signature, i):
    """ Returns list with conditional operator and new index or [-1, -1] on
    failure.
    """
    # skip whitespace
    while signature[i:i+1].isspace():
        i = i + 1
    # Compare the first non-whitespace characters against conditional operators
    # and return the conditional operator and the index of character immediately
    # following the conditional operator.
    # Return [-1, -1] if the first non-whitespace characters are not a
    # conditional operator.
    if signature[i:i+2] == '==':
        return ['==', i + 2]
    elif signature[i:i+2] == '<=':
        return ['<=', i + 2]
    elif signature[i:i+2] == '>=':
        return ['>=', i + 2]
    elif signature[i:i+1] == '<':
        return ['<', i + 1]
    elif signature[i:i+1] == '>':
        return ['>', i + 1]
    else:
        return [-1, -1]

def end_of_sig(signature, i):
    """ Returns true if end of signature or false otherwise. """
    # return true if all characters from i to the end of the signature are
    # whitespace
    return signature[i:len(signature)].isspace() or \
           not signature[i:len(signature)]
    
def print_error(error, sigNum, signature):
    """ Prints error message. """
    # print the error message with the signature number
    print "Error: invalid signature - " + error + \
          " in signature " + str(sigNum) + "."
    # print the signature
    print signature.strip()
    
    
################################################################################
#                                                                              #
#                             Make Table Function                              #
#                                                                              #
################################################################################
    
def make_table(inFile, outFile):
    """ Generates table from signatures in inFile and saves to outFile. """
    # read signatures from file into list
    sigFile = open(inFile,'r')
    origSigs = sigFile.readlines()
    sigFile.close()
    
    # create list of signatures with index to original signature for error
    # reporting
    signatures = []
    sigIndex = 0
    for signature in origSigs:
        # ignore signatures that are commented out
        if not comment(signature):
            # signature numbers start at 1, signature indices start at 0
            sigNum = sigIndex + 1
            # add signature number and signature to signatures list
            signatures.append([sigNum, signature])
        sigIndex = sigIndex + 1
    
    
    ########################################################
    #                                                      #
    #   Convert signatures with an || expression to        #
    #   multiple signatures as shown below.                #
    #                                                      #
    #   Original signature:                                #
    #     ((condition_1)||(condition_2)||(condition_3))    #
    #     &&(condition_4)                                  #
    #                                                      #
    #   Convert to:                                        #
    #     (condition_1)&&(condition_4)                     #
    #     (condition_2)&&(condiiton_4)                     #
    #     (condition_3)&&(condiiton_4)                     #
    #                                                      #
    ########################################################
    
    sigIndex = 0
    while sigIndex < len(signatures):
        sigNumber = signatures[sigIndex][0]  # signature number for error
                                             #   messages
        signature = signatures[sigIndex][1]  # signature
        
        # get index of first "||"
        if signature.find('||') == -1:
            sigIndex = sigIndex + 1
            continue
        else:
            orOperators = []       # list of indices of "||"
            openParentheses = []   # stack of indices of open parentheses
            parenthesesPairs = []  # list of indices of corresponding pairs of
                                   #   parentheses
            stringIndexPairs = []  # list with start and end indices of strings
            badSig = False         # true if error in signature
            i = 0
            while i < len(signature):
                # skip strings
                if signature[i] == '"':
                    stringStartIndex = i
                    [string, i] = get_string(signature, i)
                    if string == -1:
                        # print invalid string error and remove from
                        # signatures list
                        print_error('invalid string',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    stringEndIndex = i - 1
                    stringIndexPairs.append([stringStartIndex, stringEndIndex])
                # check for open parenthesis
                elif signature[i] == '(':
                    # push index of open parenthesis onto stack
                    openParentheses.append(i)
                    i = i + 1
                # check for close parenthesis
                elif signature[i] == ')':
                    # make sure open parentheses stack is not empty
                    if openParentheses:
                        # pop index of corresponding open parenthesis
                        openParIndex = openParentheses.pop()
                        closeParIndex = i
                        # add parentheses pair to list
                        parenthesesPairs.append([openParIndex, closeParIndex])
                        i = i + 1
                    else:
                        # print missing parenthesis error and remove from
                        # signatures list
                        print_error('missing parenthesis',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                # check for "||"
                elif signature[i:i+2] == '||':
                    # add index of "||" to list
                    orOperators.append(i)
                    i = i + 2
                else:
                    i = i + 1
            # delete signature and continue to next one if bad
            if badSig:
                signatures.pop(sigIndex)
                continue
            # print error and delete signature if all corresponding close
            # parentheses not found
            if openParentheses:
                print_error('missing parenthesis',
                            sigNumber,
                            origSigs[sigNumber-1])
                signatures.pop(sigIndex)
                continue
            # continue to next signature if no "||" found outside parentheses
            if not orOperators:
                sigIndex = sigIndex + 1
                continue
            # find preceding and following conditions for each "||"
            conditionSets = []
            for orOperator in orOperators:
                firstCondition = [-1, -1]
                secondCondition = [len(signature), len(signature)]
                for parenthesesPair in parenthesesPairs:
                    # find close parenthesis immediately preceding "||"
                    if parenthesesPair[1] < orOperator and \
                       parenthesesPair[1] > firstCondition[1]:
                        firstCondition = parenthesesPair
                    # find open parenthesis immediately following "||"
                    if parenthesesPair[0] > orOperator and \
                       parenthesesPair[0] < secondCondition[0]:
                        secondCondition = parenthesesPair
                # print error and break from loop if initial pairs not changed
                if firstCondition[0] == -1 or \
                   firstCondition[1] == -1 or \
                   secondCondition[0] == len(signature) or \
                   secondCondition[1] == len(signature):
                    print_error('missing parenthesis',
                                sigNumber,
                                origSigs[sigNumber-1])
                    badSig = True
                    break
                conditionSets.append([firstCondition, secondCondition])
            # delete signature and continue to next one if bad
            if badSig:
                signatures.pop(sigIndex)
                continue
            i = 0
            while i < (len(conditionSets) - 1):
                if conditionSets[i + 1][0] == \
                   conditionSets[i][len(conditionSets[i]) - 1]:
                    conditionSets[i].append(conditionSets[i + 1][1])
                    conditionSets.pop(i + 1)
                else:
                    break
            # add signatures with first OR expression replaced with conditions
            # additional OR expressions will be replaced on next pass
            conditionSet = conditionSets[0]
            conditionSetStart = conditionSet[0][0]
            conditionSetEnd = conditionSet[len(conditionSet) - 1][1]
            # delete original signature
            signatures.pop(sigIndex)
            # loop through conditions, replace OR expression with condition,
            # and insert into signatures
            i = len(conditionSet) - 1
            while i >= 0:
                signatures.insert(sigIndex, [sigNumber,
                                             signature[:conditionSetStart] + \
                                             signature[conditionSet[i][0]:
                                                       conditionSet[i][1]] + \
                                             signature[conditionSetEnd:]])
                i = i - 1
    
    
    ########################################################
    #                                                      #
    #   Create Python list newSigs containing the          #
    #   signatures and matchers in the following form:     #
    #                                                      #
    #    [ [ [signature_1_matcher_1_field,                 #
    #         signature_1_matcher_1_operation,             #
    #         signature_1_matcher_1_value],                #
    #        [signature_1_matcher_2_field,                 #
    #         signature_1_matcher_2_operation,             #
    #         signature_1_matcher_2_value],                #
    #                     ...                              #
    #        [signature_1_matcher_n_field,                 #
    #         signature_1_matcher_n_operation,             #
    #         signature_1_matcher_n_value] ],              #
    #                                                      #
    #      [ [signature_2_matcher_1_field,                 #
    #         signature_2_matcher_1_operation,             #
    #         signature_2_matcher_1_value],                #
    #        [signature_2_matcher_2_field,                 #
    #         signature_2_matcher_2_operation,             #
    #         signature_2_matcher_2_value],                #
    #                     ...                              #
    #        [signature_2_matcher_n_field,                 #
    #         signature_2_matcher_n_operation,             #
    #         signature_2_matcher_n_value] ],              #
    #                                                      #
    #                     ...                              #
    #                                                      #
    #      [ [signature_n_matcher_1_field,                 #
    #         signature_n_matcher_1_operation,             #
    #         signature_n_matcher_1_value],                #
    #        [signature_n_matcher_2_field,                 #
    #         signature_n_matcher_2_operation,             #
    #         signature_n_matcher_2_value],                #
    #                     ...                              #
    #        [signature_n_matcher_n_field,                 #
    #         signature_n_matcher_n_operation,             #
    #         signature_n_matcher_n_value] ] ]             #
    #                                                      #
    #   where each signature is represented by a list of   #
    #   matchers containing the field being matched, the   #
    #   operation of the matcher (exact matching,          #
    #   regular expression matching, or length             #
    #   checking), and the value the field is to be        #
    #   checked against.                                   #
    #                                                      #
    ########################################################
    
    newSigs = []  # list containing signatures with matchers
    
    for signature in signatures:
        sigNumber = signature[0]  # signature number for error messages
        signature = signature[1]  # signature        
        badSig = False            # true if signature contains an error
        sigMatchers = []          # list of signature matchers
        openParentheses = []      # stack of indices of open parentheses
        
        i = get_start_index(signature)
        if i == -1:
            print_error('missing Signature:',
                        sigNumber,
                        origSigs[sigNumber-1])
            
        while i < len(signature):
            # skip any leading whitespace
            if signature[i].isspace():
                i = i + 1
            # push open parentheses onto stack
            elif signature[i] == '(':
                openParentheses.append(i)
                i = i + 1            
            else:
                # get operation (exact matching, regular expression matching,
                # length checking)
                [operation, i] = get_operation(signature, i)
                
                # exact matching
                if operation == 'exact':
                    # get field
                    [field, i] = get_field(signature, i)
                    if field == -1:
                        print_error('invalid field',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break                        
                    # get dirs index if dirs
                    if field == 'dirs':
                        [dirsIndex, i] = get_dirs_index(signature, i)
                        if dirsIndex == -1:
                            print_error('invalid dirs index',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                        field = field + str(dirsIndex)
                    # get variable or HTTP header name if variable or
                    # HTTP header
                    elif field == 'variable' or field == 'HTTP_Headers':
                        [name, i] = get_name(signature, i)
                        if name == -1:
                            print_error('invalid ' + field + ' name',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                    # check for "=="
                    [condOp, i] = get_cond_op(signature, i)
                    if condOp != '==':
                        print_error('invalid exact matching operator',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get string
                    [value, i] = get_string(signature, i)
                    if value == -1:
                        print_error('invalid string',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                        
                # regular expression matching
                elif operation == 'reg_exp':
                    # get open parenthesis and push onto stack
                    [openPar, i] = get_open_par(signature, i)
                    if openPar == -1:
                        print_error('missing parenthesis',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    openParentheses.append(openPar)
                    # get regular expression
                    [value, i] = get_string(signature, i)
                    if value == -1:
                        print_error('invalid regular expression',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get comma
                    [comma, i] = get_comma(signature, i)
                    if comma == -1:
                        print_error('missing comma',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get field
                    [field, i] = get_field(signature, i)
                    if field == -1:
                        print_error('invalid field',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get dirs index if dirs
                    if field == 'dirs':
                        [dirsIndex, i] = get_dirs_index(signature, i)
                        if dirsIndex == -1:
                            print_error('invalid dirs index',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                        field = field + str(dirsIndex)
                    # get variable or HTTP header name if variable or
                    # HTTP header
                    elif field == 'variable' or field == 'HTTP_Headers':
                        [name, i] = get_name(signature, i)
                        if name == -1:
                            print_error('invalid ' + field + ' name',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                    
                # length checking
                elif operation == 'length':
                    # get open parenthesis
                    [openPar, i] = get_open_par(signature, i)
                    if openPar == -1:
                        print_error('missing parenthesis',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    openParentheses.append(openPar)
                    # get field
                    [field, i] = get_field(signature, i)
                    if field == -1:
                        print_error('invalid field',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get dirs index if dirs
                    if field == 'dirs':
                        [dirsIndex, i] = get_dirs_index(signature, i)
                        if dirsIndex == -1:
                            print_error('invalid dirs index',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                        field = field + str(dirsIndex)
                    # get variable or HTTP header name if variable or
                    # HTTP header
                    elif field == 'variable' or field == 'HTTP_Headers':
                        [name, i] = get_name(signature, i)
                        if name == -1:
                            print_error('invalid ' + field + ' name',
                                        sigNumber,
                                        origSigs[sigNumber-1])
                            badSig = True
                            break
                    # get close parentheses
                    [closePar, i] = get_close_par(signature, i)
                    if closePar == -1 or not openParentheses:
                        print_error('missing parenthesis',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # pop corresponding open parenthesis from stack
                    openParentheses.pop()
                    # get conditional operator
                    [condOp, i] = get_cond_op(signature, i)
                    if condOp == -1:
                        print_error('invalid conditional operator',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    # get length
                    [value, i] = get_number(signature, i)
                    if value == -1:
                        print_error('invalid length',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                    if condOp == '>=':
                        value = str(int(value) - 1)
                    elif condOp != '>':
                        print_error('invalid conditional operator',
                                    sigNumber,
                                    origSigs[sigNumber-1])
                        badSig = True
                        break
                        
                else:
                    print_error('invalid operation',
                                sigNumber,
                                origSigs[sigNumber-1])
                    badSig = True
                    break
                    
                # get close parentheses and check for corresponding
                # open parentheses
                [closePar, i] = get_close_par(signature, i)
                if closePar == -1:
                    print_error('missing parenthesis',
                                sigNumber,
                                origSigs[sigNumber-1])
                    badSig = True
                    break
                missingPar = False
                while closePar != -1:
                    # make sure open parentheses stack is not empty
                    if openParentheses:
                        # pop corresponding open parenthesis from stack
                        openParentheses.pop()
                        tempIndex = i
                        # check if additional parenthesis
                        [closePar, i] = get_close_par(signature, i)
                    else:
                        missingPar = True
                        break
                i = tempIndex
                if missingPar:
                    print_error('missing parenthesis',
                                sigNumber,
                                origSigs[sigNumber-1])
                    badSig = True
                    break
                # create name;value pair for value for variables and
                # HTTP headers
                if field == 'variable' or field == 'HTTP_Headers':
                    if operation == 'length':
                        value = 'name="' + name + '";len(value)>' + value
                    else:
                        value = 'name="' + name + '";value="' + value + '"'
                # create matcher and add to matchers list
                matcher = [field, operation, value]
                sigMatchers.append(matcher)
                # break from loop if end of signature
                if end_of_sig(signature, i):
                    break
                # get boolean operator
                [boolOp, i] = get_bool_op(signature, i)
                if boolOp != '&&':
                    print_error('invalid boolean operator',
                                sigNumber,
                                origSigs[sigNumber-1])
                    badSig = True
                    break
                    
        # skip to next signature if signature bad
        if badSig:
            continue
            
        # print error if all corresponding close parentheses not found
        if openParentheses:
            print_error('missing parenthesis',
                        sigNumber,
                        origSigs[sigNumber-1])
            continue
            
        # add list of matchers for signature to signatures list
        newSigs.append(sigMatchers)
    
    
    ########################################################
    #                                                      #
    #   Find which columns should be in the table and      #
    #   the number of dirs, variable, and header           #
    #   columns.                                           #
    #                                                      #
    ########################################################
    
    # set to true if the column exists
    methodExact = False
    methodRegExp = False
    methodLength = False
    filenameExact = False
    filenameRegExp = False
    filenameLength = False
    anyVariableNamesExact = False
    anyVariableNamesRegExp = False
    anyVariableNamesLength = False
    assignSeqExact = False
    assignSeqRegExp = False
    assignSeqLength = False
    uriExact = False
    uriRegExp = False
    uriLength = False
    anyHeaderNamesExact = False
    anyHeaderNamesRegExp = False
    anyHeaderNamesLength = False
    
    # set to the maximum number occurring in one signature
    maxAnyDirsExact = 0
    maxAnyDirsRegExp = 0
    maxAnyDirsLength = 0
    maxDirsExact = 0
    maxDirsRegExp = 0
    maxDirsLength = 0
    maxVariableExact = 0
    maxVariableRegExp = 0
    maxVariableLength = 0
    maxHeadersExact = 0
    maxHeadersRegExp = 0
    maxHeadersLength = 0
    
    for sigMatchers in newSigs:
        
        # number in one signature
        anyDirsExact = 0
        anyDirsRegExp = 0
        anyDirsLength = 0
        variableExact = 0
        variableRegExp = 0
        variableLength = 0
        headersExact = 0
        headersRegExp = 0
        headersLength = 0
        
        for matcher in sigMatchers:
            field = matcher[0]
            operation = matcher[1]
            value = matcher[2]
            
            # check if method columns exist
            if field[0:6] == 'method':
                if operation == 'exact':
                    methodExact = True
                elif operation == 'reg_exp':
                    methodRegExp = True
                elif operation == 'length':
                    methodLength = True
                else:
                    print "Error: invalid operation in matcher."
            # check if filename columns exist
            elif field[0:8] == 'filename':
                if operation == 'exact':
                    filenameExact = True
                elif operation == 'reg_exp':
                    filenameRegExp = True
                elif operation == 'length':
                    filenameLength = True
                else:
                    print "Error: invalid operation in matcher."
            # increase maximum any dirs indices if any dirs index in current
            # signature is greater than current maximum any dirs index
            elif field[0:8] == 'any_dirs':
                if operation == 'exact':
                    anyDirsExact = anyDirsExact + 1
                elif operation == 'reg_exp':
                    anyDirsRegExp = anyDirsRegExp + 1
                elif operation == 'length':
                    anyDirsLength = anyDirsLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # increase maximum dirs indices if dirs index in current signature
            # is greater than current maximum dirs index
            elif field[0:4] == 'dirs':
                dirsIndex = int(field[4:])
                if operation == 'exact':
                    if dirsIndex > maxDirsExact:
                        maxDirsExact = dirsIndex
                elif operation == 'reg_exp':
                    if dirsIndex > maxDirsRegExp:
                        maxDirsRegExp = dirsIndex
                elif operation == 'length':
                    if dirsIndex > maxDirsLength:
                        maxDirsLength = dirsIndex
                else:
                    print "Error: invalid operation in matcher."
            # increment number of variable columns in current signature
            elif field[0:8] == 'variable':
                if operation == 'exact':
                    variableExact = variableExact + 1
                elif operation == 'reg_exp':
                    variableRegExp = variableRegExp + 1
                elif operation == 'length':
                    variableLength = variableLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # check if variable names columns exist
            elif field[0:18] == 'any_variable_names':
                if operation == 'exact':
                    anyVariableNamesExact = True
                elif operation == 'reg_exp':
                    anyVariableNamesRegExp = True
                elif operation == 'length':
                    anyVariableNamesLength = True
                else:
                    print "Error: invalid operation in matcher."
            # check if assignment sequence columns exist
            elif field[0:19] == 'assignment_sequence':
                if operation == 'exact':
                    assignSeqExact = True
                elif operation == 'reg_exp':
                    assignSeqRegExp = True
                elif operation == 'length':
                    assignSeqLength = True
                else:
                    print "Error: invalid operation in matcher."
            # check if URI columns exist
            elif field[0:3] == 'uri':
                if operation == 'exact':
                    uriExact = True
                elif operation == 'reg_exp':
                    uriRegExp = True
                elif operation == 'length':
                    uriLength = True
                else:
                    print "Error: invalid operation in matcher."
            # increment number of headers columns in current signature
            elif field[0:12] == 'HTTP_Headers':
                if operation == 'exact':
                    headersExact = headersExact + 1
                elif operation == 'reg_exp':
                    headersRegExp = headersRegExp + 1
                elif operation == 'length':
                    headersLength = headersLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # check if header names columns exist
            elif field[0:16] == 'any_header_names':
                if operation == 'exact':
                    anyHeaderNamesExact = True
                elif operation == 'reg_exp':
                    anyHeaderNamesRegExp = True
                elif operation == 'length':
                    anyHeaderNamesLength = True
                else:
                    print "Error: invalid operation in matcher."
            else:
                print "Error: invalid field in matcher."
        
        # update maximum values if value in current signature is greater than
        # current maximum value
        if anyDirsExact > maxAnyDirsExact:
            maxAnyDirsExact = anyDirsExact
        if anyDirsRegExp > maxAnyDirsRegExp:
            maxAnyDirsRegExp = anyDirsRegExp
        if anyDirsLength > maxAnyDirsLength:
            maxAnyDirsLength = anyDirsLength
        if variableExact > maxVariableExact:
            maxVariableExact = variableExact
        if variableRegExp > maxVariableRegExp:
            maxVariableRegExp = variableRegExp
        if variableLength > maxVariableLength:
            maxVariableLength = variableLength
        if headersExact > maxHeadersExact:
            maxHeadersExact = headersExact
        if headersRegExp > maxHeadersRegExp:
            maxHeadersRegExp = headersRegExp
        if headersLength > maxHeadersLength:
            maxHeadersLength = headersLength
    
    
    ########################################################
    #                                                      #
    #   Find which columns need to exist in the table,     #
    #   find indices for those columns, and create row     #
    #   with column names.                                 #
    #                                                      #
    ########################################################
    
    columnNames = []  # list of names of columns in table that will be
                      #   converted to first row of table
    
    index = 0
    # method columns
    if methodExact:
        methodExactIndex = index
        columnNames.append('method_AM')
        index = index + 1
    if methodRegExp:
        methodRegExpIndex = index
        columnNames.append('method_RE')
        index = index + 1
    if methodLength:
        methodLengthIndex = index
        columnNames.append('method_LE')
        index = index + 1
    # filename columns
    if filenameExact:
        filenameExactIndex = index
        columnNames.append('filename_AM')
        index = index + 1
    if filenameRegExp:
        filenameRegExpIndex = index
        columnNames.append('filename_RE')
        index = index + 1
    if filenameLength:
        filenameLengthIndex = index
        columnNames.append('filename_LE')
        index = index + 1
    # any dirs columns
    iExact = 1
    if maxAnyDirsExact > 0:
        anyDirsExactIndices = [index]
        columnNames.append('anydirs_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    while iExact <= maxAnyDirsExact:
        anyDirsExactIndices.append(index)
        columnNames.append('anydirs_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    iRegExp = 1
    if maxAnyDirsRegExp > 0:
        anyDirsRegExpIndices = [index]
        columnNames.append('anydirs_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    while iRegExp <= maxAnyDirsRegExp:
        anyDirsRegExpIndices.append(index)
        columnNames.append('anydirs_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    iLength = 1
    if maxAnyDirsLength > 0:
        anyDirsLengthIndices = [index]
        columnNames.append('anydirs_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    while iExact <= maxAnyDirsExact:
        anyDirsLengthIndices.append(index)
        columnNames.append('anydirs_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    # dirs columns
    if maxDirsExact > 0:
        firstDirsExactIndex = index
        i = 1
        while i <= maxDirsExact:
            columnNames.append('dirs_AM_' + str(i))
            i = i + 1
        index = index + maxDirsExact
    if maxDirsRegExp > 0:
        firstDirsRegExpIndex = index
        i = 1
        while i <= maxDirsRegExp:
            columnNames.append('dirs_RE_' + str(i))
            i = i + 1
        index = index + maxDirsRegExp
    if maxDirsLength > 0:
        firstDirsLengthIndex = index
        i = 1
        while i <= maxDirsLength:
            columnNames.append('dirs_LE_' + str(i))
            i = i + 1
        index = index + maxDirsLength
    # variable columns
    iExact = 1
    if maxVariableExact > 0:
        variableExactIndices = [index]
        columnNames.append('Variable_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    while iExact <= maxVariableExact:
        variableExactIndices.append(index)
        columnNames.append('Variable_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    iRegExp = 1
    if maxVariableRegExp > 0:
        variableRegExpIndices = [index]
        columnNames.append('Variable_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    while iRegExp <= maxVariableRegExp:
        variableRegExpIndices.append(index)
        columnNames.append('Variable_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    iLength = 1
    if maxVariableLength > 0:
        variableLengthIndices = [index]
        columnNames.append('Variable_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    while iLength <= maxVariableLength:
        variableLengthIndices.append(index)
        columnNames.append('Variable_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    # variable names columns
    if anyVariableNamesExact:
        anyVariableNamesExactIndex = index
        columnNames.append('any_variable_names_AM')
        index = index + 1
    if anyVariableNamesRegExp:
        anyVariableNamesRegExpIndex = index
        columnNames.append('any_variable_names_RE')
        index = index + 1
    if anyVariableNamesLength:
        anyVariableNamesLengthIndex = index
        columnNames.append('any_variable_names_LE')
        index = index + 1
    # assignment sequence columns
    if assignSeqExact:
        assignSeqExactIndex = index
        columnNames.append('assignment_AM')
        index = index + 1
    if assignSeqRegExp:
        assignSeqRegExpIndex = index
        columnNames.append('assignment_RE')
        index = index + 1
    if assignSeqLength:
        assignSeqLengthIndex = index
        columnNames.append('assignment_LE')
        index = index + 1
    # URI columns
    if uriExact:
        uriExactIndex = index
        columnNames.append('uri_AM')
        index = index + 1
    if uriRegExp:
        uriRegExpIndex = index
        columnNames.append('uri_RE')
        index = index + 1
    if uriLength:
        uriLengthIndex = index
        columnNames.append('uri_LE')
        index = index + 1
    # headers columns
    iExact = 1
    if maxHeadersExact > 0:
        headersExactIndices = [index]
        columnNames.append('Headers_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    while iExact <= maxHeadersExact:
        headersExactIndices.append(index)
        columnNames.append('Headers_AM_' + str(iExact))
        iExact = iExact + 1
        index = index + 1
    iRegExp = 1
    if maxHeadersRegExp > 0:
        headersRegExpIndices = [index]
        columnNames.append('Headers_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    while iRegExp <= maxHeadersRegExp:
        headersRegExpIndices.append(index)
        columnNames.append('Headers_RE_' + str(iRegExp))
        iRegExp = iRegExp + 1
        index = index + 1
    iLength = 1
    if maxHeadersLength > 0:
        headersLengthIndices = [index]
        columnNames.append('Headers_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    while iLength <= maxHeadersLength:
        headersLengthIndices.append(index)
        columnNames.append('Headers_LE_' + str(iLength))
        iLength = iLength + 1
        index = index + 1
    # header names columns
    if anyHeaderNamesExact:
        anyHeaderNamesExactIndex = index
        columnNames.append('any_header_names_AM')
        index = index + 1
    if anyHeaderNamesRegExp:
        anyHeaderNamesRegExpIndex = index
        columnNames.append('any_header_names_RE')
        index = index + 1
    if anyHeaderNamesLength:
        anyHeaderNamesLengthIndex = index
        columnNames.append('any_header_names_LE')
        index = index + 1
    numberOfColumns = index
    
    
    ########################################################
    #                                                      #
    #   Create table as a Python list in the following     #
    #   form:                                              #
    #                                                      #
    #   [ [row_1_col_1, row_1_col_2, ... , row_1_col_n],   #
    #     [row_2_col_1, row_2_col_2, ... , row_2_col_n],   #
    #                          ...                         #
    #     [row_n_col_1, row_n_col_2, ... , row_n_col_n] ]  #
    #                                                      #
    #   where each row is a list containing the columns    #
    #   and the table is a list containing the rows.       #
    #                                                      #
    ########################################################
    
    table = []  # signature table in Python list form
    
    for sigMatchers in newSigs:
        row = ['N'] * numberOfColumns
        anyDirsExact = 0
        anyDirsRegExp = 0
        anyDirsLength = 0
        variableExact = 0
        variableRegExp = 0
        variableLength = 0
        headersExact = 0
        headersRegExp = 0
        headersLength = 0
        
        for matcher in sigMatchers:
            field = matcher[0]
            operation = matcher[1]
            value = matcher[2]
            
            # method columns
            if field[0:6] == 'method':
                if operation == 'exact':
                    row[methodExactIndex] = value
                elif operation == 'reg_exp':
                    row[methodRegExpIndex] = value
                elif operation == 'length':
                    row[methodLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            # filename columns
            elif field[0:8] == 'filename':
                if operation == 'exact':
                    row[filenameExactIndex] = value
                elif operation == 'reg_exp':
                    row[filenameRegExpIndex] = value
                elif operation == 'length':
                    row[filenameLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            # any dirs columns
            elif field[0:8] == 'any_dirs':
                if operation == 'exact':
                    row[anyDirsExactIndices[anyDirsExact]] = value
                    anyDirsExact = anyDirsExact + 1
                elif operation == 'reg_exp':
                    row[anyDirsRegExpIndices[anyDirsRegExp]] = value
                    anyDirsRegExp = anyDirsRegExp + 1
                elif operation == 'length':
                    row[anyDirsLengthIndices[anyDirsLength]] = value
                    anyDirsLength = anyDirsLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # dirs columns
            elif field[0:4] == 'dirs':
                dirsIndex = int(field[4:])
                if operation == 'exact':
                    row[firstDirsExactIndex + dirsIndex - 1] = value
                elif operation == 'reg_exp':
                    row[firstDirsRegExpIndex + dirsIndex - 1] = value
                elif operation == 'length':
                    row[firstDirsLengthIndex + dirsIndex - 1] = value
                else:
                    print "Error: invalid operation in matcher."
            # variable columns
            elif field[0:8] == 'variable':
                if operation == 'exact':
                    row[variableExactIndices[variableExact]] = value
                    variableExact = variableExact + 1
                elif operation == 'reg_exp':
                    row[variableRegExpIndices[variableRegExp]] = value
                    variableRegExp = variableRegExp + 1
                elif operation == 'length':
                    row[variableLengthIndices[variableLength]] = value
                    variableLength = variableLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # variable names columns
            elif field[0:18] == 'any_variable_names':
                if operation == 'exact':
                    row[anyVariableNamesExactIndex] = value
                elif operation == 'reg_exp':
                    row[anyVariableNamesRegExpIndex] = value
                elif operation == 'length':
                    row[anyVariableNamesLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            # assignment sequence columns
            elif field[0:19] == 'assignment_sequence':
                if operation == 'exact':
                    row[assignSeqExactIndex] = value
                elif operation == 'reg_exp':
                    row[assignSeqRegExpIndex] = value
                elif operation == 'length':
                    row[assignSeqLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            # URI columns
            elif field[0:3] == 'uri':
                if operation == 'exact':
                    row[uriExactIndex] = value
                elif operation == 'reg_exp':
                    row[uriRegExpIndex] = value
                elif operation == 'length':
                    row[uriLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            # headers columns
            elif field[0:12] == 'HTTP_Headers':
                if operation == 'exact':
                    row[headersExactIndices[headersExact]] = value
                    headersExact = headersExact + 1
                elif operation == 'reg_exp':
                    row[headersRegExpIndices[headersRegExp]] = value
                    headersRegExp = headersRegExp + 1
                elif operation == 'length':
                    row[headersLengthIndices[headersLength]] = value
                    headersLength = headersLength + 1
                else:
                    print "Error: invalid operation in matcher."
            # header names columns
            elif field[0:16] == 'any_header_names':
                if operation == 'exact':
                    row[anyHeaderNamesExactIndex] = value
                elif operation == 'reg_exp':
                    row[anyHeaderNamesRegExpIndex] = value
                elif operation == 'length':
                    row[anyHeaderNamesLengthIndex] = value
                else:
                    print "Error: invalid operation in matcher."
            else:
                print "Error: invalid field in matcher."
        
        table.append(row)
    
    # remove duplicate table rows
    row = len(table) - 1
    while row >= 0 :
        if table.count(table[row]) > 1:
            table.pop(row)
        row = row - 1
    
    
    ########################################################
    #                                                      #
    #   Sort the rows where the rows with a non-wildcard   #
    #   value in the first column are first, the rows      #
    #   with a non-wildcard value in the second column     #
    #   are second, etc., and where the rows are           #
    #   otherwise sorted by signature ID number.           #
    #                                                      #
    #   Convert the Python list table to a form where      #
    #   the columns are delimited by tabs and the rows     #
    #   are delimited by new lines.                        #
    #                                                      #
    #   Write the table to a file.                         #
    #                                                      #
    ########################################################
    
    sortedTable = ['\t'.join(columnNames)]  # sorted table with rows as strings
    
    # sort rows and convert rows to strings with the columns delimited by tabs
    rowDeleteList = []  # list of rows to be delete
    col = 0
    while col < numberOfColumns:
        # add rows with non-wildcard value in column to sorted table
        row = 0
        while row < len(table):
            if table[row][col] != 'N':
                sortedTable.append('\t'.join(table[row]))
                rowDeleteList.append(row)
            row = row + 1
        # delete rows in delete list
        while rowDeleteList:    
            table.pop(rowDeleteList.pop())
        col = col + 1
        
    # write table to file
    tableFile = open(outFile,'w')
    sortedTable = '\n'.join(sortedTable)
    tableFile.write(sortedTable + '\n')
    tableFile.close()
    
    
################################################################################
#                                                                              #
#                                     Main                                     #
#                                                                              #
################################################################################

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Error: invalid usage."
        print "Usage: make_table.py input_signature_file output_table_file"
    else:
        make_table(sys.argv[1], sys.argv[2])
