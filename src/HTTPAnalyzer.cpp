#include "NetShield.h"
#include "Global.h"
#include "HTTPAnalyzer.h"
#include "Util.h"

const UINT8_T HTTPAnalyzer::PROTO_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0
};

const UINT8_T HTTPAnalyzer::HOST_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   1,   0,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0
};

const UINT8_T HTTPAnalyzer::DIR_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   1,   0,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   0,   0,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   1,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   1,   0
};

const UINT8_T HTTPAnalyzer::VAR_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   1,   0,   0,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   0,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   0,   1,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0
};

const UINT8_T HTTPAnalyzer::VALUE_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   1,   0,   0,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   0,   0,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   0,   1,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0
};

const UINT8_T HTTPAnalyzer::FRAGMENT_CHAR[128] = 
{
// 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x1C 0x1D 0x1E 0x1F
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    
// ' '  '!'  '"'  '#'  '$'  '%'  '&'  '''  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
    0,   1,   0,   0,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   0,   1,
    
// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'  'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   1,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,

// 'p'  'q'  'r'  's'  't'  'u'  'v'  'w'  'x'  'y'  'z'  '{'  '|'  '}'  '~'  0x7F
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0
};

UINT8_T HTTPAnalyzer::PROTO[16];
UINT8_T HTTPAnalyzer::HOST[16];
UINT8_T HTTPAnalyzer::DIR[16];
UINT8_T HTTPAnalyzer::VAR[16];
UINT8_T HTTPAnalyzer::VALUE[16];
UINT8_T HTTPAnalyzer::FRAGMENT[16];
    
BOOL_T HTTPAnalyzer::isInitialized = FALSE;

INT32_T HTTPAnalyzer::initBitmap(UINT8_T * bitmap, const UINT8_T charSet[])
{
    for(int i = 0; i < 128; i++)
    {
        if(charSet[i] == 0)
        {
            bitmap[i >> 3] &= ~(1 << (i & 0x07));
        }
        else
        {
            bitmap[i >> 3] |= (1 << (i & 0x07));
        }
    }
    
    return 0;
}

UINT8_T * HTTPAnalyzer::ruleMatrix = NULL;
UINT32_T * HTTPAnalyzer::ruleGrpSID = NULL;
UINT32_T HTTPAnalyzer::ruleNum = 0;
UINT32_T HTTPAnalyzer::columnNum = 0;
    
TrieStruct<Rule> * HTTPAnalyzer::methodStringStruct = NULL;
DFAStruct<Rule> * HTTPAnalyzer::methodDFAStruct = NULL;
IntRangeStruct<Rule> * HTTPAnalyzer::methodLengthStruct = NULL;

TrieStruct<Rule> * HTTPAnalyzer::filenameStringStruct = NULL;
DFAStruct<Rule> * HTTPAnalyzer::filenameDFAStruct = NULL;
IntRangeStruct<Rule> * HTTPAnalyzer::filenameLengthStruct = NULL;

TrieStruct<Rule> * HTTPAnalyzer::anydirStringStruct = NULL;
DFAStruct<Rule> * HTTPAnalyzer::anydirDFAStruct = NULL;
IntRangeStruct<Rule> * HTTPAnalyzer::anydirLengthStruct = NULL;

vector< ArrayMatchingStruct<TrieStruct<Rule> *> > HTTPAnalyzer::dirStringStructVector;

TrieStruct<DictKeyData *> * HTTPAnalyzer::varnameStringStruct = NULL;
vector<TrieStruct<UINT32_T> *> * HTTPAnalyzer::varStringGroupStructVector = NULL;
vector<DFAStruct<UINT32_T> *> * HTTPAnalyzer::varRegexGroupStructVector = NULL;
vector<IntRangeStruct<UINT32_T> *> * HTTPAnalyzer::varLengthGroupStructVector = NULL;

TrieStruct<Rule> * HTTPAnalyzer::assignmentStringStruct = NULL;
DFAStruct<Rule> * HTTPAnalyzer::assignmentDFAStruct = NULL;
IntRangeStruct<Rule> * HTTPAnalyzer::assignmentLengthStruct = NULL;

TrieStruct<Rule> * HTTPAnalyzer::uriStringStruct = NULL;
DFAStruct<Rule> * HTTPAnalyzer::uriDFAStruct = NULL;
IntRangeStruct<Rule> * HTTPAnalyzer::uriLengthStruct = NULL;

TrieStruct<DictKeyData *> * HTTPAnalyzer::headernameStringStruct = NULL;
vector<TrieStruct<UINT32_T> *> * HTTPAnalyzer::headerStringGroupStructVector = NULL;
vector<DFAStruct<UINT32_T> *> * HTTPAnalyzer::headerRegexGroupStructVector = NULL;
vector<IntRangeStruct<UINT32_T> *> * HTTPAnalyzer::headerLengthGroupStructVector = NULL;

INT32_T HTTPAnalyzer::loadConfig(TiXmlDocument & config)
{
/***************************************************************************************************************/

    TiXmlHandle hConfig(&config);
    TiXmlHandle hRules = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature").FirstChild("Rules");
    loadRulesConfig(hRules);

/* Method ******************************************************************************************************/
    
    cout << "Compiling HTTP Method signature data structure...\n";
    
    TiXmlHandle hMethodString = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Method").FirstChild("String");
    if(hMethodString.ToElement() != NULL)
    {
        methodStringStruct = new TrieStruct<Rule>;
        verify(methodStringStruct);
        loadStringStruct(methodStringStruct, hMethodString);
    }
    
    TiXmlHandle hMethodRegex = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                      .FirstChild("Fields").FirstChild("Method").FirstChild("Regex");
    if(hMethodRegex.ToElement() != NULL)
    {
        methodDFAStruct = new DFAStruct<Rule>;
        verify(methodDFAStruct);
        loadDFAStruct(methodDFAStruct, hMethodRegex);
    }

    TiXmlHandle hMethodLength = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Method").FirstChild("Length");
    if(hMethodLength.ToElement() != NULL)
    {
        methodLengthStruct = new IntRangeStruct<Rule>;
        verify(methodLengthStruct);
        loadLengthStruct(methodLengthStruct, hMethodLength);
    }

/* Filename ******************************************************************************************************/
    
    cout << "Compiling HTTP Filename signature data structure...\n";
    
    TiXmlHandle hFilenameString = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Filename").FirstChild("String");
    if(hFilenameString.ToElement() != NULL)
    {
        filenameStringStruct = new TrieStruct<Rule>;
        verify(filenameStringStruct);
        loadStringStruct(filenameStringStruct, hFilenameString);
    }
        
    TiXmlHandle hFilenameRegex = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                      .FirstChild("Fields").FirstChild("Filename").FirstChild("Regex");
    if(hFilenameRegex.ToElement() != NULL)
    {
        filenameDFAStruct = new DFAStruct<Rule>;
        verify(filenameDFAStruct);
        loadDFAStruct(filenameDFAStruct, hFilenameRegex);
    }
    
    TiXmlHandle hFilenameLength = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Filename").FirstChild("Length");
    if(hFilenameLength.ToElement() != NULL)
    {
        filenameLengthStruct = new IntRangeStruct<Rule>;
        verify(filenameLengthStruct);
        loadLengthStruct(filenameLengthStruct, hFilenameLength);
    }

/* Anydir ******************************************************************************************************/
    
    cout << "Compiling HTTP Directory signature data structure...\n";
    
    TiXmlHandle hDirs = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                               .FirstChild("Fields").FirstChild("Dirs");
    TiXmlElement * pAnydir = hDirs.FirstChild("Dir").ToElement();
    while(pAnydir != NULL)
    {
        const char * index = pAnydir->Attribute("Index");
        verify(index);
        if(strcmp(index, "Any") == 0)
        {
            break;
        }
        else
        {
            pAnydir = pAnydir->NextSiblingElement("Dir");
        }
    }
    
    if(pAnydir != NULL)
    {
        TiXmlHandle hAnydirString(pAnydir->FirstChildElement("String"));
        anydirStringStruct = new TrieStruct<Rule>;
        verify(anydirStringStruct);
        loadStringStruct(anydirStringStruct, hAnydirString);
        
        TiXmlHandle hAnydirRegex(pAnydir->FirstChildElement("Regex"));
        anydirDFAStruct = new DFAStruct<Rule>;
        verify(anydirDFAStruct);
        loadDFAStruct(anydirDFAStruct, hAnydirRegex);
        
        TiXmlHandle hAnydirLength(pAnydir->FirstChildElement("Length"));
        anydirLengthStruct = new IntRangeStruct<Rule>;
        verify(anydirLengthStruct);
        loadLengthStruct(anydirLengthStruct, hAnydirLength);
    }

/* dirs *******************************************************************************************************/

    hDirs = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                               .FirstChild("Fields").FirstChild("Dirs");
    TiXmlElement * pDir = hDirs.FirstChild("Dir").ToElement();
    while(pDir != NULL)
    {
        const char * index = pDir->Attribute("Index");
        verify(index);
        if(strcmp(index, "Any") == 0)
        {
            pDir = pDir->NextSiblingElement("Dir");
            continue;
        }
        
        int idx = atoi(index);
        TrieStruct<Rule> * dirStringDFAStruct = new TrieStruct<Rule>;
        verify(dirStringDFAStruct);
        TiXmlHandle hDirString(pDir->FirstChildElement("String"));
        loadStringStruct(dirStringDFAStruct, hDirString);
        dirStringStructVector.push_back(ArrayMatchingStruct<TrieStruct<Rule> *>(idx, dirStringDFAStruct));
        
        pDir = pDir->NextSiblingElement("Dir");
    }

/* Variables ********************************************************************************************************/
    
    cout << "Compiling HTTP Variable signature data structure...\n";
    
    TiXmlHandle hVariableDict = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("VariableDict");
    if(hVariableDict.ToElement() != NULL)
    {
        loadVariablesConfig(hVariableDict);
    }
    
/* Assignment ******************************************************************************************************/
    
    cout << "Compiling HTTP Assignment signature data structure...\n";
    
    TiXmlHandle hAssignmentString = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Assignment").FirstChild("String");
    if(hAssignmentString.ToElement() != NULL)
    {
        assignmentStringStruct = new TrieStruct<Rule>;
        verify(assignmentStringStruct);
        loadStringStruct(assignmentStringStruct, hAssignmentString);
    }
    
    TiXmlHandle hAssignmentRegex = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                      .FirstChild("Fields").FirstChild("Assignment").FirstChild("Regex");
    if(hAssignmentRegex.ToElement() != NULL)
    {
        assignmentDFAStruct = new DFAStruct<Rule>;
        verify(assignmentDFAStruct);
        loadDFAStruct(assignmentDFAStruct, hAssignmentRegex);
    }
    
    TiXmlHandle hAssignmentLength = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Assignment").FirstChild("Length");
    if(hAssignmentLength.ToElement() != NULL)
    {
        assignmentLengthStruct = new IntRangeStruct<Rule>;
        verify(assignmentLengthStruct);
        loadLengthStruct(assignmentLengthStruct, hAssignmentLength);
    }

/* Uri ******************************************************************************************************/
    
    cout << "Compiling HTTP Uri signature data structure...\n";
    
    TiXmlHandle hUriString = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Uri").FirstChild("String");
    if(hUriString.ToElement() != NULL)
    {
        uriStringStruct = new TrieStruct<Rule>;
        verify(uriStringStruct);
        loadStringStruct(uriStringStruct, hUriString);
    }
    
    TiXmlHandle hUriRegex = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                      .FirstChild("Fields").FirstChild("Uri").FirstChild("Regex");
    if(hUriRegex.ToElement() != NULL)
    {
        uriDFAStruct = new DFAStruct<Rule>;
        verify(uriDFAStruct);
        loadDFAStruct(uriDFAStruct, hUriRegex);
    }
    
    TiXmlHandle hUriLength = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("Uri").FirstChild("Length");
    if(hUriLength.ToElement() != NULL)
    {
        uriLengthStruct = new IntRangeStruct<Rule>;
        verify(uriLengthStruct);
        loadLengthStruct(uriLengthStruct, hUriLength);
    }

/* Headers ********************************************************************************************************/
    
    cout << "Compiling HTTP Header signature data structure...\n";
    
    TiXmlHandle hHeaderDict = hConfig.FirstChild("NetShield").FirstChild("HTTP").FirstChild("Signature")
                                       .FirstChild("Fields").FirstChild("HeaderDict");
    if(hHeaderDict.ToElement() != NULL)
    {
        loadHeadersConfig(hHeaderDict);
    }

/***************************************************************************************************************/

    maxDFAStructTotalSize = currentDFAStructTotalSize;
    maxTrieStructTotalSize = currentTrieStructTotalSize;
    
	return 0;
}

INT32_T HTTPAnalyzer::loadRulesConfig(TiXmlHandle & hRules)
{
    TiXmlHandle hColumns = hRules.FirstChild("Columns");
    TiXmlElement * pColumns = hColumns.ToElement();
    verify(pColumns);
    
    if(pColumns->QueryIntAttribute("Num", (int *)(&(HTTPAnalyzer::columnNum))) != TIXML_SUCCESS)
    {
        fprintf(stderr, "Missing element \"Columns Num\"!\n");
        exit(0);
    }
    
    TiXmlHandle hBitmaps = hRules.FirstChild("Bitmaps");
    TiXmlElement * pBitmaps = hBitmaps.ToElement();
    verify(pBitmaps);

    if(pBitmaps->QueryIntAttribute("Num", (int *)(&(HTTPAnalyzer::ruleNum))) != TIXML_SUCCESS)
    {
        fprintf(stderr, "Missing attribute \"Bitmaps Num\"!\n");
        exit(0);
    }
    
    if(HTTPAnalyzer::ruleGrpSID != NULL)
    {
        delete []HTTPAnalyzer::ruleGrpSID;
    }
    HTTPAnalyzer::ruleGrpSID = new UINT32_T[HTTPAnalyzer::columnNum];
    
    if(HTTPAnalyzer::ruleMatrix != NULL)
    {
        delete []HTTPAnalyzer::ruleMatrix;
    }
    UINT32_T ruleBitmapBytes = 0;
    if(HTTPAnalyzer::columnNum % 8 == 0)
    {
        ruleBitmapBytes = HTTPAnalyzer::columnNum / 8;
    }
    else
    {
       ruleBitmapBytes = HTTPAnalyzer::columnNum / 8 + 1;
    }
    HTTPAnalyzer::ruleMatrix = new UINT8_T[HTTPAnalyzer::ruleNum * ruleBitmapBytes];
    memset(HTTPAnalyzer::ruleMatrix, 0, HTTPAnalyzer::ruleNum * ruleBitmapBytes);
    
    for(UINT32_T i = 0; i < HTTPAnalyzer::columnNum; i++)
    {
        TiXmlElement * pColumn = hColumns.Child("Column", i).ToElement();
        verify(pColumn);
        
        if(pColumn->QueryIntAttribute("StartRuleID", (int *)(&(HTTPAnalyzer::ruleGrpSID[i]))) != TIXML_SUCCESS)
        {
            fprintf(stderr, "Missing attribute \"Column StartRuleID\"!\n");
            exit(0);
        }
    }
    
    for(UINT32_T i = 0; i < HTTPAnalyzer::ruleNum; i++)
    {
        TiXmlElement * pBitmap = hBitmaps.Child("Bitmap", i).ToElement();
        verify(pBitmap);
        
        const char * bitmap = pBitmap->Attribute("Bmp");
        verify(bitmap);
        
        UINT8_T * pRuleBmp = &(HTTPAnalyzer::ruleMatrix[i * ruleBitmapBytes]);
        const char * p = bitmap + HTTPAnalyzer::columnNum - 1;
        UINT32_T bitIndex = 0;
        while(p >= bitmap)
        {
            UINT8_T value = 0;
            if(*p == '0')
            {
                value = ~(1 << bitIndex);
                *pRuleBmp &= value;
            }
            else
            {
                value = 1 << bitIndex;
                *pRuleBmp |= value;
            }
            
            bitIndex++;
            if(bitIndex >= 8)
            {
                bitIndex = bitIndex % 8;
                pRuleBmp++;
            }
            
            p--;
        }
    }
    
    return 0;
}

INT32_T HTTPAnalyzer::loadVariablesConfig(TiXmlHandle & hVariableDict)
{
/* Variable Name ------------------------------------------------------------------------------------ */

    varnameStringStruct = new TrieStruct<DictKeyData *>;
    verify(varnameStringStruct);
    
    TiXmlHandle hVariables = hVariableDict.FirstChild("Variables");
    TiXmlElement * pVariable = hVariables.FirstChild("Variable").ToElement();
    while(pVariable != NULL)
    {
        const char * pName = pVariable->Attribute("Name");
        verify(pName);
        
        const char * pStringGroup = pVariable->Attribute("StringGroup");
        const char * pRegexGroup = pVariable->Attribute("RegexGroup");
        const char * pLengthGroup = pVariable->Attribute("LengthGroup");
        
        DictKeyData * pDictKeyData = new DictKeyData;
        
        if(pStringGroup != NULL)
        {
            pDictKeyData->stringGroup = atoi(pStringGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pVariable).FirstChild("String").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->stringRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        if(pRegexGroup != NULL)
        {
            pDictKeyData->regexGroup = atoi(pRegexGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pVariable).FirstChild("Regex").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->regexRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        if(pLengthGroup != NULL)
        {
            pDictKeyData->lengthGroup = atoi(pLengthGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pVariable).FirstChild("Length").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->lengthRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        varnameStringStruct->add(pName, pDictKeyData);
        
        pVariable = pVariable->NextSiblingElement("Variable");
    }

/* Variable String Groups ------------------------------------------------------------------------------------ */

    varStringGroupStructVector = new vector<TrieStruct<UINT32_T> *>;
    verify(varStringGroupStructVector);
    
    TiXmlHandle hStringGroups = hVariableDict.FirstChild("StringGroups");
    TiXmlElement * pStringGroup = hStringGroups.FirstChild("StringGroup").ToElement();
    while(pStringGroup != NULL)
    {
        TrieStruct<UINT32_T> * trie = new TrieStruct<UINT32_T>;
        verify(trie);

        TiXmlElement * pExpression = pStringGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            
            trie->add(exp, count);

            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }
        
        varStringGroupStructVector->push_back(trie);
        
        pStringGroup = pStringGroup->NextSiblingElement("StringGroup");
    }
    
/* Variable Regex Groups ------------------------------------------------------------------------------------ */

    varRegexGroupStructVector = new vector<DFAStruct<UINT32_T> *>;
    verify(varRegexGroupStructVector);
    
    TiXmlHandle hRegexGroups = hVariableDict.FirstChild("RegexGroups");
    TiXmlElement * pRegexGroup = hRegexGroups.FirstChild("RegexGroup").ToElement();
    while(pRegexGroup != NULL)
    {
        DFAStruct<UINT32_T> * dfa = new DFAStruct<UINT32_T>;
        string combinedRegex;
        vector<DFAStruct<UINT32_T> *> subDFAVector;
        TiXmlElement * pExpression = pRegexGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            if(combinedRegex.length() != 0)
            {
                combinedRegex += "|";
            }
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            combinedRegex += exp;
            
            DFAStruct<UINT32_T> * subDFA = new DFAStruct<UINT32_T>;
            subDFA->compile(exp);
            
            subDFA->annotate(count, hasDollar(exp));
            subDFAVector.push_back(subDFA);
            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }
        
        dfa->compile(combinedRegex.c_str());
		// cout << *dfa;
        vector<DFAStruct<UINT32_T> *>::iterator it = subDFAVector.begin();
        while(it != subDFAVector.end())
        {
            dfa->annotate(**it);
            delete *it;
            it++;
        }
        
        varRegexGroupStructVector->push_back(dfa);
        
        pRegexGroup = pRegexGroup->NextSiblingElement("RegexGroup");
    }
    
/* Variable Length Groups ------------------------------------------------------------------------------------ */

    varLengthGroupStructVector = new vector<IntRangeStruct<UINT32_T> *>;
    verify(varLengthGroupStructVector);
    
    TiXmlHandle hLengthGroups = hVariableDict.FirstChild("LengthGroups");
    TiXmlElement * pLengthGroup = hLengthGroups.FirstChild("LengthGroup").ToElement();
    while(pLengthGroup != NULL)
    {
        IntRangeStruct<UINT32_T> * intRangeStruct = new IntRangeStruct<UINT32_T>;

        TiXmlElement * pExpression = pLengthGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            
            intRangeStruct->add(atoi(exp), count);
            
            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }

        varLengthGroupStructVector->push_back(intRangeStruct);
        
        pLengthGroup = pLengthGroup->NextSiblingElement("LengthGroup");
    }
    
    return 0;
}

INT32_T HTTPAnalyzer::loadHeadersConfig(TiXmlHandle & hHeaderDict)
{
/* Header Name ------------------------------------------------------------------------------------ */

    headernameStringStruct = new TrieStruct<DictKeyData *>;
    verify(headernameStringStruct);
    
    TiXmlHandle hHeaders = hHeaderDict.FirstChild("Headers");
    TiXmlElement * pHeader = hHeaders.FirstChild("Header").ToElement();
    while(pHeader != NULL)
    {
        const char * pName = pHeader->Attribute("Name");
        verify(pName);
        
        const char * pStringGroup = pHeader->Attribute("StringGroup");
        const char * pRegexGroup = pHeader->Attribute("RegexGroup");
        const char * pLengthGroup = pHeader->Attribute("LengthGroup");
        
        DictKeyData * pDictKeyData = new DictKeyData;
        
        if(pStringGroup != NULL)
        {
            pDictKeyData->stringGroup = atoi(pStringGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pHeader).FirstChild("String").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->stringRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        if(pRegexGroup != NULL)
        {
            pDictKeyData->regexGroup = atoi(pRegexGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pHeader).FirstChild("Regex").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->regexRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        if(pLengthGroup != NULL)
        {
            pDictKeyData->lengthGroup = atoi(pLengthGroup);
            
            TiXmlElement * pRuleGroup = TiXmlHandle(pHeader).FirstChild("Length").FirstChild("RuleGroup").ToElement();
            while(pRuleGroup != NULL)
            {
                vector<Rule> * ruleVector = new vector<Rule>;
                verify(ruleVector);
                
                TiXmlElement * pRule = TiXmlHandle(pRuleGroup).FirstChild("Rule").ToElement();
                while(pRule != NULL)
                {
                    INT32_T ColumnID, RuleID;
                    if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
                    }
                    
                    if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
                    {
                        fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
                    }
                    
                    ruleVector->push_back(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
                    
                    pRule = pRule->NextSiblingElement("Rule");
                }
                
                pDictKeyData->lengthRuleVector.push_back(ruleVector);
                
                pRuleGroup = pRuleGroup->NextSiblingElement("RuleGroup");
            }
        }
        
        headernameStringStruct->add(pName, pDictKeyData);
        
        pHeader = pHeader->NextSiblingElement("Header");
    }

/* Header String Groups ------------------------------------------------------------------------------------ */

    headerStringGroupStructVector = new vector<TrieStruct<UINT32_T> *>;
    verify(headerStringGroupStructVector);
    
    TiXmlHandle hStringGroups = hHeaderDict.FirstChild("StringGroups");
    TiXmlElement * pStringGroup = hStringGroups.FirstChild("StringGroup").ToElement();
    while(pStringGroup != NULL)
    {
        TrieStruct<UINT32_T> * trie = new TrieStruct<UINT32_T>;
        verify(trie);

        TiXmlElement * pExpression = pStringGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            
            trie->add(exp, count);

            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }
        
        headerStringGroupStructVector->push_back(trie);
        
        pStringGroup = pStringGroup->NextSiblingElement("StringGroup");
    }
    
/* Header Regex Groups ------------------------------------------------------------------------------------ */

    headerRegexGroupStructVector = new vector<DFAStruct<UINT32_T> *>;
    verify(headerRegexGroupStructVector);
    
    TiXmlHandle hRegexGroups = hHeaderDict.FirstChild("RegexGroups");
    TiXmlElement * pRegexGroup = hRegexGroups.FirstChild("RegexGroup").ToElement();
    while(pRegexGroup != NULL)
    {
        DFAStruct<UINT32_T> * dfa = new DFAStruct<UINT32_T>;
        string combinedRegex;
        vector<DFAStruct<UINT32_T> *> subDFAVector;
        TiXmlElement * pExpression = pRegexGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            if(combinedRegex.length() != 0)
            {
                combinedRegex += "|";
            }
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            combinedRegex += exp;
            
            DFAStruct<UINT32_T> * subDFA = new DFAStruct<UINT32_T>;
            subDFA->compile(exp);
            
            subDFA->annotate(count, hasDollar(exp));
            subDFAVector.push_back(subDFA);
            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }
        
        dfa->compile(combinedRegex.c_str());
		// cout << *dfa;
        vector<DFAStruct<UINT32_T> *>::iterator it = subDFAVector.begin();
        while(it != subDFAVector.end())
        {
            dfa->annotate(**it);
            delete *it;
            it++;
        }
        
        headerRegexGroupStructVector->push_back(dfa);
        
        pRegexGroup = pRegexGroup->NextSiblingElement("RegexGroup");
    }
    
/* Header Length Groups ------------------------------------------------------------------------------------ */

    headerLengthGroupStructVector = new vector<IntRangeStruct<UINT32_T> *>;
    verify(headerLengthGroupStructVector);
    
    TiXmlHandle hLengthGroups = hHeaderDict.FirstChild("LengthGroups");
    TiXmlElement * pLengthGroup = hLengthGroups.FirstChild("LengthGroup").ToElement();
    while(pLengthGroup != NULL)
    {
        IntRangeStruct<UINT32_T> * intRangeStruct = new IntRangeStruct<UINT32_T>;

        TiXmlElement * pExpression = pLengthGroup->FirstChildElement("Expression");
        UINT32_T count = 0;
        while(pExpression != NULL)
        {
            const char * exp = pExpression->Attribute("Exp");
            verify(exp);
            
            intRangeStruct->add(atoi(exp), count);
            
            count++;
            
            pExpression = pExpression->NextSiblingElement("Expression");
        }

        headerLengthGroupStructVector->push_back(intRangeStruct);
        
        pLengthGroup = pLengthGroup->NextSiblingElement("LengthGroup");
    }
    
    return 0;
}

INT32_T HTTPAnalyzer::init()
{
    if(HTTPAnalyzer::isInitialized == TRUE)
    {
        return 0;
    }
    
    HTTPAnalyzer::isInitialized = TRUE;
    
    initBitmap(PROTO, PROTO_CHAR);
    initBitmap(HOST, HOST_CHAR);
    initBitmap(DIR, DIR_CHAR);
    initBitmap(VAR, VAR_CHAR);
    initBitmap(VALUE, VALUE_CHAR);
    initBitmap(FRAGMENT, FRAGMENT_CHAR);
    
    if(parseOnly->count == 0 && seqMatch->count == 0)
    {
        loadConfig(config);
    }
    
    return 0;
}

UINT32_T HTTPAnalyzer::instanceNum = 0;
FILE * HTTPAnalyzer::logFile = NULL;

INT32_T HTTPAnalyzer::run()
{
    // DEBUG_WRAP(DebugMessage("HTTPAnalyzer: 0x%.8X, run()\n", this););
    verify(matched == false);
    
    if(this->isPac == true)
    {
        if(parser == NULL)
        {
            parser = new FastParser(new SimpleFlowBuffer(), NULL, this);
            verify(parser);
        }
        parser->Reset();
    }
    
    while(1)
    {
        buffer->setRecallPoint();
		
		Connection * conn = flow->getConnection();
        
        if(logFile != NULL)
        {
            if(reassembled->count == 1)
            {
                fprintf(logFile, "Connection: %u\n\n", conn->tuple5.origIP);
            }
            else
            {
                fprintf(logFile, "Connection: %s\n\n", conn->tuple5.toString().c_str());
            }
        }
        
        if(this->isPac == true)
        {
            parser->is_orig = (dir == ORIG_TO_RESP) ? true : false;

    		UINT8_T * dataBegin = NULL;
    		UINT32_T dataLength = 0;
    		buffer->readAll(&dataBegin, &dataLength);
    		UINT8_T * dataEnd = dataBegin + dataLength;
    		
    		parser->flowbuffer->NewData((const_byteptr)dataBegin, (const_byteptr)dataEnd);
            parser->FuncParsingFlow();
        }
        else
        {
            resetState();
            
            INT32_T length = parseHttpPdu(buffer, dir);
            
            validPduNum += 1;
            
            UINT8_T * recallPoint = buffer->getRecallPoint();
            
            if(recallPoint != NULL && logFile != NULL)
            {
                logFields();
                
                fprintf(logFile, "HTTP pdu:\n");
                fwrite(recallPoint, sizeof(UINT8_T), length, logFile);
    
                fprintf(logFile, "\n");
            }
            
            if(parseOnly->count == 0)
            {
                if(seqMatch->count == 0)
                {
                    incrementalMatch();
                    performCSAlgo();
                }
                else
                {
                    HTTPAnalyzerSeqMatch(methodField, filenameField,
                              dirFieldVector, varNameVector, 
                              varValueVector, headerNameVector,
                              headerValueVector, assignmentField, uriField);
                }
            }
        }
        
        // DEBUG_WRAP(DebugMessage("HTTPAnalyzer: 0x%.8X, PDU length = %d\n", this, length););
    }

	return 0;
}
