/*************************************
This is the header file for field table class
**************************************/

#ifndef FIELD_TABLE_H
#define FIELD_TABLE_H

#include <vector>
#include <iostream>
#include <fstream>
#include "pac_output.h"
#include "pac_type.h"
#include "pac_expr.h"
#include "pac_id.h"
#include "pac_case.h"
#include "pac_record.h"
#include "pac_paramtype.h"
#include "pac_typedecl.h"
#include "pac_array.h"
#include "pac_number.h"
#include "pac_strtype.h"
#include "pac_cstr.h"
#include "pac_attr.h"
#include "pac_regex.h"
#include "pac_param.h"
#include "pac_exttype.h"
#include "pac_analyzer.h"
#include "pac_flow.h"
#include "pac_embedded.h"
#include "pac_btype.h"
#include "pac_func.h"
#include "assert.h"

using namespace std;

class FieldEntry;
class FieldTable;
string ReComputeExpr(Expr* expr, FieldTable* fieldtable);

class Metadata	{
public:
	Metadata()	{
		type_ = NULL;
		id_ = NULL;
		field_ = NULL;
		}

	Metadata(const Metadata& param)	{
		this->type_ = param.type_;
		this->id_ = param.id_;
		this->field_ = param.field_;
		}

	~Metadata()	{
		}

	void DebugOutput(ofstream& fout);

	Type* type_;	//the "Type" structure corresponding to the field
	const ID* id_;		//the "ID" structure corresponding to the field
	Field* field_;	//the pointer to the "Field" strucure corresponding to the field. For root declaration, this field is "NULL"
};
	
class FieldLength	{
public:
	enum LengthType	{ CONSTNUMBER, ONELINE, RESTOFDATA, RESTOFFLOW, UNTIL, REGEXMATCHING, EXPRESSION};
	
	FieldLength(LengthType theType = CONSTNUMBER)	{
		lengthType_ = theType;
		}

	FieldLength(const FieldLength& param)	{
		this->lengthType_ = param.lengthType_;
		}

	~FieldLength()	{
		}

	
	LengthType lengthType_;
};

class ConstFieldLength	:public FieldLength	{
public:
	ConstFieldLength(int length = 0, LengthType lengthtype = CONSTNUMBER)
		: FieldLength(lengthtype)	{
		//lengthType_ = lengthtype;
		length_ = length;
		}

	ConstFieldLength(const ConstFieldLength& param)	
		: FieldLength(CONSTNUMBER)	{
		this->length_ = param.length_;
		this->lengthType_ = param.lengthType_;
		}

	~ConstFieldLength()	{
		}

	int length_;
};

class RegExFieldLength :public FieldLength {
public:
    RegExFieldLength(RegEx* regex = NULL, LengthType lengthType_ = REGEXMATCHING)
        : FieldLength(lengthType_) {
            regex_ = regex;
        }
    RegExFieldLength(const RegExFieldLength& param) 
		: FieldLength(param.lengthType_)	{
        this->regex_ = param.regex_;
    }
    ~RegExFieldLength() {
    }
    RegEx* regex_; // Are we using char pointers or strings?
};

class ExpressionFieldLength: public FieldLength{
public:
	ExpressionFieldLength(Expr* argexpr = NULL, LengthType lengthType_ = EXPRESSION)
		:FieldLength(lengthType_)	{
		expr_ = argexpr;
	}
	ExpressionFieldLength(const ExpressionFieldLength& param)
		:FieldLength(param.lengthType_)	{
		this->expr_ = param.expr_;
	}
	~ExpressionFieldLength()	{
		}

	Expr* expr_;
};
class NextField	{
public:
	enum NextFieldType	{ CONSEQUENT, BRANCH, NONE};
	
	NextField(NextFieldType theType = NONE, NextField* parentNextField_ = NULL)	{
		nextFieldType_ = theType;
		parentNextField = parentNextField_;
		}

	NextField(const NextField& param)	{
		this->nextFieldType_ = param.nextFieldType_;
		}

	virtual ~NextField()	{
		}

	virtual NextField* Clone()	//to return a pointer to a NextField class that is identical to *this
	{
		NextField* replica = new NextField(this->nextFieldType_, this->parentNextField);
		return replica;
	}

	//find out the next field structure, which has the parameter as next field
	virtual NextField* FindNextField(FieldEntry* nextField)
		{
			return NULL;
		}

	//update preceder attribute for all possible next fields
	virtual int UpdatePreceder(FieldEntry* complexField, vector<FieldEntry*> expandedcasefield)	{return -1;}
	
	//gen code for next field function
	virtual int GenCode(Output* out_h, FieldTable* fieldtable, int cur_field_num)	{	
		if (nextFieldType_ == NONE)	{
			//out_h->println("parserentity->tablepointer = -1;");
			out_h->println("tablepointer = -1;");
			out_h->println("goto parse_PDU_complete;") ;
		}
		return 0;	
	}
	
	virtual void DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable)	{
		fout <<"NONE"<<endl;
	}
	NextFieldType nextFieldType_;

	NextField* parentNextField;	//points to the NextField structure that contains the current next field structure
};

class ConsequentNextField: public NextField{
public:
	ConsequentNextField(FieldEntry* nextEntry = NULL, NextFieldType nextfieldtype_ = NONE, NextField* parentNextField = NULL)
		: NextField(nextfieldtype_, parentNextField)	{
		assert(nextfieldtype_ != BRANCH);
		nextField_ = nextEntry;
		}

	ConsequentNextField(const ConsequentNextField& param)	
		: NextField(param.nextFieldType_, param.parentNextField) {
		this->nextField_ = param.nextField_;
		nextFieldType_ = param.nextFieldType_;
		parentNextField = param.parentNextField;
		}

	~ConsequentNextField()		{
		}

	virtual NextField* Clone()	//to return a pointer to a NextField class that is identical to *this
	{
		ConsequentNextField* replica = new ConsequentNextField(nextField_, nextFieldType_, parentNextField);
		return replica;
	}

	//find out the next field structure, which has the parameter as next field
	virtual NextField* FindNextField(FieldEntry* nextField)
	{
		if (nextField_ == nextField)	{
			return this;
			}
		else	{
			return NULL;
			}
	}

	//update preceder attribute for all possible next fields
	virtual int UpdatePreceder(FieldEntry* complexField, vector<FieldEntry*> expandedcasefield);
	
	//gen code for next field function
	virtual int GenCode(Output* out_h, FieldTable* fieldtable, int cur_field_num);
		
	virtual void DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable);
	FieldEntry* nextField_;
};
	
class BranchNextField: public NextField{
public:
	BranchNextField(Expr* param_index = NULL, NextField* parentNextField = NULL)
		: NextField(BRANCH, parentNextField) {
		index_expr_ = param_index;
		}

	BranchNextField(const BranchNextField& param)	
		: NextField(param.nextFieldType_, param.parentNextField)	{
		this->index_expr_ = param.index_expr_;
		this->env_ = param.env_;
		this->index_for_case_ = param.index_for_case_;
		this->branchNextField_ = param.branchNextField_;
		}

	~BranchNextField()	{
		}

	virtual NextField* Clone()	//to return a pointer to a NextField class that is identical to *this
	{
		assert(index_for_case_.size() == branchNextField_.size());
		BranchNextField* replica = new BranchNextField(this->index_expr_, parentNextField);
		replica->index_for_case_ = this->index_for_case_;
		replica->env_ = this->env_;
		for (vector<NextField*>::iterator it = this->branchNextField_.begin() ; it < this->branchNextField_.end() ; it++)
		{
			//(*it)->parentNextField = this;
			assert((*it)->parentNextField);
			NextField* temp = (*it)->parentNextField;
			(*it)->parentNextField = replica;
			replica->branchNextField_.push_back((*it)->Clone());
			(*it)->parentNextField = temp;
		}

		return replica;
	}

	//find out the next field structure, which has the parameter as next field
	virtual NextField* FindNextField(FieldEntry* nextField)
	{
		NextField* temp;
		for (vector<NextField*>::iterator it = branchNextField_.begin(); it < branchNextField_.end() ; it++)
		{
			temp = (*it)->FindNextField(nextField);
			if (temp)	{
				return temp;
			}
		}
		return NULL;
	}

	//update preceder attribute for all possible next fields
	virtual int UpdatePreceder(FieldEntry* complexField, vector<FieldEntry*> expandedcasefield);
	
	//gen code for next field function
	virtual int GenCode(Output* out_h, FieldTable* fieldtable, int cur_field_num);
		
	virtual void DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable);
	Expr* index_expr_;	//corresponding the to index_ expr in case type.
	Env* env_;	//env for the type that contains this branch case
	vector<ExprList*> index_for_case_;	//each element corresponds to the index_ variable in a case field
	vector<NextField*> branchNextField_;	//each element points to the next field in one case. These two vectors should have the same size. 
};

class ContextUpdateAfterParse	{
public:
	ContextUpdateAfterParse(ID* varid_ = NULL, Expr* updateexpr_ = NULL)	{
		varid = varid_;
		updateexpr = updateexpr_;
		}

	ContextUpdateAfterParse(const ContextUpdateAfterParse& param)	{
		this->varid = param.varid;
		this->updateexpr = param.updateexpr;
		}

	~ContextUpdateAfterParse()	{
		}

	ContextUpdateAfterParse* Clone()	{
		return new ContextUpdateAfterParse(varid, updateexpr);
		}
	
	ID* varid;
	Expr* updateexpr;
};

class FieldEntry	{
public:
	enum FieldType  { NOT_USED, TYPE1, TYPE2 };
	
	FieldEntry()	{
		nextField_ = NULL;
		fieldType_ = TYPE1;
		oneline_ = false;
		oneline_transfered_ = false;
		oneline_cleanup_ =false;
		}

	FieldEntry(const FieldEntry& param)	{
		this->metadata_ = param.metadata_;
		this->fieldType_ = param.fieldType_;
		this->fieldLength_ = param.fieldLength_;
		this->garbageLength_ = param.garbageLength_;
		this->nextField_ = param.nextField_;
		this->preceders = param.preceders;
		this->contextupdateafterparse = param.contextupdateafterparse;
		this->oneline_ = param.oneline_;
		this->oneline_transfered_ = param.oneline_transfered_;
		this->oneline_cleanup_ = param.oneline_cleanup_;
		}
	
	~FieldEntry()	{
		}
	
	void DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable);

	vector<FieldEntry*> preceders;	//all FieldEntries that possibly points to this entry as next field
	//here the field entry does not include value. because value field can not be determined during table generation
	Metadata metadata_;
    
	FieldType fieldType_;
	vector<FieldLength*> fieldLength_;
	vector<FieldLength*> garbageLength_;
	NextField* nextField_;
	vector<ContextUpdateAfterParse*> contextupdateafterparse;
	bool oneline_;
	bool oneline_transfered_;
	bool oneline_cleanup_;
};

class FieldTable	{
public:
	FieldTable()	{
		debugout.open("debugout", ios::out);
		}
	
	FieldTable(const FieldTable& FieldTable_)	{
		this->startFieldPointer = FieldTable_.startFieldPointer;
		/*this->debugout = FieldTable_.debugout;*/
		this->fieldTable_ = FieldTable_.fieldTable_;
		this->globalvarname = FieldTable_.globalvarname;
		this->globalvartype = FieldTable_.globalvartype;
		}
	
	~FieldTable()	{
		debugout.close();
		}
	
	int Push_back(FieldEntry* newEntry)	{
		fieldTable_.push_back(newEntry);
		return 0;
		}

	int GenStartField(Type* type_, const ID* id_);	//Add the first/starting field(root node of parsing tree) into the field table

	int AddParamToGlobalContext(Type* typeComplexField);	//add param into global context

	int AddLetFieldToGlobalContext(Type* typeComplexField);		//add let field into global context
				
	int GenOtherFields();	//add the other fields in the protocol into the field table

	vector<FieldEntry*>::iterator FindComplexField();	//find a complex field in the field table

	int ExpandCaseType(FieldEntry* complexField);	//expand a case type complex field

	int ExpandRecordType(FieldEntry* complexField);	//expand record type complex field

	int ExpandArrayType(FieldEntry* complexField);		//expand array type complex field

	void ContextUpdateRecordLetField(Type* typeComplexField);	//updating context in record let field

	void ContextUpdateRecordParameter(RecordType* recordtypeComplexField);	//update context in record type, parameter passing

	void ContextUpdateCaseParameter(CaseType* casetypeComplexField);	//update context in case type, parameter passing
	
	//the following function fill in the table those attributes that can be determined during table generation
	//additional parameters are needed
	int GenTypeColumn();

	int GenLengthColumn();

	int GenGarbageLengthColumn();

	//After phase 1 table is generated, compress it to get phase 2 table
	int CompressTable();
	
	//check if there is inconsistency in the fully built field table
	//This checking is a necessary, but not sufficient condition for the field table to be correct
	//return true if the table is consistent. return false otherwise
	bool CheckConsistency();
	
	//generate code for fast parser, given the fully built field table
	int GenCode(Output* out_h, Output* out_cc);

	int GenCodeForRegexMatcherDeclaration(Output* out_cc);	//declare regex matcher in .cc file

	int GenCodeForBasicDefinition(Output* out_h);	//gen code for basic definition
	
	int GenCodeForClassDeclaration(Output* out_h, Output* out_cc);	//gen code for fast parser class declaration

	int GenCodeForFuncInSpec(Output* out_h, Output* out_cc);

	int GenCodeForClassImplementation(Output* out_cc);	//gen code for class implementation

	int GenCodeForContextDeclaration(Output* out_h);	//gen code for context variable declaration
	
	int GenCodeForFieldTable(Output* out_h, Output* out_cc);

	int GenCodeForAllInOneParsing(Output* out_h, Output* out_cc);

	int GenCodeForParsingField(Output* out_h, vector<FieldEntry*>::iterator it);

	int GenCodeForFieldName(Output* out_h, Output* out_cc, vector<FieldEntry*>::iterator it);	//gen function to return the name of field

	int GenCodeInitMetadata(Output* out_h, Output* out_cc);	//gen function to initial metadata column

	int GenCodeInitFieldType(Output* out_h, Output* out_cc);	//gen function to initial FieldType column

	int GenCodeInitFuncNextField(Output* out_h, Output* out_cc);

	void DebugOutput();	
	void DebugCheckGlobalVar();
	void DebugOutputContextUpdate();
//Private:
	vector<ID*> globalvarname;	//the global variable table, which is the globally accessible context, name part
	vector<Type*> globalvartype;	//the global varaible table, which is the globally accessible context, type part
	vector<FieldEntry*> fieldTable_;
	FieldEntry* startFieldPointer;		//the starting field of the table
	ofstream debugout;
};






#endif
