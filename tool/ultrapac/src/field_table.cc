/*******************************
created by Hongyu
				on Feb. 15
*******************************/

#include "field_table.h"

extern Output* out_temp;

static const char* expr_fmt[] = 
{
#	define EXPR_DEF(type, num_op, fmt) fmt,
#	include "pac_expr.def"
#	undef EXPR_DEF
};

static size_t basic_type_size[] = 
{
#	define TYPE_DEF(name, pactype, ctype, size)	size,
#	include "pac_type.def"
#	undef TYPE_DEF
};

static const char* basic_ctype_name[] = {
#	define TYPE_DEF(name, pactype, ctype, size)	ctype,
#	include "pac_type.def"
#	undef TYPE_DEF
	0,
};

string ReComputeExprList(ExprList* list, FieldTable* fieldtable)
{
	bool first = true;
	string str;
	foreach(i, ExprList, list)
		{
		Expr *expr = *i;
		if ( first )
			first = false;
		else
			str += ", ";
		str += ReComputeExpr(expr, fieldtable);
		}
	return str;
}

string ReComputeExpr(Expr* expr, FieldTable* fieldtable)
{
	if (expr->expr_type() == Expr::EXPR_ID) {
		//expr->orig_ = fmt("parserentity->%s", expr->id_->Name());
		/*if (expr->id()->name=="rr_type")	{
			cout <<"find the expr of rr_type"<<endl;
			}*/

		if (expr->id()->name == "$input")	//the special case that the expression comes from "$input"
		{
			//expr->orig_ = "parserentity->flowbuffer";
			expr->orig_ = "flowbuffer";
			return expr->orig_;
		}
		else if (expr->id()->name == "$flow")	//the special case that the expression comes from "flow"
		{
			//expr->orig_ = "parserentity";
			expr->orig_ ="this";
			return expr->orig_;
		}

		vector<ID*>::iterator idit;
		for (idit = fieldtable->globalvarname.begin() ; idit < fieldtable->globalvarname.end() ; idit++)
		{
			if ((*idit)->name == expr->id()->name)	{
				break;
			}
		}

		
		if (idit == fieldtable->globalvarname.end())	{	//if the id is not one of the global variables
			vector<FieldEntry*>::iterator entryit;
			for (entryit = fieldtable->fieldTable_.begin() ; entryit < fieldtable->fieldTable_.end() ; entryit++)	{
				//check if the id is one of the field entries
				assert ((*entryit)->metadata_.id_);
				if (expr->id()->name == (*entryit)->metadata_.id_->name)	{
					break;
					}
			}
			if (entryit == fieldtable->fieldTable_.end())	{	//the id is not a field entry
				expr->orig_ = fmt("%s", expr->id_->Name());
			}
			else	{	//for id that is one of the field entries, change the name to "parserentity" instead
				//expr->orig_ = fmt("parserentity");
				expr->orig_ = fmt("this");
			}
		}
		else	{	//if the id is one of the global variables
			//expr->orig_ = fmt("parserentity->%s", expr->id_->Name());
			expr->orig_ = fmt("%s", expr->id_->Name());
		}

	}
	else if (expr->expr_type() == Expr::EXPR_NUM)	{
		//expr->orig_ = fmt("((int) %s)", expr->num_->Str());
		expr->orig_ = fmt("%s", expr->num_->Str());
	}
	else if (expr->expr_type() == Expr::EXPR_CSTR)	{
		expr->orig_ = expr->cstr_->str();
	}
	else if (expr->expr_type() == Expr::EXPR_REGEX)	{
		expr->orig_ = fmt("/%s/", expr->regex_->str().c_str());
	}
	else if (expr->num_operands_ == 1)	{
		expr->orig_ = fmt(expr_fmt[expr->expr_type_], ReComputeExpr(expr->operand_[0], fieldtable).c_str());
	}
	else if (expr->num_operands_ == 2)	{
		expr->orig_ = fmt(expr_fmt[expr->expr_type_], ReComputeExpr(expr->operand_[0], fieldtable).c_str(), ReComputeExpr(expr->operand_[1], fieldtable).c_str());
	}
	else if (expr->num_operands_ == 3)	{
		expr->orig_ = fmt(expr_fmt[expr->expr_type_], ReComputeExpr(expr->operand_[0], fieldtable).c_str(), ReComputeExpr(expr->operand_[1], fieldtable).c_str(), ReComputeExpr(expr->operand_[2], fieldtable).c_str());
	}
	else if (expr->num_operands_ == -1 && expr->expr_type() == Expr::EXPR_CALLARGS)	{
		expr->orig_ = ReComputeExprList(expr->args_, fieldtable);
	}
	else {
		cout <<"unexpected expr type, exit..."<<endl;
		exit(1);
	}

	return expr->orig_;
		
}

	
void Metadata::DebugOutput(ofstream& fout)
{
	if (field_)	{
		fout <<"the field is "<<field_->id_->Name()<<endl;
	}
	if (type_)	{
		if (type_->tot() == Type::PARAMETERIZED)	{
			ParameterizedType* paramType = static_cast<ParameterizedType*>(type_);
			fout <<"the type is "<<paramType->type_id_->Name()<<endl;
		}
		/*else	{
			fout <<"have not dealt with this case"<<endl;
		}*/
	}
	if (id_)	{
		fout <<"the id is "<<id_->Name()<<endl;
	}
}

int ConsequentNextField::UpdatePreceder(FieldEntry* complexField, vector<FieldEntry*> expandedcasefield)
{
	vector<FieldEntry*>::iterator it;
	assert(nextField_);
	for (it = nextField_->preceders.begin() ; it<nextField_->preceders.end() ; it++)	{
		if ((*it) == NULL)	{
			cout <<"*it == NULL"<<endl;
			}
		assert(*it);
		if ((*it) == complexField)	{
			break;
			}
	}
	//assert(it < nextField_->preceders.end());
	if (it < nextField_->preceders.end())	{
		unsigned int index = it - nextField_->preceders.begin();

		nextField_->preceders.erase(it);

		it = nextField_->preceders.begin()+index;

		nextField_->preceders.insert(it, expandedcasefield.begin(), expandedcasefield.end());
	}

	return 0;
}

void ConsequentNextField::DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable)
{
	vector<FieldEntry*>::iterator tempi;
	for (tempi = fieldtable.begin() ; tempi < fieldtable.end() ; tempi++)	{
		if ((*tempi) == nextField_)	{
			break;
		}
	}
	if (tempi == fieldtable.end())	{
		fout <<"error, next field not found"<<endl;
	}
	else	{
		fout <<"the "<<tempi - fieldtable.begin()<<"th field entry"<<endl;
	}
}

int BranchNextField::UpdatePreceder(FieldEntry* complexField, vector<FieldEntry*> expandedcasefield)
{
	for (vector<NextField*>::iterator it = branchNextField_.begin() ; it < branchNextField_.end() ; it++)
	{
		(*it)->UpdatePreceder(complexField, expandedcasefield);
	}

	return 0;
}

int ConsequentNextField::GenCode(Output* out_h, FieldTable* fieldtable, int cur_field_num)	{	//return the next field for consequent next field
		unsigned int index = 0;
		while (fieldtable->fieldTable_[index] != nextField_)	{
			index++;
			assert(index < fieldtable->fieldTable_.size());
		}
		//out_h->println("parserentity->tablepointer =  %d;", index);
		out_h->println("tablepointer = %d;", index);
		if (index != cur_field_num+1)	{
			out_h->println("goto parse_field_%u;", index);
		}

		return 0;
	}

void BranchNextField::DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable)
{
	for (vector<NextField*>::iterator tempi = branchNextField_.begin() ; tempi < branchNextField_.end() ; tempi++)	{
		fout <<"Branch: ";
		(*tempi)->DebugOutput(fout, fieldtable);
	}
}

int BranchNextField::GenCode(Output* out_h, FieldTable* fieldtable, int cur_field_num)	{	//return the next field for branch next field
		//cout <<"enter the gencode for branch next field"<<endl;
		assert(index_expr_);
		ReComputeExpr(index_expr_, fieldtable);

		out_h->println("switch (%s)	{", index_expr_->orig());
		out_h->inc_indent();
		
		assert(index_for_case_.size() == branchNextField_.size());

		vector<ExprList*>::iterator it1 = index_for_case_.begin();	//the first case
		vector<NextField*>::iterator it2 = branchNextField_.begin();
		ExprList::iterator subit;

		bool defaultcase = false;
		for (;it1 < index_for_case_.end() ; it1++)	{	//output all cases
			if (*it1)	{
				for (subit = (*it1)->begin(); subit<(*it1)->end(); subit++)	{
					assert((*subit)!=NULL);
					out_h->println("case %s:", ReComputeExpr((*subit), fieldtable).c_str());
				}
			}
			else	{
				assert(!defaultcase);
				out_h->println("default:");
				defaultcase = true;
			}
			
			out_h->inc_indent();
	
			assert((*it2) != NULL);
			(*it2)->GenCode(out_h, fieldtable, cur_field_num);	//recursively generate code
			out_h->println("break;");

			out_h->dec_indent();

			it2++;
		}

		if (!defaultcase)	{
			out_h->println("default:");
			out_h->inc_indent();
			out_h->println("//cout <<\"unexpected case, exiting\"<<endl;");
			//out_h->println("parserentity->tablepointer = -2;");
			out_h->println("status = BAD;");
			out_h->println("return %d;	//return a positive number mean parsing error in this field", cur_field_num);
			out_h->println("break;");
			out_h->dec_indent();
		}

		out_h->dec_indent();
		out_h->println("}");

	//cout <<"leave the gencode for branch next field"<<endl;
		return 0;
		
	}

#if 0	
int BranchNextField::GenCode(Output* out_h, FieldTable* fieldtable)	{	//return the next field for branch next field
		//cout <<"enter the gencode for branch next field"<<endl;
		assert(index_expr_);
		ReComputeExpr(index_expr_, fieldtable);
		/*if (index_expr_->num_operands_ >= 1)	{
			index_expr_->GenStrFromFormat();
		}*/
		assert(index_for_case_.size() == branchNextField_.size());

		vector<ExprList*>::iterator it1 = index_for_case_.begin();	//the first case
		vector<NextField*>::iterator it2 = branchNextField_.begin();
		ExprList::iterator subit;

		bool defaultcase = false;
		for (;it1 < index_for_case_.end() ; it1++)	{	//output all cases
			if (it1> index_for_case_.begin())	{
				for (int temp = 0; temp < out_h->indent(); temp++)	{
					out_h->print("\t");
				}
				out_h->print("else ");
			}

			if (*it1)	{
				subit = (*it1)->begin();
				assert((*subit) != NULL);
				/*if ((*subit)->num_operands_>=1)	{
					(*subit)->GenStrFromFormat();
				}*/
				if (it1 == index_for_case_.begin())	{
					for (int temp = 0; temp < out_h->indent() ; temp++)	{
						out_h->print("\t");
					}
				}
				out_h->print("if (((%s) == (%s)) ", index_expr_->orig(),  ReComputeExpr((*subit), fieldtable).c_str());
				//out_h->print("if (((%s) == (%s)) ", index_expr_->EvalExpr(out_temp, env_), (*subit)->EvalExpr(out_temp, env_));
				/*if ((*subit)->expr_type_ == Expr::EXPR_NUM)	{
					out_h->print("if (((%s) == (%s)) ", index_expr_->str(), (*subit)->num_->Str());
				}
				else if ((*subit)->expr_type_ == Expr::EXPR_ID)	{
					out_h->print("if (((%s) == (%s)) ", index_expr_->str(), (*subit)->id_->Name());
				}
				else	{
					out_h->print("if (((%s) == (%s)) ", index_expr_->str(), (*subit)->str());
				}*/
				subit++;
				for (; subit<(*it1)->end(); subit++)	{
					assert((*subit)!=NULL);
					/*if ((*subit)->num_operands_>=1)	{
						(*subit)->GenStrFromFormat();
					}*/
					out_h->print("|| ((%s) == (%s)) ", index_expr_->orig(), ReComputeExpr((*subit), fieldtable).c_str());
					//out_h->print("|| ((%s) == (%s)) ", index_expr_->EvalExpr(out_temp, env_), (*subit)->EvalExpr(out_temp, env_));
					/*if ((*subit)->expr_type_ == Expr::EXPR_NUM)	{
						out_h->print("|| ((%s) == (%s)) ", index_expr_->str(), (*subit)->num_->Str());
					}
					else if ((*subit)->expr_type_ == Expr::EXPR_ID)	{
						out_h->print("|| ((%s) == (%s)) ", index_expr_->str(), (*subit)->id_->Name());
					}
					else	{
						out_h->print("|| ((%s) == (%s)) ", index_expr_->str(), (*subit)->str());
					}*/
				}
				out_h->print(")	");
			}
			else	{
				assert(!defaultcase);
				defaultcase = true;
			}
			
			out_h->print("{\n");
			out_h->inc_indent();
	
			assert((*it2) != NULL);
			(*it2)->GenCode(out_h, fieldtable);	//recursively generate code

			out_h->dec_indent();
			out_h->println("}");

			it2++;
		}

		if (!defaultcase)	{
			out_h->println("else {");
			out_h->inc_indent();
			out_h->println("//cout <<\"unexpected case, exiting\"<<endl;");
			//out_h->println("exit(1);");
			out_h->println("parserentity->tablepointer = -2;");
			//out_h->println("return -2;");
			out_h->dec_indent();
			out_h->println("}");
		}

	//cout <<"leave the gencode for branch next field"<<endl;
		return 0;
		
	}
#endif

void FieldEntry::DebugOutput(ofstream& fout, vector<FieldEntry*>& fieldtable)
{
	fout <<"--------------- starting a new field -----------------"<<endl;
	metadata_.DebugOutput(fout);
	fout <<"the preceders are:"<<endl;
	for (vector<FieldEntry*>::iterator tempi = preceders.begin() ; tempi < preceders.end() ; tempi++)	{
		vector<FieldEntry*>::iterator tempj;
		for (tempj = fieldtable.begin() ; tempj < fieldtable.end() ; tempj++)
		{
			if ((*tempi) == (*tempj))	{
				break;
			}
		}
		if (tempj == fieldtable.end())	{
			fout <<"\terror, do not find the "<<tempi - preceders.begin()<<"th preceder"<<endl;
		}
		else	{
			fout <<"\tthe "<<tempj - fieldtable.begin()<<"th entry"<<endl;
		}
	}
	fout <<"the next fields are:"<<endl;
	if (nextField_)	{
		nextField_->DebugOutput(fout, fieldtable);
	}
	else	{
		fout <<"NONE"<<endl;
	}
	fout <<"--------------- ending current field -----------------"<<endl<<endl;
}

void FieldTable::DebugCheckGlobalVar()
{
	assert(globalvarname.size() == globalvartype.size());
	debugout <<"----------- start print global variables ----------"<<endl;
	for (unsigned int i = 0; i<globalvarname.size() ; i++)	{
		debugout <<globalvartype[i]->DataTypeStr()<<" "<<globalvarname[i]->Name()<<endl;
	}
	debugout <<"----------- end print global variables -----------"<<endl;
}
//Add the first/starting field(root node of parsing tree) into the field table
int FieldTable::GenStartField(Type* field_type, const ID* field_id)
{
	FieldEntry* startField = new FieldEntry();
	startField->metadata_.type_ = field_type;	//set metadata
	startField->metadata_.id_ = field_id;
	startField->metadata_.field_ = NULL;

	startField->fieldType_ = FieldEntry::TYPE2;
	
	ConstFieldLength* startFieldLength = new ConstFieldLength(0, FieldLength::CONSTNUMBER);
	startField->fieldLength_.push_back(startFieldLength);	//set field length

	ConstFieldLength* startGarbageLength = new ConstFieldLength(0, FieldLength::CONSTNUMBER);
	startField->garbageLength_.push_back(startGarbageLength);	//set garbage length

	fieldTable_.push_back(startField);	//add the first entry into field table
	startFieldPointer = startField;		//set the pointer to the start field

	return 0;
}

//add the other fields in the protocol into the field table
int FieldTable::GenOtherFields()
{
	//cout <<"enter genotherfields"<<endl;
	bool running = true;
	bool specialstartingcase = true;

	while (running)	{	//iteratively traverse through the protocol parsing tree to add all fields into the table
		//DebugOutput();
		if (specialstartingcase)	//special case if there is only the starting node in the field table
		{
			//cout <<"enter special starting case"<<endl;
			specialstartingcase = false;
			FieldEntry* complexField = startFieldPointer;
			assert(complexField!=NULL);
			Type* typeComplexField = complexField->metadata_.type_;
			assert(typeComplexField!=NULL);
			//ID* idComplexField = complexField->metadata_.id_;

			if (typeComplexField->tot() == Type::CASE || typeComplexField->tot() == Type::RECORD)	//the only case that is dealt now
			{
				AddParamToGlobalContext(typeComplexField);	//add param into global context

				AddLetFieldToGlobalContext(typeComplexField);	//add let field into global context
			}
			else	{	//not deal with other cases
				cout <<"error, only support root node of case or record type"<<endl;
				exit(1);
			}
			
			if (typeComplexField->tot() == Type::CASE)	//only handle case type and record type now
			{
				CaseType* casetypeComplexField = static_cast<CaseType*>(typeComplexField);
				BranchNextField* parentNextField  = new BranchNextField(casetypeComplexField->index_expr_);	//build the next field attribute for the complex field
				parentNextField->env_ = typeComplexField->env();
				CaseFieldList::iterator it;
				for (it = casetypeComplexField->cases_->begin() ; it < casetypeComplexField->cases_->end() ; it++)	//add every case into the table
				{
					CaseField* pCaseField = *it;
					assert(pCaseField!=NULL);
					FieldEntry* pNewEntry = new FieldEntry();
					pNewEntry->metadata_.id_ = pCaseField->id();		//set the metadata
					pNewEntry->metadata_.type_ = pCaseField->type();
					pNewEntry->metadata_.field_ = pCaseField;

					pNewEntry->preceders.push_back(complexField);	//add preceder
					fieldTable_.push_back(pNewEntry);		//add the entry into the field table

					parentNextField->index_for_case_.push_back(pCaseField->index_);	//build parent's next field
					parentNextField->branchNextField_.push_back(new ConsequentNextField(pNewEntry,NextField::CONSEQUENT));
				}
				complexField->nextField_ = parentNextField;
			}					
			else if (typeComplexField->tot() == Type::RECORD)
			{
				RecordType* recordtypeComplexField = static_cast<RecordType*>(typeComplexField);

				RecordFieldList::iterator it;
				for (it = recordtypeComplexField->record_fields_->begin() ; it < recordtypeComplexField->record_fields_->end() ; it++)	//add every record field into the table
				{
					RecordField* pRecordField = *it;
					
					FieldEntry* pNewEntry = new FieldEntry();
					pNewEntry->metadata_.id_ = pRecordField->id();	//set the metadata
					pNewEntry->metadata_.type_ = pRecordField->type();
					pNewEntry->metadata_.field_ = pRecordField;

					fieldTable_.push_back(pNewEntry);		//add the entry into the field table;

					if (it == recordtypeComplexField->record_fields_->begin())	//if this is the first field in the record
					{
						if (typeComplexField->attr_oneline_)	{	//set child field to be &oneline
							pNewEntry->oneline_ = true;
						}
						
						pNewEntry->preceders.push_back(complexField);	//add preceder
						complexField->nextField_ = new ConsequentNextField(pNewEntry, NextField::CONSEQUENT);
					}
					else		//if this is not the first field in the record
					{
						FieldEntry* lastField = fieldTable_[fieldTable_.size() - 2];	//get the field before the current field
						pNewEntry->preceders.push_back(lastField);	//the field before the current field is its preceder
						lastField->nextField_ = new ConsequentNextField(pNewEntry, NextField::CONSEQUENT);
					}
				}
			}
			else	{
				cout <<"error, only support root node of case or record type"<<endl;
				exit(1);
			}
			//cout <<"leaving special staring case"<<endl;
					
		}
		else		//other normal cases
		{
			//cout <<"entering normal case"<<endl;
			vector<FieldEntry*>::iterator itComplexField = FindComplexField();	//try to find a complex field in the table
			if (itComplexField == fieldTable_.end())	{		//if all fields are simple field, the table is completely built
				running = false;
			}
			else		//expand the found complex field, then delete it from the field table
			{
				FieldEntry* complexField = *itComplexField;
				assert(complexField);
				Type* typeComplexField = complexField->metadata_.type_;
				assert(typeComplexField);
				fieldTable_.erase(itComplexField);	//erase the complex  field from field table
				//ID* idComplexField = complexField->metadata_.id_;
				if (typeComplexField->tot() == Type::CASE)	{	//expand case type
					//cout <<"handle case type field"<<endl;
					ExpandCaseType(complexField);
					//cout <<"finished case type field"<<endl;
				}
				else if (typeComplexField->tot() == Type::RECORD)	{	//expand record type
					//cout <<"handle record type field"<<endl;
					ExpandRecordType(complexField);
					//cout <<"finished record type field"<<endl;
				}
				else if (typeComplexField->tot() == Type::ARRAY)	{	//expand array type
					//cout <<"handle array type field"<<endl;
					ExpandArrayType(complexField);
					//cout <<"finished array type field"<<endl;
				}
				else if (typeComplexField->tot() == Type::PARAMETERIZED)	{	//expand parameterized type
					//cout <<"handle parameterized type field"<<endl;
					ParameterizedType* paramType_ = static_cast<ParameterizedType*>(typeComplexField);
					Type* lookupresult = TypeDecl::LookUpType(paramType_->type_id_);
					
					assert(lookupresult != NULL);

				
					if (lookupresult->tot() == Type::CASE)	{	//expand case type
						//cout <<"in parameterized type, expand as caset type"<<endl;
						ExpandCaseType(complexField);
					}
					else if (lookupresult->tot() == Type::RECORD)	{	//expand record type
						//cout <<"in parameterized type, expand as record type"<<endl;
						ExpandRecordType(complexField);
					}
					else if (lookupresult->tot() == Type::ARRAY)	{	//expand array type
						//cout <<"in parameterized type, expand as array type"<<endl;
						ExpandArrayType(complexField);
					}
					else 	{	//other cases
						cout <<"error, unexpected cases of parameterized type, exiting"<<endl;
						exit(1);
					}
					//cout <<"finished parameterized type field"<<endl;
				}
				else	{	//error
					cout <<"error, current type is not complex type"<<endl;
					exit(1);
				}
				//check for correctness
				for (vector<FieldEntry*>::iterator checkit = fieldTable_.begin(); checkit < fieldTable_.end() ; checkit++)	{
					for (vector<FieldEntry*>::iterator checkiq = (*checkit)->preceders.begin(); checkiq < (*checkit)->preceders.end() ; checkiq++)	{
						assert(*checkiq);
						assert((*checkiq) != complexField);
					}
				}
				delete complexField;
				//cout <<"leaving normal case"<<endl;
			}
		}

		
	}

	DebugCheckGlobalVar();
	//cout <<"leaving gen other fields"<<endl;
	return 0;
}

//find a complex field in the field table
//Currently, only condiser "type", "case" and "array" field as complex field
vector<FieldEntry*>::iterator FieldTable::FindComplexField()
{
	//cout <<"starting finding complex field"<<endl;
	vector<FieldEntry*>::iterator it;
	for ( it = fieldTable_.begin() ; it < fieldTable_.end() ; it++)
	{
		FieldEntry* currentField = *it;
		assert(currentField);
	//	cout <<"starting checking current iterator"<<endl;
		if (currentField == startFieldPointer)	{	//do not consider the special starting pointer
	//		cout <<"current field is starting field, end checking current one"<<endl;
			continue;
		}
		else	{	//consider other fields
	//		cout <<"current pointer is not starting field"<<endl;
			Type* typeCurrentField = currentField->metadata_.type_;
			assert(typeCurrentField);
			if (typeCurrentField->tot() == Type::CASE || typeCurrentField->tot() == Type::RECORD
				|| typeCurrentField->tot() == Type::ARRAY)	//if they are complex field
			{
	//			cout <<"successfully find complex field"<<endl;
				if (typeCurrentField->tot() == Type::ARRAY)	{
					ArrayType* arraytype = static_cast<ArrayType*>(typeCurrentField);
					if (arraytype->elemtype_->tot() == Type::BUILTIN)	{
						continue;
						}
				}
				return it;
			}
			else if (typeCurrentField->tot() == Type::PARAMETERIZED)	//need to consider parameterized type
			{
	//			cout <<"current iterator is parameterized type"<<endl;
				ParameterizedType* paramType = static_cast<ParameterizedType*>(typeCurrentField);
				assert(paramType);
				if (paramType->type_id_ != NULL)	{
	//				cout <<"the type id is "<<paramType->type_id_->name<<endl;
				}
				else	{
	//				cout <<"the type id is NULL"<<endl;
					}
				Type* lookupresult = TypeDecl::LookUpType(paramType->type_id_);
	//			cout <<"finished looking up type"<<endl;
				assert(lookupresult);
				if (lookupresult && 
					(lookupresult->tot() == Type::CASE || lookupresult->tot() == Type::RECORD || lookupresult->tot() == Type::ARRAY))
				{
	//				cout <<"successfully find complex field"<<endl;
					if (lookupresult->tot() == Type::ARRAY)	{
					ArrayType* arraytype = static_cast<ArrayType*>(lookupresult);
					if (arraytype->elemtype_->tot() == Type::BUILTIN)	{
						continue;
						}
				}
					//cout <<"current expanding field is "<<(*it)->metadata_.id_->Name()<<endl;
					return it;
				}
				else	{
					cout <<"error, unexpected cases of paremeterized type"<<endl;
					exit(1);
				}
			}
			else	{	//current field is of simple type
				continue;
			}
		}
	//	cout <<"ending checking current iterator"<<endl;
	}
	//cout <<"not find complex field, leaving finding complex field"<<endl;
	return it;
}

//add param declaration, in parameters,  into global context
int FieldTable::AddParamToGlobalContext(Type* typeComplexField)	//add param into global context
{
	assert(typeComplexField->type_decl());
	ParamList* paramlist = typeComplexField->type_decl()->params_;
	if (!paramlist)	{
		return 0;
		}

	for (ParamList::iterator it = paramlist->begin() ; it < paramlist->end() ; it++)	{
		Param* temp = (*it);
		//the id of global variable, equals to typename_variablename
		//ID* paramid = new ID(nfmt("%s_%s", typeComplexField->type_decl()->id()->Name(), temp->id()->Name()));
		ID* paramid = temp->id()->clone();
		vector<ID*>::iterator check;
		for (check = globalvarname.begin() ; check < globalvarname.end() ; check++)	{
			if ((*check)->name == paramid->name)	{	//check for duplication
				break;
			}
		}
		if (check < globalvarname.end())	{
			delete paramid;
			}
		else	{
			globalvarname.push_back(paramid);
			assert(temp->type()->tot() == Type::PARAMETERIZED
				||temp->type()->tot() == Type::EXTERN
				||temp->type()->tot() == Type::BUILTIN);
			globalvartype.push_back(temp->type());
		}
	}
	return 0;
}

//add param declaration, in let fields, into global context
int FieldTable::AddLetFieldToGlobalContext(Type* typeComplexField)		//add let field into global context
{
	assert(typeComplexField->type_decl());
	AttrList* attrlist = typeComplexField->type_decl()->attrlist_;
	if (!attrlist)	{
		return 0;
		}

	for (AttrList::iterator it = attrlist->begin() ; it < attrlist->end() ; it++)	{
		if ((*it)->type() == ATTR_LET)	{
			LetAttr* letattr = static_cast<LetAttr*>(*it);
			for (FieldList::iterator j = letattr->letfields()->begin() ; j < letattr->letfields()->end() ; j++)	{
				assert((*j)->tof() == LET_FIELD);
				LetField* letfield = static_cast<LetField*>(*j);
				//ID* paramid = new ID(nfmt("%s_%s", typeComplexField->type_decl()->id()->Name(), letfield->id()->Name()));
				ID* paramid = letfield->id()->clone();
				vector<ID*>::iterator check;
				for (check = globalvarname.begin() ; check < globalvarname.end() ; check++)	{
					if ((*check)->name == paramid->name)	{	//check for duplication
						break;
					}
				}
				if (check < globalvarname.end())	{
					delete paramid;
					}
				else	{
					globalvarname.push_back(paramid);
					assert(letfield->type()->tot() == Type::PARAMETERIZED
						||letfield->type()->tot() == Type::EXTERN
						||letfield->type()->tot() == Type::BUILTIN);
					globalvartype.push_back(letfield->type());
				}
			}
		}
	}
	
	return 0;
}

//expand a case type complex field
int FieldTable::ExpandCaseType(FieldEntry* complexField)
{
	//cout <<"enter expand case for "<<complexField->metadata_.id_->Name()<<endl;
	Type* typeComplexField = complexField->metadata_.type_;
	CaseType* casetypeComplexField;	//the case type pointer to the type of complex field
	if (typeComplexField->tot() == Type::CASE)	{	//the case where the type is directly "case" type
		if (typeComplexField->type_decl())	{
			AddParamToGlobalContext(typeComplexField);	//add param into global context
			AddLetFieldToGlobalContext(typeComplexField);	//add let field into global context
		}
		casetypeComplexField = static_cast<CaseType*>(typeComplexField);
	}
	else if (typeComplexField->tot() == Type::PARAMETERIZED)	{	//the case where the type is "parameterized"
		ParameterizedType* paramType = static_cast<ParameterizedType*>(typeComplexField);
		Type* lookupresult = TypeDecl::LookUpType(paramType->type_id_);
		assert(lookupresult);
		AddParamToGlobalContext(lookupresult);	//add param into global context
		AddLetFieldToGlobalContext(lookupresult);	//add let field into global context
		if (lookupresult->tot() == Type::CASE)	{	//find such type
			if (paramType->attr_oneline_)	{	// propagate the &oneline attribute
				lookupresult->attr_oneline_ = true;
			}

			casetypeComplexField = static_cast<CaseType*>(lookupresult);
		}
		else	{	//do not find such  type
			cout <<"error, expect to find a \"case\" type here, exiting"<<endl;
			exit(1);
		}
	}
	else	{	//for type other than "case" or "parameterized"
		cout <<"error, expect to find a \"case\" type here, exiting"<<endl;
		exit(1);
	}

	//cout <<"found type for "<<complexField->metadata_.id_->Name()<<endl;
	BranchNextField* pNextField = new BranchNextField(casetypeComplexField->index_expr_);	//build the next field attribute for preceders
	pNextField->env_ = casetypeComplexField->env();
	CaseFieldList::iterator it;
	vector<FieldEntry*> expandedcasefield;	//the vector records all expanded case fields
	for (it = casetypeComplexField->cases_->begin() ; it < casetypeComplexField->cases_->end() ; it++)	//add every case into the table
	{
		CaseField* pCaseField = *it;
		FieldEntry* pNewEntry = new FieldEntry();
		pNewEntry->metadata_.field_ = pCaseField;	//set metadata
		pNewEntry->metadata_.id_ = pCaseField->id();
		pNewEntry->metadata_.type_ = pCaseField->type();
		if (casetypeComplexField->attr_oneline_ || complexField->oneline_)	{	//propagate the &oneline attribute
			pNewEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pNewEntry->oneline_transfered_ = true;
		}
		if (casetypeComplexField->attr_oneline_ || complexField->oneline_cleanup_)	{
			pNewEntry->oneline_cleanup_ = true;
		}

		pNewEntry->preceders = complexField->preceders;	//the preceders for the new entry is identical to that of complex entry
		fieldTable_.push_back(pNewEntry);	//add the new field into the table
		expandedcasefield.push_back(pNewEntry);	
		
		/*update the NextField attribute of all the preceders*/	
		pNextField->index_for_case_.push_back(pCaseField->index_);		//build preceders's next field;
		pNextField->branchNextField_.push_back(new ConsequentNextField(pNewEntry, NextField::CONSEQUENT, pNextField));
	}

	//cout <<"add all case field into field table"<<endl;
	/* add the next field attribute into all preceders */
	vector<FieldEntry*>::iterator j;
	for (j = complexField->preceders.begin() ; j < complexField->preceders.end() ; j++)
	{
		FieldEntry* preceder = *j;
		NextField* containComplexField = preceder->nextField_->FindNextField(complexField);

		assert(containComplexField);

		//pNextField->parentNextField = containComplexField->parentNextField;
		NextField* parentNextField_ = containComplexField->parentNextField;
		if (!parentNextField_)	{
			delete preceder->nextField_;
			preceder->nextField_ = pNextField->Clone();
		}
		else	{
			BranchNextField* branchParentNextField = static_cast<BranchNextField*>(parentNextField_);
			/*
			for (vector<NextField*>::iterator k = branchParentNextField->branchNextField_.begin() ; k != branchParentNextField->branchNextField_.end() ; k++)
			{
				if ((*k) != containComplexField)	{
					continue;
					}
				else	{
					delete (*k);
					unsigned int index = k - branchParentNextField->branchNextField_.begin();
					branchParentNextField->branchNextField_.erase(k);	//delete old next field pointer
					k = branchParentNextField->branchNextField_.begin()+index;
					pNextField->parentNextField = branchParentNextField;
					branchParentNextField->branchNextField_.insert(k, pNextField->Clone());	//insert new next field pointer
					pNextField->parentNextField = NULL;
				}
				
			}
			*/
			for (vector<NextField*>::iterator k = branchParentNextField->branchNextField_.begin() ; k != branchParentNextField->branchNextField_.end() ; k++)
			{
				if ((*k) != containComplexField)	{
					continue;
					}
				else	{
					delete (*k);

					pNextField->parentNextField = branchParentNextField;
					*k = pNextField->Clone();	//insert new next field pointer
					pNextField->parentNextField = NULL;
				}
				
			}
		}
	}

	//cout <<"update preceders next field complete"<<endl;
	for (j = expandedcasefield.begin() ; j<expandedcasefield.end() ; j++)	{
		if (complexField->nextField_)	{	//if the complex field has next field
			assert(complexField->nextField_->parentNextField == NULL);
			(*j)->nextField_ = complexField->nextField_->Clone();	//set the next field for the new entry
		}
	}

	//cout <<"update the next field for new field complete"<<endl;

	//check for correctness
	for (vector<FieldEntry*>::iterator checkit = fieldTable_.begin(); checkit < fieldTable_.end() ; checkit++)	{
		for (vector<FieldEntry*>::iterator checkiq = (*checkit)->preceders.begin(); checkiq < (*checkit)->preceders.end() ; checkiq++)	{
			assert(*checkiq);
		}
	}
	for (vector<FieldEntry*>::iterator checkiq = complexField->preceders.begin(); checkiq < complexField->preceders.end() ; checkiq++)	{
		assert(*checkiq);
	}
	//cout <<"check preceders in expand case field complete"<<endl;
	
	/* modify the preceder attribute for all possible nextfields */
	if (complexField->nextField_)	{
		complexField->nextField_->UpdatePreceder(complexField, expandedcasefield);
	}

	delete pNextField;

	//cout <<"modify the preceder for next fields complete"<<endl;
	if (complexField->contextupdateafterparse.size() > 0)	{	//pass the context update to child field
		for (vector<ContextUpdateAfterParse*>::iterator updateit = complexField->contextupdateafterparse.begin() ; updateit < complexField->contextupdateafterparse.end() ; updateit++)	{
			for (vector<FieldEntry*>::iterator entryit = expandedcasefield.begin() ; entryit < expandedcasefield.end() ; entryit++)	{
				(*entryit)->contextupdateafterparse.push_back((*updateit)->Clone());
			}
			/*for (unsigned int i = 0; i<expandedcasefield.size() ; i++)	{
				fieldTable_[fieldTable_.size()-1-i]->contextupdateafterparse.push_back((*updateit)->Clone());
			}*/
		}
	}

	//update context 
	ContextUpdateCaseParameter(casetypeComplexField);
	//cout <<"finished context update, returning"<<endl;
	
	return 0;
}

//expand record type complex field
int FieldTable::ExpandRecordType(FieldEntry* complexField)
{
	Type* typeComplexField = complexField->metadata_.type_;
	assert(typeComplexField != NULL);
	RecordType* recordtypeComplexField;	//the record type pointer to the type of complex field
	if (typeComplexField->tot() == Type::RECORD)	{	//the case where the type is directly "record" type
		AddParamToGlobalContext(typeComplexField);	//add param into global context
		AddLetFieldToGlobalContext(typeComplexField);	//add let field into global context
		recordtypeComplexField = static_cast<RecordType*>(typeComplexField);
	}
	else if (typeComplexField->tot() == Type::PARAMETERIZED)	{	//the case where the type is "parameterized"
		ParameterizedType* paramType = static_cast<ParameterizedType*>(typeComplexField);
		assert(paramType->type_id_);
		Type* lookupresult = TypeDecl::LookUpType(paramType->type_id_);
		assert(lookupresult );
		AddParamToGlobalContext(lookupresult);	//add param into global context
		AddLetFieldToGlobalContext(lookupresult);	//add let field into global context
		if (lookupresult->tot() == Type::RECORD)	{	//find such type
			if (paramType->attr_oneline_)	{	// propagate the &oneline attribute
				lookupresult->attr_oneline_ = true;
			}
			
			recordtypeComplexField = static_cast<RecordType*>(lookupresult);
		}
		else	{	//do not find such  type
			cout <<"error, expect to find a \"record\" type here, exiting"<<endl;
			exit(1);
		}
	}
	else	{	//for type other than "record" or "parameterized"
		cout <<"error, expect to find a \"record\" type here, exiting"<<endl;
		exit(1);
	}

	assert(recordtypeComplexField!=NULL);
	assert(recordtypeComplexField->record_fields_ != NULL);
	RecordFieldList::iterator it;
	for (it = recordtypeComplexField->record_fields_->begin() ; it < recordtypeComplexField->record_fields_->end() ; it++)	//add every case into the table
	{
		RecordField* pRecordField = *it;
		assert(pRecordField);
		
		FieldEntry* pNewEntry = new FieldEntry();
		pNewEntry->metadata_.field_ = pRecordField;	//set metadata
		pNewEntry->metadata_.id_ = pRecordField->id();
		pNewEntry->metadata_.type_ = pRecordField->type();

		//if (it == recordtypeComplexField->record_fields_->end())	{	//test if works
		if (recordtypeComplexField->attr_oneline_ || complexField->oneline_)	{	//propagate the &oneline attribute
			pNewEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pNewEntry->oneline_transfered_ = true;
		}
		//	}
		fieldTable_.push_back(pNewEntry);	//add the new field into the table

		assert(complexField!=NULL);
		if (it == recordtypeComplexField->record_fields_->begin())	{	//the first record field
			pNewEntry->preceders = complexField->preceders;	//the preceders for the new entry is identical to that of complex entry

#if 0
			if (recordtypeComplexField->attr_oneline_ || complexField->oneline_)	{	//propagate the &oneline attribute
				pNewEntry->oneline_ = true;
			}
			if (complexField->oneline_transfered_)	{
				pNewEntry->oneline_transfered_ = true;
			}
#endif			
			/*update the NextField attribute of all the preceders of parent node*/
			vector<FieldEntry*>::iterator j;
			for (j = complexField->preceders.begin() ; j<complexField->preceders.end() ; j++)
			{
				FieldEntry* preceder = *j;
				assert(preceder!=NULL);
				/*if (preceder->nextField_ == NULL)	{
					cout <<"the preceder's id is "<<preceder->metadata_.id_->name
						<<", the id of current complex field is "<<complexField->metadata_.id_->name<<endl;
					}*/
				assert(preceder->nextField_!=NULL);
				NextField* containComplexField = preceder->nextField_->FindNextField(complexField);
				assert(containComplexField);

				assert(containComplexField->nextFieldType_ == NextField::CONSEQUENT);
				ConsequentNextField* consNextField = static_cast<ConsequentNextField*>(containComplexField);
				consNextField->nextField_ = pNewEntry;	
			}
		}
		else	{	//not the first record field
			assert(fieldTable_.size()>=2);
			FieldEntry* lastField = fieldTable_[fieldTable_.size() - 2];	//get the field before the current field
			assert(lastField);
			assert(pNewEntry);
			pNewEntry->preceders.push_back(lastField);	//the field before the current field is its preceder
			lastField->nextField_ = new ConsequentNextField(pNewEntry, NextField::CONSEQUENT);
		}

		assert(recordtypeComplexField->record_fields_->size()>0);
		if (it == recordtypeComplexField->record_fields_->end() -1)	{	//the last record field
			if (complexField->nextField_)	{	//if the complex field has next field
				if (recordtypeComplexField->attr_oneline_ || complexField->oneline_cleanup_)	{	//propagate the &oneline_cleanup attribute
					pNewEntry->oneline_cleanup_= true;
				}
				
				pNewEntry->nextField_ = complexField->nextField_->Clone();	//set the next field for the new entry

				NextField* containComplexField = pNewEntry->nextField_->FindNextField(complexField);
				if (containComplexField)	{	//if the complex field has itself as the next field
					assert(containComplexField->nextFieldType_ == NextField::CONSEQUENT);
					ConsequentNextField* consNextField = static_cast<ConsequentNextField*>(containComplexField);
					consNextField->nextField_ = fieldTable_[fieldTable_.size() - recordtypeComplexField->record_fields_->size()];
				}
				/* update the preceder attribute for all next fields */
				vector<FieldEntry*> newpreceder;
				newpreceder.push_back(pNewEntry);
				pNewEntry->nextField_->UpdatePreceder(complexField, newpreceder);
			}
		}
	}

	if (complexField->contextupdateafterparse.size() > 0)	{	//pass the context update to child field
		for (vector<ContextUpdateAfterParse*>::iterator updateit = complexField->contextupdateafterparse.begin() ; updateit < complexField->contextupdateafterparse.end() ; updateit++)	{
			fieldTable_[fieldTable_.size()-1]->contextupdateafterparse.push_back((*updateit)->Clone());
		}
	}
	ContextUpdateRecordLetField(recordtypeComplexField);
	ContextUpdateRecordParameter(recordtypeComplexField);
	
	return 0;
}

//expand array type complex field
int FieldTable::ExpandArrayType(FieldEntry* complexField)
{
	assert(complexField->contextupdateafterparse.size() == 0);
#if 0
	if (complexField->contextupdateafterparse.size() > 0)	{
		for (vector<ContextUpdateAfterParse*>::iterator it = complexField->contextupdateafterparse.begin() ; it < complexField->contextupdateafterparse.end() ; it++)	{
			cout <<(*it)->varid->Name()<<" = "<<(*it)->updateexpr->orig_<<endl;
		}
		exit(1);
	}
#endif
	
	Type* typeComplexField = complexField->metadata_.type_;
	ArrayType* arraytypeComplexField;	//the array type pointer to the type of complex field
	if (typeComplexField->tot() == Type::ARRAY)	{	//the case where the type is directly "array" type
		arraytypeComplexField = static_cast<ArrayType*>(typeComplexField);
	}
	else if (typeComplexField->tot() == Type::PARAMETERIZED)	{	//the case where the type is "parameterized"
		ParameterizedType* paramType = static_cast<ParameterizedType*>(typeComplexField);
		Type* lookupresult = TypeDecl::LookUpType(paramType->type_id_);
		if (lookupresult && lookupresult->tot() == Type::ARRAY)	{	//find such type
			if (paramType->attr_oneline_)	{	// propagate the &oneline attribute
				lookupresult->attr_oneline_ = true;
			}
		
			arraytypeComplexField = static_cast<ArrayType*>(lookupresult);
		}
		else	{	//do not find such  type
			cout <<"error, expect to find a \"array\" type here, exiting"<<endl;
			exit(1);
		}
	}
	else	{	//for type other than "array" or "parameterized"
		cout <<"error, expect to find a \"array\" type here, exiting"<<endl;
		exit(1);
	}

	assert(arraytypeComplexField->elemtype_);
	if (arraytypeComplexField->length_)	{	//if the array length is explicitly specified
		FieldEntry* pNewEntry = new FieldEntry();
		pNewEntry->metadata_.type_ = arraytypeComplexField->elemtype_;	//set metadata
		pNewEntry->metadata_.id_ = new ID("array_element");
		FieldEntry* pTail = new FieldEntry();
		pTail->metadata_.type_ = new BuiltInType(BuiltInType::EMPTY);
		pTail->metadata_.id_ = new ID("array_tail");

		if (arraytypeComplexField->attr_oneline_ || complexField->oneline_)		{//propagate the &oneline attribute
			pNewEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pNewEntry->oneline_transfered_ = true;
		}

		pNewEntry->preceders = complexField->preceders;		//set preceders
		pNewEntry->preceders.push_back(pTail);		
		pTail->preceders.push_back(pNewEntry);

		BranchNextField* newNextField = new BranchNextField(arraytypeComplexField->length_);	//set next field
		newNextField->env_ = arraytypeComplexField->env();
		ExprList* firstcase = new ExprList;
		firstcase->push_back(new Expr(new Number(0)));
		newNextField->index_for_case_.push_back(firstcase);	//set the case where array has reached the end
		if (complexField->nextField_)	{
			NextField* complexfieldNextField = complexField->nextField_->Clone();
			complexfieldNextField->parentNextField = newNextField;
			newNextField->branchNextField_.push_back(complexfieldNextField);
		}
		else	{
			newNextField->branchNextField_.push_back(new NextField(NextField::NONE, newNextField));
		}
		newNextField->index_for_case_.push_back(NULL);	//set the case when array has not reached the end
		newNextField->branchNextField_.push_back(new ConsequentNextField(pNewEntry, NextField::CONSEQUENT, newNextField));
		
		pTail->nextField_ = newNextField;
		pNewEntry->nextField_ = new ConsequentNextField(pTail, NextField::CONSEQUENT, NULL);

		fieldTable_.push_back(pNewEntry);
		fieldTable_.push_back(pTail);
		
		/*update the NextField attribute of all the preceders of parent node*/	
		vector<FieldEntry*> newpreceder;
		vector<FieldEntry*>::iterator j;
		for (j = complexField->preceders.begin() ; j<complexField->preceders.end() ; j++)
		{
			FieldEntry* preceder = *j;
			newpreceder.push_back(preceder);
			
			NextField* containComplexField = preceder->nextField_->FindNextField(complexField);
			assert(containComplexField);
			assert(containComplexField->nextFieldType_ == NextField::CONSEQUENT);
			if (containComplexField->parentNextField == NULL)	{
				delete preceder->nextField_;
				preceder->nextField_ = newNextField->Clone();
			}
			else	{
				assert(containComplexField->parentNextField->nextFieldType_ == NextField::BRANCH);
				BranchNextField* parentcontaincomplexfield = static_cast<BranchNextField*>(containComplexField->parentNextField);
				for (vector<NextField*>::iterator itnext = parentcontaincomplexfield->branchNextField_.begin() ; itnext < parentcontaincomplexfield->branchNextField_.end() ; itnext++)	{
					if ((*itnext) == containComplexField)	{
						delete (*itnext);
						(*itnext) = newNextField->Clone();
						(*itnext)->parentNextField = parentcontaincomplexfield;
					}
				}
			}
		}

		/* update the preceder attribute for all possible next fields */
		if (complexField->nextField_)	{
			
			newpreceder.push_back(pTail);
			complexField->nextField_->UpdatePreceder(complexField, newpreceder);
		}

		/*add the context update to decrement the array length variable */
		ContextUpdateAfterParse* contextupdate = new ContextUpdateAfterParse();
		contextupdate->varid = new ID(arraytypeComplexField->length_->orig());
		contextupdate->updateexpr = new Expr(Expr::EXPR_MINUS, new Expr(new ID(arraytypeComplexField->length_->orig())), new Expr(new Number(1)));
		pTail->contextupdateafterparse.push_back(contextupdate);
	}
	else if (arraytypeComplexField->attr_until_input_expr_)	{	//needs to check the input before the first element
		FieldEntry* pHeaderEntry = new FieldEntry();		//need a new header field
		pHeaderEntry->metadata_.type_ = new BuiltInType(BuiltInType::EMPTY);	//set metadata
		pHeaderEntry->metadata_.id_ = new ID("array_header");

		FieldEntry* pNewEntry = new FieldEntry();
		pNewEntry->metadata_.type_ = arraytypeComplexField->elemtype_;	//set metadata
		pNewEntry->metadata_.id_ = new ID("array_element");

		if (arraytypeComplexField->attr_oneline_ || complexField->oneline_)		{//propagate the &oneline attribute
			pNewEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pNewEntry->oneline_transfered_ = true;
		}

#if 0
		if (arraytypeComplexField->attr_oneline_ || complexField->oneline_)		{//propagate the &oneline attribute
			pHeaderEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pHeaderEntry->oneline_transfered_ = true;
		}
#endif
		if (pNewEntry->metadata_.type_->attr_oneline_)	{	//move forward the &oneline attribute
			pHeaderEntry->oneline_ = true;
			pNewEntry->oneline_ = true;
			//pNewEntry->oneline_transfered_ =  true;
		}
		if (pNewEntry->metadata_.type_->tot() == Type::PARAMETERIZED)	{
			ParameterizedType* paramType = static_cast<ParameterizedType*>(pNewEntry->metadata_.type_);
			Type* lookupresult = TypeDecl::LookUpType(paramType->type_id_);
			assert(lookupresult);
			if (lookupresult->attr_oneline_)	{	// propagate the &oneline attribute
				pHeaderEntry->oneline_ = true;
				pNewEntry->oneline_ =  true;
				//pNewEntry->oneline_transfered_ =  true;
			}
		}

		pHeaderEntry->preceders = complexField->preceders;		//set preceders
		pHeaderEntry->preceders.push_back(pNewEntry);
		pNewEntry->preceders.push_back(pHeaderEntry);

		Expr* indexExpr;
		indexExpr = arraytypeComplexField->attr_until_input_expr_;

		BranchNextField* newNextField = new BranchNextField(indexExpr);	//set next field
		newNextField->env_ = arraytypeComplexField->env();
		ExprList* firstcase = new ExprList;
		firstcase->push_back(new Expr(new Number(0)));
		newNextField->index_for_case_.push_back(firstcase);	//set the case where array has not reached the end
		newNextField->branchNextField_.push_back(new ConsequentNextField(pNewEntry, NextField::CONSEQUENT, newNextField));
		ExprList* secondcase = new ExprList;
		secondcase->push_back(new Expr(new Number(1)));
		newNextField->index_for_case_.push_back(secondcase);	//set the case when array has reached the end
		//newNextField->index_for_case_.push_back(NULL);	//set the case when array has reached the end
		if (complexField->nextField_)	{
			NextField* complexfieldNextField = complexField->nextField_->Clone();
			complexfieldNextField->parentNextField = newNextField;
			newNextField->branchNextField_.push_back(complexfieldNextField);
		}
		else	{
			newNextField->branchNextField_.push_back(new NextField(NextField::NONE, newNextField));
		}
		pHeaderEntry->nextField_ = newNextField;

		pNewEntry->nextField_ = new ConsequentNextField(pHeaderEntry, NextField::CONSEQUENT, NULL);

		fieldTable_.push_back(pHeaderEntry);
		fieldTable_.push_back(pNewEntry);

		/*update the NextField attribute of all the preceders of parent node*/
		vector<FieldEntry*>::iterator j;
		for (j = complexField->preceders.begin() ; j<complexField->preceders.end() ; j++)
		{
			FieldEntry* preceder = *j;
			NextField* containComplexField = preceder->nextField_->FindNextField(complexField);
			assert(containComplexField);
			assert(containComplexField->nextFieldType_ == NextField::CONSEQUENT);
			ConsequentNextField* consqcontaincomplexfield = static_cast<ConsequentNextField*>(containComplexField);
			assert(consqcontaincomplexfield->nextField_ == complexField);

			ConsequentNextField* temp = static_cast<ConsequentNextField*>(containComplexField);
			temp->nextField_ = pHeaderEntry;
		}

		/* update the preceder attribute for all possible next fields */
		if (complexField->nextField_)	{
			vector<FieldEntry*> newpreceder;
			newpreceder.push_back(pHeaderEntry);
			complexField->nextField_->UpdatePreceder(complexField, newpreceder);
		}
	}
	else	{	//the case the until check is after the first element
		FieldEntry* pNewEntry = new FieldEntry();
		pNewEntry->metadata_.type_ = arraytypeComplexField->elemtype_->Clone();	//set metadata
		pNewEntry->metadata_.id_ = new ID("array_element");

		if (arraytypeComplexField->attr_oneline_ || complexField->oneline_)		{//propagate the &oneline attribute
			pNewEntry->oneline_ = true;
		}
		if (complexField->oneline_transfered_)	{
			pNewEntry->oneline_transfered_ = true;
		}

		pNewEntry->preceders = complexField->preceders;		//set preceders
		pNewEntry->preceders.push_back(pNewEntry);

		Expr* indexExpr;
		if (arraytypeComplexField->attr_until_element_expr_)	{
			indexExpr = arraytypeComplexField->attr_until_element_expr_;
		}
		else if (arraytypeComplexField->attr_generic_until_expr_)	{
			indexExpr = arraytypeComplexField->attr_generic_until_expr_;
		}
		else	{
			cout <<"error, the terminating condition of array type is not specified, exiting"<<endl;
			exit(1);
		}

		BranchNextField* newNextField = new BranchNextField(indexExpr);	//set next field
		newNextField->env_ = arraytypeComplexField->env();
		ExprList* firstcase = new ExprList;
		firstcase->push_back(new Expr(new Number(0)));
		newNextField->index_for_case_.push_back(firstcase);	//set the case where array has not reached the end
		newNextField->branchNextField_.push_back(new ConsequentNextField(pNewEntry, NextField::CONSEQUENT, newNextField));
		ExprList* secondcase = new ExprList;
		secondcase->push_back(new Expr(new Number(1)));
		newNextField->index_for_case_.push_back(secondcase);	//set the case when array has reached the end
		//newNextField->index_for_case_.push_back(NULL);	//set the case when array has reached the end
		if (complexField->nextField_)	{
			NextField* complexfieldNextField = complexField->nextField_->Clone();
			complexfieldNextField->parentNextField = newNextField;
			newNextField->branchNextField_.push_back(complexfieldNextField);
		}
		else	{
			newNextField->branchNextField_.push_back(new NextField(NextField::NONE, newNextField));
		}
		pNewEntry->nextField_ = newNextField;

		fieldTable_.push_back(pNewEntry);

		/*update the NextField attribute of all the preceders of parent node*/	
		vector<FieldEntry*>::iterator j;
		for (j = complexField->preceders.begin() ; j<complexField->preceders.end() ; j++)
		{
			FieldEntry* preceder = *j;
			NextField* containComplexField = preceder->nextField_->FindNextField(complexField);
			assert(containComplexField);
			assert(containComplexField->nextFieldType_ == NextField::CONSEQUENT);
			ConsequentNextField* consqcontaincomplexfield = static_cast<ConsequentNextField*>(containComplexField);
			assert(consqcontaincomplexfield->nextField_ == complexField);

			ConsequentNextField* temp = static_cast<ConsequentNextField*>(containComplexField);
			temp->nextField_ = pNewEntry;
		}

		/* update the preceder attribute for all possible next fields */
		if (complexField->nextField_)	{
			vector<FieldEntry*> newpreceder;
			newpreceder.push_back(pNewEntry);
			complexField->nextField_->UpdatePreceder(complexField, newpreceder);
		}
	}
	
	return 0;
}

void FieldTable::ContextUpdateRecordLetField(Type* typeComplexField)	//updating context in record let field
{
	assert(typeComplexField->tot() == Type::RECORD);
	RecordType* recordtypeComplexField = static_cast<RecordType*>(typeComplexField);

	assert(typeComplexField->type_decl());
	AttrList* attrlist = typeComplexField->type_decl()->attrlist_;
	if (!attrlist)	{
		return;
		}

	for (AttrList::iterator it = attrlist->begin() ; it < attrlist->end() ; it++)	{
		if ((*it)->type() == ATTR_LET)	{
			LetAttr* letattr = static_cast<LetAttr*>(*it);
			for (FieldList::iterator j = letattr->letfields()->begin() ; j < letattr->letfields()->end() ; j++)	{
				assert((*j)->tof() == LET_FIELD);
				LetField* letfield = static_cast<LetField*>(*j);
				//ID* paramid = new ID(nfmt("%s_%s", typeComplexField->type_decl()->id()->Name(), letfield->id()->Name()));
				ID* paramid = letfield->id()->clone();
				Expr* valueexpr = letfield->expr();	//find the variable name and the expression to update value
				
				if (valueexpr->expr_type() == Expr::EXPR_CALL)	//the case of function calling
				{
					assert(valueexpr->operand_[1]);
					Expr* callingargs = valueexpr->operand_[1];	//get the parameters
					assert(callingargs->expr_type() == Expr::EXPR_CALLARGS);

					//find a suitable field to put the update in
					for (ExprList::iterator exprit = callingargs->args_->begin() ; exprit < callingargs->args_->end() ; exprit++)
					{
						if ((*exprit)->num_operands_ != 0)	{	//not a simple expression
							cout <<"do not handle complex expression in function arguments now, exit(1)"<<endl;
							exit(1);
						}
						for (RecordFieldList::iterator fieldit = recordtypeComplexField->record_fields_->begin(); fieldit < recordtypeComplexField->record_fields_->end() ; fieldit++)	{
							//cout <<"the field id is "<<(*fieldit)->id()->Name()<<endl;
							//cout <<"the expr is "<<(*exprit)->orig_<<endl;
							if ((*fieldit)->id()->name == (*exprit)->orig_)	//two string matches
							{
								//add this update into the corresponding field
								FieldEntry* fieldupdate = fieldTable_[fieldTable_.size() - (recordtypeComplexField->record_fields_->end() - fieldit)];
								fieldupdate->contextupdateafterparse.push_back(new ContextUpdateAfterParse(paramid, valueexpr));
							}
						}
					}
					
				}
				else	{	//assuming the first recordfield will do the context update ,needs further refinement
					FieldEntry* fieldupdate = fieldTable_[fieldTable_.size() - recordtypeComplexField->record_fields_->size()];
					fieldupdate->contextupdateafterparse.push_back(new ContextUpdateAfterParse(paramid, valueexpr));
				}
				
			}
		}
	}
	
}

void FieldTable::ContextUpdateRecordParameter(RecordType* recordtypeComplexField)	//update context in record type, parameter passing
{
	assert(recordtypeComplexField->record_fields_);
	for (RecordFieldList::iterator fieldit = recordtypeComplexField->record_fields_->begin(); fieldit < recordtypeComplexField->record_fields_->end() ; fieldit++)	{
		//find the cases where parameter is passed
		if ((*fieldit)->type()->tot() == Type::PARAMETERIZED)	{
			ParameterizedType* fieldtype = static_cast<ParameterizedType*>((*fieldit)->type());
			if (fieldtype->args_)	{	//case where parameters are passed to the child type
				vector<ContextUpdateAfterParse*> contextupdate;
				Type* childtype = TypeDecl::LookUpType(fieldtype->type_id_);
				assert(childtype);
				assert(childtype->type_decl());
				assert(childtype->type_decl()->params_);
				assert(fieldtype->args_->size() == childtype->type_decl()->params_->size());
				ExprList::iterator exprit = fieldtype->args_->begin();
				ParamList::iterator paramit = childtype->type_decl()->params_->begin();
				for (; exprit<fieldtype->args_->end(); exprit++)	{	//update each global variable(parameter)
					//ID* paramid = new ID(nfmt("%s_%s", childtype->type_decl()->id()->Name(), (*paramit)->id()->Name()));
					/*if ((*exprit)->expr_type_ == Expr::EXPR_ID)	{	//add header for expression for ID typed expression
						(*exprit)->id()->name = 
					}*/
					ID* paramid = (*paramit)->id();
					if ((*exprit)->expr_type() == Expr::EXPR_ID && (*exprit)->id()->name == paramid->name)	{
						}
					else	{
						if ((*exprit)->expr_type() == Expr::EXPR_CALL)	{	
							//deal with member typed expression
							Expr* args = (*exprit)->operand_[1];
							assert (args->expr_type() == Expr::EXPR_CALLARGS);
							ExprList* argslist = args->args_;
							for (ExprList::iterator argit = argslist->begin() ; argit < argslist->end() ; argit++)	{
								Expr* arg = (*argit);
								while (arg->expr_type() == Expr::EXPR_MEMBER)	//deal with member type
								{
									arg = arg->operand_[1];
								}
								(*argit) = arg;
							}
						}
						contextupdate.push_back(new ContextUpdateAfterParse(paramid, (*exprit)));
					}
					paramit++;
				}

				FieldEntry* tableentry = fieldTable_[fieldTable_.size() - (recordtypeComplexField->record_fields_->end() - fieldit)];
				for (vector<FieldEntry*>::iterator entryit = tableentry->preceders.begin() ; entryit < tableentry->preceders.end() ; entryit++)	{
					//add update into preceder's field
					for (vector<ContextUpdateAfterParse*>::iterator updateit = contextupdate.begin() ; updateit < contextupdate.end() ; updateit++)	{
						(*entryit)->contextupdateafterparse.push_back((*updateit)->Clone());
					}
				}
			}
		}
	}
}

void FieldTable::ContextUpdateCaseParameter(CaseType* casetypeComplexField)	//update context in case type, parameter passing
{
	assert(casetypeComplexField->cases_);
	for (CaseFieldList::iterator fieldit = casetypeComplexField->cases_->begin(); fieldit < casetypeComplexField->cases_->end() ; fieldit++)	{
		//find the cases where parameter is passed
		if ((*fieldit)->type()->tot() == Type::PARAMETERIZED)	{
			ParameterizedType* fieldtype = static_cast<ParameterizedType*>((*fieldit)->type());
			if (fieldtype->args_)	{	//case where parameters are passed to the child type
				vector<ContextUpdateAfterParse*> contextupdate;
				Type* childtype = TypeDecl::LookUpType(fieldtype->type_id_);
				assert(childtype);
				assert(childtype->type_decl());
				assert(childtype->type_decl()->params_);
				assert(fieldtype->args_->size() == childtype->type_decl()->params_->size());
				ExprList::iterator exprit = fieldtype->args_->begin();
				ParamList::iterator paramit = childtype->type_decl()->params_->begin();
				for (; exprit<fieldtype->args_->end(); exprit++)	{	//update each global variable(parameter)
					//ID* paramid = new ID(nfmt("%s_%s", childtype->type_decl()->id()->Name(), (*paramit)->id()->Name()));
					ID* paramid = (*paramit)->id();
					if ((*exprit)->expr_type_ == Expr::EXPR_ID && (*exprit)->id()->name == paramid->name)	{
						}
					else	{
						if ((*exprit)->expr_type() == Expr::EXPR_CALL)	{	
							//deal with member typed expression
							Expr* args = (*exprit)->operand_[1];
							assert (args->expr_type() == Expr::EXPR_CALLARGS);
							ExprList* argslist = args->args_;
							for (ExprList::iterator argit = argslist->begin() ; argit < argslist->end() ; argit++)	{
								Expr* arg = (*argit);
								while (arg->expr_type() == Expr::EXPR_MEMBER)	//deal with member type
								{
									arg = arg->operand_[1];
								}
								(*argit) = arg;
							}
						}
						contextupdate.push_back(new ContextUpdateAfterParse(paramid, (*exprit)));
						}
					paramit++;
				}

				FieldEntry* tableentry = fieldTable_[fieldTable_.size() - (casetypeComplexField->cases_->end() - fieldit)];
				for (vector<FieldEntry*>::iterator entryit = tableentry->preceders.begin() ; entryit < tableentry->preceders.end() ; entryit++)	{
					//add update into preceder's field
					for (vector<ContextUpdateAfterParse*>::iterator updateit = contextupdate.begin() ; updateit < contextupdate.end() ; updateit++)	{
						(*entryit)->contextupdateafterparse.push_back((*updateit)->Clone());
					}
				}
			}
		}
	}
}


//the following function fill in the table those attributes that can be determined during table generation
//Additional parameters are needed.
int FieldTable::GenTypeColumn()	{
	return 0;
}

/*may have to handle the case that the length attribute should incorporate multiple length features*/
int FieldTable::GenLengthColumn()	{
  for (vector<FieldEntry*>::iterator i = fieldTable_.begin(); i != fieldTable_.end(); i++) {
    if ((*i)==startFieldPointer) {
      continue;
    }
    FieldLength* length;

	/* by hongyu */
	Type* fieldtype = (*i)->metadata_.type_;
	if (fieldtype->tot() == Type::STRING)	{
		StringType* stringfieldtype = static_cast<StringType*>(fieldtype);
		if (stringfieldtype->type_ == StringType::CSTR)	{
			assert(stringfieldtype->str_);
			length = new ConstFieldLength(stringfieldtype->str_->unescaped_.size(), FieldLength::CONSTNUMBER);
		}
		else if (stringfieldtype->type_ == StringType::ANYSTR)	{
			if (fieldtype->attr_length_expr_!=0)	{
				length = new ExpressionFieldLength(fieldtype->attr_length_expr_, FieldLength::EXPRESSION);
			}
			#if 0
			else if (fieldtype->attr_restofdata_)	{	//till now, only see &oneline to specify bytestring field
				length = new FieldLength(FieldLength::RESTOFDATA);
			}
			#endif
			else if (fieldtype->attr_restofdata_)	{
				if ((*i)->oneline_ && !(*i)->oneline_transfered_)	{
					length = new FieldLength(FieldLength::ONELINE);
				}
				else	{
					cout <<"rest of data but not oneline, the field id is "<<(*i)->metadata_.id_->Name()<<endl;
					if ((*i)->oneline_transfered_)	{
						cout <<"has one line but get transfered"<<endl;
						}
					length = new FieldLength(FieldLength::RESTOFDATA);
				}
			}
			else if (fieldtype->attr_restofflow_)	{	//same as above
				length = new FieldLength(FieldLength::RESTOFFLOW);
			}
			else if (fieldtype->attr_oneline_)	{	
				length = new FieldLength(FieldLength::ONELINE);
			}	
			/*else if ((*i)->metadata_.field_)	{	//anystr must have specified some length function
				Field* curfield = (*i)->metadata_.field_;
				AttrList::iterator it;
				for (it = curfield->attrs_->begin() ; it < curfield->attrs_->end() ; it++)	{
					if ((*it)->type() == ATTR_LENGTH)	{
						break;
					}
				}
				assert(it < curfield->attrs_->end());
				(*i)->DebugOutput(debugout, fieldTable_);
				length = new ExpressionFieldLength((*it)->expr(), FieldLength::EXPRESSION);
			}*/
			else	{	//other cases 
				cout <<"unexpected other cases for \"ANYSTR\" type, error"<<endl;
				exit(1);
			}
		}
		else if (stringfieldtype->type_ == StringType::REGEX)	{
			assert(stringfieldtype->regex_);
			length = new RegExFieldLength(stringfieldtype->regex_, FieldLength::REGEXMATCHING);
		}
		else	{
			cout <<"unexpected string type, error"<<endl;
			exit(1);
		}
	}
	else if (fieldtype->tot() == Type::EMPTY)	{
		length = new ConstFieldLength(0, FieldLength::CONSTNUMBER);
	}
	else if (fieldtype->tot() == Type::BUILTIN)	{
		BuiltInType* builtintype = static_cast<BuiltInType*>(fieldtype);
		length = new ConstFieldLength(basic_type_size[builtintype->bit_type()], FieldLength::CONSTNUMBER);
	}
	else if (fieldtype->tot() == Type::ARRAY)	{
		ArrayType* arraytype = static_cast<ArrayType*>(fieldtype);
		assert(arraytype->elemtype_->tot() == Type::BUILTIN);
		BuiltInType* elemtype = static_cast<BuiltInType*>(arraytype->elemtype_);
		assert(arraytype->length_);
		assert(arraytype->length_->num_);
		length = new ConstFieldLength(basic_type_size[elemtype->bit_type()]*arraytype->length_->num_->Num(), FieldLength::CONSTNUMBER);
	}
	else
	{
		cout <<"unexpected type for basic field, error"<<endl;
		exit(1);
	}
	
    // We might have to consider multiple attributes, e.g. expression and oneline.
    // But I don't knwo if this happens-- if it does, just transform all the above
    // statements into a push_back.
    (*i)->fieldLength_.push_back(length);
  }

  return 0;
}

int FieldTable::GenGarbageLengthColumn()	{
  // Sets the garbageLength field of each row to zero.
  for (vector<FieldEntry*>::iterator i = fieldTable_.begin(); i != fieldTable_.end(); i++) {
  	if ((*i)==startFieldPointer)	{
		continue;
  		}
	
    (*i)->garbageLength_.push_back(new ConstFieldLength(0, FieldLength::CONSTNUMBER));
  }

  return 0;
}

//After phase 1 table is generated, compress it to get phase 2 table
int FieldTable::CompressTable()	{
    for (vector<FieldEntry*>::iterator i = fieldTable_.begin(); i != fieldTable_.end(); i++) {
        if ((*i)==startFieldPointer) {
            continue;
        }
        // So we'll have to look ahead to the following fields to see if they're used in
        // parsing or not.
        NextField* nextField = (*i)->nextField_;
        FieldEntry* checkField;
        // Should be CONSEQUENT but ConsequentNextField structure uses NONE
        if (nextField->nextFieldType_ == NextField::NONE) { 
            /*
            checkField = nextField->nextField_;
            */
        } else if (nextField->nextFieldType_ == NextField::BRANCH) {
            // Need to get correct field or something
            // If NextField is flat, then we can just push the NextField of the next
            // field to this field. However, what do we do if the NextField of the
            // current field branches?
            // Is it even possible to 'compress' this? Since we don't know which
            // field it might take, won't we have to leave it as-is?
            // checkField = NULL;
            continue;
        }
        // If the following field is not used, we compress it.
        if (checkField->fieldType_ == FieldEntry::NOT_USED) {
            // Update GarbageLength
            vector<FieldLength*> fieldLength = checkField->fieldLength_;
            for (vector<FieldLength*>::iterator j = fieldLength.begin(); j != fieldLength.end(); j++) {
                // Not sure if this is correct
                (*i)->garbageLength_.push_back(*j);
            }
            // Update NextField
            (*i)->nextField_ = checkField->nextField_;
            // I do not think we need to update preceers with this kind of approach.

            // Remove the unused entry from the table
            //fieldTable_.erase(i++);
            // I think we can get away without doing this, but if not put in the correct statement.
        }
    }
	return 0;
}


//generate code for fast parser, given the fully built field table
//This is the only function that writes code to output files
int FieldTable::GenCode(Output* out_h, Output* out_cc)	{
	//RearrangeEntry();
	GenCodeForRegexMatcherDeclaration(out_cc);
	GenCodeForBasicDefinition(out_h);
	GenCodeForClassDeclaration(out_h, out_cc);
	GenCodeForClassImplementation(out_cc);
	GenCodeForFieldTable(out_h, out_cc);

	return 0;
}

int FieldTable::GenCodeForRegexMatcherDeclaration(Output* out_cc)	//declare regex matcher in .cc file
{
	for (vector<FieldEntry*>::iterator it = fieldTable_.begin() ; it < fieldTable_.end() ; it++)	{
		Type* fieldtype = (*it)->metadata_.type_;
		if (fieldtype->tot() == Type::STRING)	{
			StringType* stringfieldtype = static_cast<StringType*>(fieldtype);
			if (stringfieldtype->type_ == StringType::REGEX)	{
				RegEx* curregex = stringfieldtype->regex_;
				//out_cc->println("pcre* regexmatcher_%d;", it - fieldTable_.begin());
				out_cc->println("RegExMatcher regexmatcher_%d(\"%s\");", it - fieldTable_.begin(), curregex->str().c_str());
			}
		}
	}
	out_cc->println("");
	return 0;
}
	
int FieldTable::GenCodeForBasicDefinition(Output* out_h)	//gen code for basic definition
{	
	out_h->println("class Metadata{");
	out_h->println("public:");
	out_h->inc_indent();
	out_h->println("Metadata(char* initname) {");
	out_h->inc_indent();
	out_h->println("name = initname;");
	out_h->dec_indent();
	out_h->println("}\n");
	out_h->println("string name;");
	out_h->dec_indent();
	out_h->println("};\n");

	out_h->println("enum FieldType{");
	out_h->inc_indent();
	out_h->println("TYPE1, ");
	out_h->println("TYPE2, ");
	out_h->println("NOT_USED,");
	out_h->dec_indent();
	out_h->println("};\n");
	
	return 0;
}

int FieldTable::GenCodeForFuncInSpec(Output* out_h, Output* out_cc)
{
	foreach (i, DeclList, Decl::decl_list_)	//find the root node
	{
		Decl *decl = *i;
		//current_decl_id = decl->id();
									//find the FlowDecl
		if (decl->decl_type() == Decl::FLOW)	{
			FlowDecl* flowdecl = static_cast<FlowDecl*>(decl);

			foreach (j, FunctionList, flowdecl->functions_)
			{
				(*j)->GenCode(out_h, out_cc);
			}
		}

	}
	return 0;
}
int FieldTable::GenCodeForClassDeclaration(Output* out_h, Output* out_cc)	//gen code for fast parser class declaration
{
	out_h->println("class FastParser {");
	out_h->println("public:");
	out_h->inc_indent();

	out_h->println("enum ParserStatus { NORMAL, INCOMPLETE_FIELD, BAD, PARSING_COMPLETE, REST_OF_FLOW};");
	FlowDecl* flowdecl = NULL;
	foreach (i, DeclList, Decl::decl_list_)	//find FlowDecl
	{
		Decl *decl = *i;
		//current_decl_id = decl->id();
									//find the FlowDecl
		if (decl->decl_type() == Decl::FLOW)	{
			flowdecl = static_cast<FlowDecl*>(decl);
		}
	}
	assert(flowdecl);
	
	//gen code for constructor
	//out_h->println("FastParser(FlowBuffer* buffer_, const_byteptr start_ = NULL) {");
	out_h->println("FastParser(SimpleFlowBuffer* buffer_, const_byteptr start_ = NULL, void* param_ = NULL) {");
	out_h->inc_indent();
	//gen code for the contructor from FlowDecl
	out_h->println("//member variables in FlowDecl");
	for (AnalyzerHelperList::iterator itinit = flowdecl->constructor_helpers_->begin() ; itinit < flowdecl->constructor_helpers_->end() ; itinit++)	{
		AnalyzerHelper* inithelper = static_cast<AnalyzerHelper*>(*itinit);
		if (inithelper->helper_type() == AnalyzerHelper::INIT_CODE)	{
			inithelper->code()->GenCode(out_h, flowdecl->env());
		}
	}
	out_h->println("this->flowbuffer = buffer_;");
	out_h->println("this->startptr = start_;");
	out_h->println("this->tablepointer = 0;");
	out_h->println("this->status = NORMAL;");
	out_h->println("this->field_length_left = 0;");
	out_h->println("this->param = param_;");
	out_h->dec_indent();
	out_h->println("}\n");

	//gen code for destructor
	out_h->println("~FastParser() {");
	out_h->inc_indent();
	out_h->println("delete flowbuffer;");
	out_h->println("header_name_field.free();");	//adhoc solution. need to figure out a generic way
	for (AnalyzerHelperList::iterator itdes = flowdecl->destructor_helpers_->begin() ; itdes < flowdecl->destructor_helpers_->end() ; itdes++)	{
		AnalyzerHelper* deshelper = static_cast<AnalyzerHelper*>(*itdes);
		if (deshelper->helper_type() == AnalyzerHelper::CLEANUP_CODE)	{
			deshelper->code()->GenCode(out_h, flowdecl->env());
		}
	}
	out_h->println("if (param)	{");
	out_h->inc_indent();
	out_h->println("delete param;");
	out_h->dec_indent();
	out_h->println("}");
	out_h->dec_indent();
	out_h->println("}\n");

	out_h->println("void* getParam()	{");
	out_h->inc_indent();
	out_h->println("return param;");
	out_h->dec_indent();
	out_h->println("}");

	out_h->println("inline void Reset()	{");
	out_h->inc_indent();
	out_h->println("this->tablepointer = 0;");
	out_h->println("this->status = NORMAL;");
	out_h->println("this->startptr = flowbuffer->begin();");
	out_h->println("this->content_length_ = 0;");
	out_h->println("this->delivery_mode_ = UNKNOWN_DELIVERY_MODE;");
	out_h->println("this->field_length_left = 0;");
	out_h->println("this->flowbuffer->data_begin = this->flowbuffer->_buf;");
	out_h->println("this->flowbuffer->orig_end = this->flowbuffer->_buf;");
	out_h->println("this->flowbuffer->_size = 0;");
	out_h->dec_indent();
	out_h->println("}");

	out_h->println("int FuncParsingPDU();	//the function to parse one PDU");	//the function to parse one PDU
	out_h->println("void FuncParsingFlow();	//the function to parse one flow");	//the function to parse one flow

	//gen code for func in protocol specification
	GenCodeForFuncInSpec(out_h, out_cc);

	//gen code for functions declaration
	out_h->println("//declaration of crucial functions");
	out_h->println("static Metadata metadata[%d];", fieldTable_.size());
	out_h->println("static FieldType fieldtype[%d];", fieldTable_.size());
	out_h->println("");
	
	//gen code for context variable declaration
	out_h->println("//declaration of context variables");
	GenCodeForContextDeclaration(out_h);

	//gen code for variables in FlowDecl
	out_h->println("//declaration for context variables in FlowDecl declaration");
	for (AnalyzerHelperList::iterator itmem = flowdecl->helpers_->begin() ; itmem < flowdecl->helpers_->end() ; itmem++)	{
		AnalyzerHelper* memhelper = static_cast<AnalyzerHelper*>(*itmem);
		if (memhelper->helper_type() == AnalyzerHelper::MEMBER_DECLS)	{
			memhelper->code()->GenCode(out_h, flowdecl->env());
		}
	}
	
	//gen code for other variables
	out_h->println("//declaration of parsing necessary variables");
	//out_h->println("FlowBuffer* flowbuffer;");
	out_h->println("SimpleFlowBuffer* flowbuffer;");
	out_h->println("const_byteptr startptr;");
	out_h->println("int field_length;");
	out_h->println("int tablepointer;");
	out_h->println("ParserStatus status;");
	out_h->println("unsigned int field_length_left;	//this variable is used to handle incremental parsing within a field");
	out_h->println("void* param;	//the variable asked by Gao");

	out_h->dec_indent();
	out_h->println("};	\t//end declaration of past parser class\n");

	out_h->println("typedef FastParser *fast_parser_t;\n");

	/*********** generate code for connection parser **********/
	out_h->println("class ConnParser {	");
	out_h->println("public:");
	out_h->inc_indent();
	out_h->println("ConnParser()	{");
	out_h->inc_indent();
	out_h->println("server = new FastParser(new SimpleFlowBuffer());");
	out_h->println("client = new FastParser(new SimpleFlowBuffer());");
	out_h->dec_indent();
	out_h->println("}\n");
	out_h->println("~ConnParser()	{");
	out_h->inc_indent();
	out_h->println("delete server;");
	out_h->println("delete client;");
	out_h->dec_indent();
	out_h->println("}\n");
	out_h->println("fast_parser_t server;");
	out_h->println("fast_parser_t client;");
	out_h->dec_indent();
	out_h->println("};\n");
	out_h->println("typedef ConnParser *conn_parser_t;\n");
	
	return 0;
}

int FieldTable::GenCodeForContextDeclaration(Output* out_h)	//gen code for context variable declaration
{
	assert(globalvarname.size() == globalvartype.size());
	vector<ID*>::iterator itname = globalvarname.begin();
	vector<Type*>::iterator ittype = globalvartype.begin();

	for (; itname < globalvarname.end() ; itname++)	{
		if ((*ittype)->tot() == Type::PARAMETERIZED)	{
			ParameterizedType* paramtype = static_cast<ParameterizedType*>(*ittype);
			out_h->println("%s %s;", paramtype->type_id_->Name(), (*itname)->Name());
		}
		else if ((*ittype)->tot() == Type::EXTERN)	{
			ExternType* externtype = static_cast<ExternType*>(*ittype);
			out_h->println("%s %s;", externtype->DataTypeStr().c_str(), (*itname)->Name());
		}
		else if ((*ittype)->tot() == Type::BUILTIN)	{
			BuiltInType* builtintype = static_cast<BuiltInType*>(*ittype);
			out_h->println("%s %s;", basic_ctype_name[builtintype->bit_type()], (*itname)->Name());
		}
		else	{
			cout <<"context var type is unexpected!, exit..."<<endl;
			cout <<"the id is "<<(*itname)->Name()<<endl;
			cout <<(*ittype)->tot()<<endl;
			exit(1);
			}
		ittype++;
	}
	out_h->println("");
	
	return 0;
}

//#if 0
int FieldTable::GenCodeForClassImplementation(Output* out_cc)	//gen code for class implementation
{

	out_cc->println("void FastParser::FuncParsingFlow()");
	out_cc->println("{");
	out_cc->inc_indent();

	out_cc->println("this->startptr = flowbuffer->begin();");
	out_cc->println("FuncParsingPDU();");

	out_cc->println("while (this->status== FastParser::PARSING_COMPLETE)	{");
	out_cc->inc_indent();
	//out_cc->println("parser->Reset();");

	out_cc->println("this->tablepointer = 0;");
	out_cc->println("this->status = NORMAL;");
	out_cc->println("this->startptr = flowbuffer->begin();");
	out_cc->println("this->content_length_ = 0;");
	out_cc->println("this->delivery_mode_ = UNKNOWN_DELIVERY_MODE;");
	out_cc->println("this->field_length_left = 0;");
	
	out_cc->println("FuncParsingPDU();");
	out_cc->dec_indent();
	out_cc->println("}\n");

	out_cc->dec_indent();
	out_cc->println("}\n");
	
	return 0;
}
//#endif 

int FieldTable::GenCodeForFieldTable(Output* out_h, Output* out_cc)
{	
	DebugOutputContextUpdate();

	GenCodeForAllInOneParsing(out_h, out_cc);
	
	for (vector<FieldEntry*>::iterator it = fieldTable_.begin(); it < fieldTable_.end() ; it++)	//gen function for every field
	{
		//GenCodeForParsingField(out_cc, it);	
		//cout <<"complete gencode for current field"<<endl;
	}
	
	GenCodeInitMetadata(out_h, out_cc);
	GenCodeInitFieldType(out_h, out_cc);
	
	return 0;
}

int FieldTable::GenCodeForAllInOneParsing(Output* out_h, Output* out_cc)
{
	out_cc->println("int FastParser::FuncParsingPDU()");
	out_cc->println("{");
	out_cc->inc_indent();

	out_cc->println("switch (status)	{");
	out_cc->inc_indent();
	//out_cc->println("case INCOMPLETE_FIELD: status = NORMAL; break;");
	out_cc->println("case BAD: return tablepointer; break;");
	out_cc->println("case PARSING_COMPLETE: return -1;");
	out_cc->println("default: break;");
	out_cc->dec_indent();
	out_cc->println("}\n");

	out_cc->println("switch (tablepointer)	{");
	out_cc->inc_indent();
	for (int pointeridx = 0; pointeridx < fieldTable_.size() ; pointeridx++)	{
		out_cc->println("case %d: goto parse_field_%d; break;", pointeridx, pointeridx);
	}
	out_cc->println("case -1: status = PARSING_COMPLETE; return -1; break;");
	out_cc->println("default: status = BAD; return 0; break;");
	out_cc->dec_indent();
	out_cc->println("}\n");
	
	for (vector<FieldEntry*>::iterator it = fieldTable_.begin() ; it < fieldTable_.end() ; it++)	{
		out_cc->dec_indent();
		out_cc->println("parse_field_%d:", it - fieldTable_.begin());
		out_cc->inc_indent();
		vector<FieldLength*> currentFieldLength = (*it)->fieldLength_;
		Type* fieldtype = (*it)->metadata_.type_;
		//if (fieldtype->tot() == Type::STRING)	{
		//StringType* stringfieldtype = static_cast<StringType*>(fieldtype);
		//if (stringfieldtype->type_ == StringType::CSTR)	{
		bool cleanoneline = false;
		bool advanceptr = true;
		for (vector<FieldLength*>::iterator ik = currentFieldLength.begin() ; ik < currentFieldLength.end() ; ik++)	{	
			
			if ((*ik)->lengthType_ == FieldLength::CONSTNUMBER)	{
				ConstFieldLength* constfieldlength_ = static_cast<ConstFieldLength*>(*ik);

				if (fieldtype->tot() == Type::STRING || constfieldlength_->length_>0)	{	//handling string of constant length
					out_cc->println("if (status == NORMAL)	{	//handling starting of a new field");
					out_cc->inc_indent();
					out_cc->println("field_length_left = %d;", constfieldlength_->length_);
					out_cc->dec_indent();
					out_cc->println("}");
					out_cc->println("if (flowbuffer->data_begin+field_length_left> flowbuffer->orig_end) {");
					out_cc->inc_indent();
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");
					out_cc->println("field_length_left-=field_length;");
					out_cc->println("status = INCOMPLETE_FIELD;");

					//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

					out_cc->println("//update context");	//update context, although field incomplete
	
					vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
					for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
					{
						out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
					}
					out_cc->println("flowbuffer->data_begin+=field_length;");
					out_cc->println("startptr=flowbuffer->data_begin;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
					out_cc->println("else {");
					out_cc->inc_indent();
					out_cc->println("field_length = field_length_left;");
					out_cc->println("field_length_left-=field_length;");
					out_cc->dec_indent();
					out_cc->println("}");
					
				}
				/*else if (constfieldlength_->length_>0)	{
					out_cc->println("field_length=%d;", constfieldlength_->length_);
							
					out_cc->println("if (flowbuffer->data_begin+field_length > flowbuffer->orig_end) {");
					out_cc->inc_indent();
					out_cc->println("status = INCOMPLETE_FIELD;");
					//out_cc->println("flowbuffer->data_begin = flowbuffer->orig_end;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
				}*/
				else	{
					out_cc->println("field_length = 0;");
					advanceptr = false;
					if ((*it)->metadata_.id_->name == "array_header" && (*it)->oneline_)	{
						out_cc->println("if (flowbuffer->data_begin < flowbuffer->orig_end-2)	{");		//newly modified
						out_cc->inc_indent();
						out_cc->println("flowbuffer->TestOneline();");
						out_cc->dec_indent();
						out_cc->println("}");
						//out_cc->println("else if (flowbuffer->data_begin < flowbuffer->expected_end)	{");
						//out_cc->inc_indent();
						//out_cc->println("status = INCOMPLETE_FIELD;");
						//out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
						//out_cc->dec_indent();
						//out_cc->println("}");
						out_cc->println("else	{");
						//out_cc->println("flowbuffer->line_length = 0;");
						out_cc->println("status = INCOMPLETE_FIELD;");	//newly modified
						out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin()); //newly modified
						out_cc->inc_indent();
						out_cc->dec_indent();
						out_cc->println("}");
						cleanoneline = true;
					}
				}
			}
			else if ((*ik)->lengthType_ == FieldLength::EXPRESSION)	{
				ExpressionFieldLength* expressionfieldlength_ = static_cast<ExpressionFieldLength*>(*ik);
				if (fieldtype->tot() == Type::STRING)	{	//handling string of constant length
					out_cc->println("if (status == NORMAL)	{	//handling starting of a new field");
					out_cc->inc_indent();
					out_cc->println("field_length_left = %s;", ReComputeExpr(expressionfieldlength_->expr_, this).c_str());
					out_cc->dec_indent();
					out_cc->println("}");
					out_cc->println("if (flowbuffer->data_begin+field_length_left> flowbuffer->orig_end) {");
					out_cc->inc_indent();
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");
					out_cc->println("field_length_left-=field_length;");
					out_cc->println("status = INCOMPLETE_FIELD;");

					//out_cc->println("testoutput(flowbuffer, field_length);");	//test output


					out_cc->println("//update context");	//update context, although field incomplete
	
					vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
					for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
					{
						out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
					}
					out_cc->println("flowbuffer->data_begin+=field_length;");
					out_cc->println("startptr=flowbuffer->data_begin;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
					out_cc->println("else {");
					out_cc->inc_indent();
					out_cc->println("field_length = field_length_left;");
					out_cc->println("field_length_left-=field_length;");
					out_cc->dec_indent();
					out_cc->println("}");
				}
				else	{					
					out_cc->println("field_length = %s;", ReComputeExpr(expressionfieldlength_->expr_, this).c_str());
					out_cc->println("if (field_length < 0) {");
					out_cc->inc_indent();
					out_cc->println("status = BAD;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
					out_cc->println("else if (flowbuffer->data_begin+field_length > flowbuffer->orig_end)	{");
					out_cc->inc_indent();
					out_cc->println("status = INCOMPLETE_FIELD;");

					//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
				}
			}
			else if ((*ik)->lengthType_ == FieldLength::REGEXMATCHING)	{
				RegExFieldLength* regexfieldlength = static_cast<RegExFieldLength*>(*ik);
				out_cc->println("field_length = regexmatcher_%d.MatchPrefix(flowbuffer->data_begin, flowbuffer->orig_end - flowbuffer->data_begin);", it - fieldTable_.begin());
				out_cc->println("if (field_length < 0) {");
				out_cc->inc_indent();
				out_cc->println("if (flowbuffer->orig_end - flowbuffer->data_begin < 20) {");	//decide the unmatch is caused by incomplete data or error
				out_cc->inc_indent();
				out_cc->println("status = INCOMPLETE_FIELD;");
				out_cc->dec_indent();
				out_cc->println("}");
				out_cc->println("else {");
				out_cc->inc_indent();
				out_cc->println("status = BAD;");
				out_cc->dec_indent();
				out_cc->println("}");
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
				if (!(*it)->oneline_cleanup_)	{
					out_cc->println("if (flowbuffer->data_begin+field_length >= flowbuffer->orig_end)	{");
					out_cc->inc_indent();
					out_cc->println("status = INCOMPLETE_FIELD;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
				}
				else {
					out_cc->println("if (flowbuffer->data_begin+field_length +1 >= flowbuffer->orig_end)	{");
					out_cc->inc_indent();
					out_cc->println("status = INCOMPLETE_FIELD;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
					cleanoneline = true;
				}
			}
			else if ((*ik)->lengthType_ == FieldLength::ONELINE)	{
				assert(fieldtype->tot() == Type::STRING);		//handling string with &oneline
				out_cc->println("field_length = flowbuffer->Oneline();");
				out_cc->println("if (flowbuffer->data_begin+field_length +1>= flowbuffer->orig_end)	{	//allow the ending CRLF");
				out_cc->inc_indent();
				out_cc->println("status = INCOMPLETE_FIELD;");

				//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

				//don't handle incremental parsing in oneline field
				/*out_cc->println("//update context");	//update context, although field incomplete
				vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
				for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
				{
					out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
				}
				out_cc->println("flowbuffer->data_begin += field_length;");*/
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
				cleanoneline = true;
			}
			else if ((*ik)->lengthType_ == FieldLength::RESTOFDATA)	{
				if (fieldtype->tot() == Type::STRING)	{	//handling string with rest_of_data
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");					

					out_cc->println("//update context");	//update context, although field incomplete
					out_cc->println("status = REST_OF_FLOW;");

					//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

					vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
					for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
					{
						out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
					}
					out_cc->println("flowbuffer->data_begin+=field_length;");
					out_cc->println("startptr=flowbuffer->data_begin;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				}
				else	{
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");
				}
			}
			else if ((*ik)->lengthType_ == FieldLength::RESTOFFLOW)	{	//need to figure out the difference between RESTOFDATA and RESTOFFLOW
				if (fieldtype->tot() == Type::STRING)	{	//handling string with rest_of_flow
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");					

					out_cc->println("//update context");	//update context, although field incomplete
					out_cc->println("status = REST_OF_FLOW;");

					//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

					vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
					for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
					{
						out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
					}
					out_cc->println("flowbuffer->data_begin+=field_length;");
					out_cc->println("startptr=flowbuffer->data_begin;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				}
				else	{
					out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");
				}
			}
			else {
				out_cc->println("//unhandled field length type");
				cout <<"unhandled field length type"<<endl;
				assert(0);
			}
			
		}
		

		//out_cc->println("//oneline = %d;", (*it)->oneline_);
		//out_cc->println("//oneline_transfered_ = %d;", (*it)->oneline_transfered_);
		//out_cc->println("//oneline_cleanup_ = %d;", (*it)->oneline_cleanup_);
		//out_cc->println("testoutput(flowbuffer, field_length);");	//test output

		out_cc->println("//update context");
		out_cc->println("status = NORMAL;"); 
		vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
		for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
		{
			out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
		}
		out_cc->println("");

		if (advanceptr)	{
			out_cc->println("flowbuffer->data_begin+=field_length;");
			out_cc->println("startptr = flowbuffer->data_begin;");

			//discard already parsed data
			//out_cc->println("flowbuffer->pop_front(field_length);");
			//out_cc->println("startptr = flowbuffer->data_begin;");
		}


		if (cleanoneline)	{
			out_cc->println("if (flowbuffer->CleanUpNewLine())	{");
			out_cc->inc_indent();
			//out_cc->println("printf(\"%cc%cc\", '\\r', '\\n');", '%', '%');	//test output
			out_cc->dec_indent();
			out_cc->println("}");
		}
		if (!cleanoneline && (*it)->oneline_cleanup_)	{
			out_cc->println("flowbuffer->EatLine();");
		}
		//out_cc->println("printf(\"the buffer length is %cd : \", flowbuffer->length());", '%');
		out_cc->println("//compute garbage length");
		out_cc->println("//no garbage length in the current implementation\n");

		out_cc->println("//compute next field");

		if ((*it)->nextField_)	{
			(*it)->nextField_->GenCode(out_cc, this, it - fieldTable_.begin());
			}
		else	{
			out_cc->println("tablepointer = -1;");
			out_cc->println("goto parse_PDU_complete;");
		}
	}

	out_cc->println("parse_PDU_complete:");
	out_cc->println("status = PARSING_COMPLETE;");
	out_cc->println("return -1;");

	out_cc->dec_indent();
	out_cc->println("}\n");
	return 0;
}

#if 0
int FieldTable::GenCodeForAllInOneParsing(Output* out_h, Output* out_cc)
{
	out_cc->println("int FastParser::FuncParsingPDU()");
	out_cc->println("{");
	out_cc->inc_indent();

	out_cc->println("switch (status)	{");
	out_cc->inc_indent();
	out_cc->println("case INCOMPLETE_FIELD: status = NORMAL; break;");
	out_cc->println("case BAD: return tablepointer; break;");
	out_cc->println("case PARSING_COMPLETE: return -1;");
	out_cc->println("default: break;");
	out_cc->dec_indent();
	out_cc->println("}\n");

	out_cc->println("switch (tablepointer)	{");
	out_cc->inc_indent();
	for (int pointeridx = 0; pointeridx < fieldTable_.size() ; pointeridx++)	{
		out_cc->println("case %d: goto parse_field_%d; break;", pointeridx, pointeridx);
	}
	out_cc->println("case -1: status = PARSING_COMPLETE; return -1; break;");
	out_cc->println("default: status = BAD; return 0; break;");
	out_cc->dec_indent();
	out_cc->println("}\n");
	
	for (vector<FieldEntry*>::iterator it = fieldTable_.begin() ; it < fieldTable_.end() ; it++)	{
		out_cc->dec_indent();
		out_cc->println("parse_field_%d:", it - fieldTable_.begin());
		out_cc->inc_indent();
		vector<FieldLength*> currentFieldLength = (*it)->fieldLength_;
		bool cleanoneline = false;
		bool advanceptr = true;
		for (vector<FieldLength*>::iterator ik = currentFieldLength.begin() ; ik < currentFieldLength.end() ; ik++)	{	
			
			if ((*ik)->lengthType_ == FieldLength::CONSTNUMBER)	{
				ConstFieldLength* constfieldlength_ = static_cast<ConstFieldLength*>(*ik);
				if (constfieldlength_->length_>0)	{
					out_cc->println("field_length=%d;", constfieldlength_->length_);
							
					out_cc->println("if (flowbuffer->data_begin+field_length > flowbuffer->orig_end) {");
					out_cc->inc_indent();
					out_cc->println("status = INCOMPLETE_FIELD;");
					//out_cc->println("flowbuffer->data_begin = flowbuffer->orig_end;");
					out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
					out_cc->dec_indent();
					out_cc->println("}");
				}
				else	{
					out_cc->println("field_length = 0;");
					advanceptr = false;
					if ((*it)->metadata_.id_->name == "array_header" && (*it)->oneline_)	{
						out_cc->println("flowbuffer->TestOneline();");
						cleanoneline = true;
					}
				}
			}
			else if ((*ik)->lengthType_ == FieldLength::EXPRESSION)	{
				//cout <<"length is an expression"<<endl;
				ExpressionFieldLength* expressionfieldlength_ = static_cast<ExpressionFieldLength*>(*ik);
				out_cc->println("field_length = %s;", ReComputeExpr(expressionfieldlength_->expr_, this).c_str());
				//out_cc->println("if (flowbuffer->data_begin+field_length > flowbuffer->orig_end) {");
				out_cc->println("if (field_length < 0) {");
				out_cc->inc_indent();
				out_cc->println("status = BAD;");
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
				out_cc->println("else if (flowbuffer->data_begin+field_length > flowbuffer->orig_end)	{");
				out_cc->inc_indent();
				out_cc->println("status = INCOMPLETE_FIELD;");
				//out_cc->println("flowbuffer->data_begin = flowbuffer->orig_end;");
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
			}
			else if ((*ik)->lengthType_ == FieldLength::REGEXMATCHING)	{
				RegExFieldLength* regexfieldlength = static_cast<RegExFieldLength*>(*ik);
				out_cc->println("field_length = regexmatcher_%d.MatchPrefix(flowbuffer->data_begin, flowbuffer->orig_end - flowbuffer->data_begin);", it - fieldTable_.begin());
				out_cc->println("if (field_length < 0) {");
				out_cc->inc_indent();
				out_cc->println("status = BAD;");
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
			}
			else if ((*ik)->lengthType_ == FieldLength::ONELINE)	{
				out_cc->println("field_length = flowbuffer->Oneline();");
				out_cc->println("if (flowbuffer->data_begin+field_length >= flowbuffer->orig_end)	{");
				out_cc->inc_indent();
				out_cc->println("status = INCOMPLETE_FIELD;");
				out_cc->println("flowbuffer->data_begin = flowbuffer->orig_end;");
				out_cc->println("return %d; //return a positive number means parsing error on this field", it - fieldTable_.begin());
				out_cc->dec_indent();
				out_cc->println("}");
				cleanoneline = true;
			}
			else if ((*ik)->lengthType_ == FieldLength::RESTOFDATA)	{
				out_cc->println("field_ength = flowbuffer->orig_end - flowbuffer->data_begin;");
			}
			else if ((*ik)->lengthType_ == FieldLength::RESTOFFLOW)	{	//need to figure out the difference between RESTOFDATA and RESTOFFLOW
				out_cc->println("field_length = flowbuffer->orig_end - flowbuffer->data_begin;");
			}
			else {
				out_cc->println("//unhandled field length type");
				cout <<"unhandled field length type"<<endl;
				assert(0);
			}
			
		}
		//temp output
		/*out_cc->println("if (field_length > 0)	{");
		//out_cc->println("printf(\"the parsed field is %d, the content is :\");", it - fieldTable_.begin());
		out_cc->println("for (int i = 0; i < field_length ; i++)	{");
		out_cc->inc_indent();
		//out_cc->println("if (*(flowbuffer->data_begin+i) == 10)	{");
		//out_cc->println("printf(\"%cc\", (char)13);", '%');
		//out_cc->println("}");
		out_cc->println("printf(\"%cc\", *(flowbuffer->data_begin+i));", '%');
		out_cc->dec_indent();
		out_cc->println("}");
		//out_cc->println("printf(\"%cc\\n\", (char)13);", '%');
		out_cc->println("printf(\"\\n\");");
		out_cc->println("}");*/
			
		out_cc->println("//update context");
	
		vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
		for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
		{
			out_cc->println("%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
		}
		out_cc->println("");

		if (advanceptr)	{
			out_cc->println("flowbuffer->data_begin+=field_length;");
			out_cc->println("startptr = flowbuffer->data_begin;");
		}

		if (cleanoneline)	{
			out_cc->println("flowbuffer->CleanUpNewLine();");
		}
		if (!cleanoneline && (*it)->oneline_cleanup_)	{
			out_cc->println("flowbuffer->EatLine();");
		}
		//out_cc->println("printf(\"the buffer length is %cd : \", flowbuffer->length());", '%');
		out_cc->println("//compute garbage length");
		out_cc->println("//no garbage length in the current implementation\n");

		out_cc->println("//compute next field");

		if ((*it)->nextField_)	{
			(*it)->nextField_->GenCode(out_cc, this, it - fieldTable_.begin());
			}
		else	{
			out_cc->println("goto parse_PDU_complete;");
		}
	}

	out_cc->println("parse_PDU_complete:");
	out_cc->println("return -1;");

	out_cc->dec_indent();
	out_cc->println("}\n");
	return 0;
}
#endif

int FieldTable::GenCodeForParsingField(Output* out_h, vector<FieldEntry*>::iterator it)		//gen function to do parsing for one field
{
	out_h->println("int FuncParsingField_%d(FastParser* parserentity, const_byteptr& fieldstart)", it - fieldTable_.begin());	//gen func declaration
	out_h->println("{");
	out_h->inc_indent();

	out_h->println("//parsing net field length");
	//out_h->println("int length;	//initialize the length of the field");
	vector<FieldLength*> currentFieldLength = (*it)->fieldLength_;
	for (vector<FieldLength*>::iterator ik = currentFieldLength.begin() ; ik < currentFieldLength.end() ; ik++)	{	
		//cout <<"start produce one length "<<endl;
		if ((*ik)->lengthType_ == FieldLength::CONSTNUMBER)	{
			ConstFieldLength* constfieldlength_ = static_cast<ConstFieldLength*>(*ik);
			if (constfieldlength_->length_>0)	{
				out_h->println("parserentity->field_length=%d;", constfieldlength_->length_);
							
				out_h->println("if (parserentity->flowbuffer->data_begin+parserentity->field_length > parserentity->flowbuffer->orig_end) {");
				out_h->inc_indent();
				out_h->println("fieldstart = NULL;");
				out_h->println("return -1; //return -1 indicates not enough data");
				out_h->dec_indent();
				out_h->println("}");	
			}
			else	{
				out_h->println("parserentity->field_length = 0;");
				}
		}
		else if ((*ik)->lengthType_ == FieldLength::EXPRESSION)	{
			//cout <<"length is an expression"<<endl;
			ExpressionFieldLength* expressionfieldlength_ = static_cast<ExpressionFieldLength*>(*ik);
			out_h->println("parserentity->field_length = (%s);", ReComputeExpr(expressionfieldlength_->expr_, this).c_str());
			out_h->println("if (parserentity->flowbuffer->data_begin+parserentity->field_length > parserentity->flowbuffer->orig_end) {");
			out_h->inc_indent();
			out_h->println("fieldstart = NULL;");
			out_h->println("return -1; //return -1 indicates not enough data");
			out_h->dec_indent();
			out_h->println("}");
		}
		else if ((*ik)->lengthType_ == FieldLength::REGEXMATCHING)	{
			RegExFieldLength* regexfieldlength = static_cast<RegExFieldLength*>(*ik);
			out_h->println("parserentity->field_length = regexmatcher_%d.MatchPrefix(parserentity->flowbuffer->data_begin, parserentity->flowbuffer->orig_end - parserentity->flowbuffer->data_begin);", it - fieldTable_.begin());
			out_h->println("if (parserentity->field_length < 0) {");
			out_h->inc_indent();
			out_h->println("fieldstart = NULL;");
			out_h->println("parserentity->tablepointer = -2; //indicating quiting parsing, might need modification");
			out_h->println("return -2;	//return -2 indicates parsing error");
			out_h->dec_indent();
			out_h->println("}");
		}
		else if ((*ik)->lengthType_ == FieldLength::ONELINE)	{
			out_h->println("parserentity->field_length = parserentity->flowbuffer->Oneline();");
			/*out_h->println("if ( length < 0 ) {");
			out_h->inc_indent();
			out_h->println("fieldstart = NULL;");
			//out_h->println("throw ExceptionInvalidStringLength(\"./http-protocol.pac:65\", length);");
			out_h->println("return -1;");
			out_h->dec_indent();
			out_h->println("}");*/
		}
		else if ((*ik)->lengthType_ == FieldLength::RESTOFDATA)	{
			out_h->println("parserentity->field_length = parserentity->flowbuffer->orig_end - parserentity->flowbuffer->data_begin;");
			/*out_h->println("if ( length < 0 ) {");
			out_h->inc_indent();
			out_h->println("fieldstart = NULL;");
			//out_h->println("throw ExceptionInvalidStringLength(\"./http-protocol.pac:65\", length);");
			out_h->println("return -1;");
			out_h->dec_indent();
			out_h->println("}");*/
		}
		else if ((*ik)->lengthType_ == FieldLength::RESTOFFLOW)	{	//need to figure out the difference between RESTOFDATA and RESTOFFLOW
			out_h->println("parserentity->field_length = parserentity->flowbuffer->orig_end - parserentity->flowbuffer->data_begin;");
			/*out_h->println("if ( length < 0 ) {");
			out_h->inc_indent();
			out_h->println("fieldstart = NULL;");
			//out_h->println("throw ExceptionInvalidStringLength(\"./http-protocol.pac:65\", length);");
			out_h->println("return -1;");
			out_h->dec_indent();
			out_h->println("}");*/
		}
		else {
			out_h->println("//unhandled field length type");
			cout <<"unhandled field length type"<<endl;
		}
		
	}

	out_h->println("fieldstart = parserentity->flowbuffer->data_begin;");
	out_h->println("//update context");
	
	//out_h->println("parserentity->field_length = length;");
	vector<ContextUpdateAfterParse*> v_contextupdate = (*it)->contextupdateafterparse;
	for (vector<ContextUpdateAfterParse*>::iterator itcontext = v_contextupdate.begin() ; itcontext < v_contextupdate.end() ; itcontext++)
	{
		out_h->println("parserentity->%s = %s;", (*itcontext)->varid->Name(), ReComputeExpr((*itcontext)->updateexpr, this).c_str());
	}
	out_h->println("");

	out_h->println("parserentity->flowbuffer->data_begin+=parserentity->field_length;");
	out_h->println("if (parserentity->flowbuffer->line_mode)	{");
	out_h->inc_indent();
	out_h->println("parserentity->flowbuffer->CleanUpNewLine();");
	out_h->dec_indent();
	out_h->println("}");
	out_h->println("//compute garbage length");
	out_h->println("//no garbage length in the current implementation\n");

	out_h->println("//compute next field");

	if ((*it)->nextField_)	{
		(*it)->nextField_->GenCode(out_h, this, it - fieldTable_.begin());
		}
	else	{
		out_h->println("parserentity->tablepointer = -1;");
	}

	out_h->println("return parserentity->field_length;");
	out_h->dec_indent();
	out_h->println("}\n");
	
	return 0;
}

int FieldTable::GenCodeForFieldName(Output* out_h, Output* out_cc, vector<FieldEntry*>::iterator it)	//gen function to return the name of field
{
	vector<FieldEntry*>::iterator ik;
	for (ik = fieldTable_.begin() ; ik < it ; ik++)	{
		if ((*ik)->metadata_.id_->name == (*it)->metadata_.id_->name)	{
			break;
		}
	}

	if (ik < it)	{
		return -1;
		}

	out_h->println("int %s();", (*it)->metadata_.id_->Name());	//gen forward declaration
	out_cc->println("int %s()", (*it)->metadata_.id_->Name());
	out_cc->println("{");
	out_cc->inc_indent();
	out_cc->println("int index = 0;");
	out_cc->println("int tablesize = %d;", fieldTable_.size());
	out_cc->println("for (; index < tablesize ; index++) {");
	out_cc->inc_indent();
	out_cc->println("if (fieldtable[index].metadata.name == \"%s\")	{", (*it)->metadata_.id_->Name());
	out_cc->inc_indent();
	out_cc->println("break;");
	out_cc->dec_indent();
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("}");
	out_cc->println("if (index < tablesize)	{");
	out_cc->inc_indent();
	out_cc->println("return index;");
	out_cc->dec_indent();
	out_cc->println("}");
	out_cc->println("else	{");
	out_cc->inc_indent();
	out_cc->println("return -1;");
	out_cc->dec_indent();
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("}");
	out_cc->println("");
	
	return 0;
}

int FieldTable::GenCodeInitMetadata(Output* out_h, Output* out_cc)	//gen function to initial metadata column
{
	vector<FieldEntry*>::iterator it = fieldTable_.begin();
	out_cc->print("Metadata FastParser::metadata[%d] = {Metadata(\"%s\")", fieldTable_.size(), (*it)->metadata_.id_->Name());
	it++;
	for (; it < fieldTable_.end() ; it++)	{
		out_cc->print(", Metadata(\"%s\")", (*it)->metadata_.id_->Name());
	}
	out_cc->print("};\n");
	out_cc->println("");
	
	return 0;
}

int FieldTable::GenCodeInitFieldType(Output* out_h, Output* out_cc)
{
	out_cc->print("FieldType FastParser::fieldtype[%d] = {", fieldTable_.size());

	for (vector<FieldEntry*>::iterator it = fieldTable_.begin(); it < fieldTable_.end() ; it++)	{
		if (it != fieldTable_.begin())	{
			out_cc->print(", ");
		}
		if ((*it)->fieldType_ == FieldEntry::NOT_USED){
			out_cc->print("NOT_USED");
		}
		else if ((*it)->fieldType_ == FieldEntry::TYPE1){
			out_cc->print("TYPE1");
		}
		else if ((*it)->fieldType_ == FieldEntry::TYPE2){
			out_cc->print("TYPE2");
		}
		else {	//error cases
			cout <<"error, field type does not match, exiting"<<endl;
			exit(1);
		}
	}
	out_cc->print("};\n");
	out_cc->println("");

	return 0;
}

int FieldTable::GenCodeInitFuncNextField(Output* out_h, Output* out_cc)
{
	out_cc->print("int (*FastParser::ParsingField[%d])(FastParser*, const_byteptr&) = {", fieldTable_.size());

	for (vector<FieldEntry*>::iterator it = fieldTable_.begin(); it < fieldTable_.end() ; it++)	{
		if (it != fieldTable_.begin())	{
			out_cc->print(", ");
		}
		out_cc->print("FuncParsingField_%d", it - fieldTable_.begin());
	}
	out_cc->println("};");
	out_cc->println("");

	return 0;
}
//After the construction of field table is complete, check if there is inconsistency in the fully built field table
//This checking is a necessary, but not sufficient condition for the field table to be correct
//return true if the table is consistent. return false otherwise
bool FieldTable::CheckConsistency(){
	return true;
}

void FieldTable::DebugOutput()	{
	debugout <<"/******** starting printing out debuging information for field table *********/"<<endl;
	debugout <<"the total number of field in current field table is "<<fieldTable_.end() - fieldTable_.begin()<<endl;
	for (vector<FieldEntry*>::iterator tempi = fieldTable_.begin() ; tempi < fieldTable_.end() ; tempi++)	{
		(*tempi)->DebugOutput(debugout, fieldTable_);		
	}

	debugout <<"/******** ending printing out current field table *******/"<<endl<<endl;
}

void FieldTable::DebugOutputContextUpdate(){
	debugout <<endl;
	for (vector<FieldEntry*>::iterator itentry = fieldTable_.begin() ; itentry < fieldTable_.end() ; itentry++)	{
		for (vector<ContextUpdateAfterParse*>::iterator itupdate = (*itentry)->contextupdateafterparse.begin() ; itupdate < (*itentry)->contextupdateafterparse.end() ; itupdate++)	{
			if ((*itentry)->metadata_.id_)	{
				debugout <<(*itentry)->metadata_.id_->Name();
			}
			debugout <<" : "<<(*itupdate)->varid->Name()<<" = "<<ReComputeExpr((*itupdate)->updateexpr, this)<<endl;
		}
		
	}
}

