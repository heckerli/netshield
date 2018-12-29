#include "pac_attr.h"
#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_record.h"
#include "pac_type.h"
#include "pac_utils.h"

#include "pac_decl.h"
#include "pac_regex.h"
#include "pac_strtype.h"
#include "pac_cstr.h"
#include "pac_paramtype.h"
#include "pac_case.h"
#include "pac_array.h"
#include "pac_flow.h"
#include "pac_dataunit.h"

#include "field_table.h"

#include <assert.h>

DeclList *Decl::decl_list_ = 0;
Decl::DeclMap Decl::decl_map_;

Output* out_temp;

Decl::Decl(ID* id, DeclType decl_type)
	: id_(id), decl_type_(decl_type), attrlist_(0)
	{
	decl_map_[id_] = this;
	if ( ! decl_list_ )
		decl_list_ = new DeclList();
	decl_list_->push_back(this);

	DEBUG_MSG("Finished Decl %s\n", id_->Name());

	analyzer_context_ = 0;
	}

Decl::~Decl()
	{
	delete id_;
	delete_list(AttrList, attrlist_);
	}

void Decl::AddAttrs(AttrList* attrs)
	{
	if ( ! attrs )
		return;
	if ( ! attrlist_ )
		attrlist_ = new AttrList();
	foreach ( i, AttrList, attrs )
		{
		attrlist_->push_back(*i);
		ProcessAttr(*i);
		}
	}

void Decl::ProcessAttr(Attr *attr)
	{
	throw Exception(attr, "unhandled attribute");
	}

void Decl::SetAnalyzerContext()
	{
	analyzer_context_ = 
		AnalyzerContextDecl::current_analyzer_context();
	if ( ! analyzer_context_ )
		{
		throw Exception(this, 
		                "analyzer context not defined");
		}
	}

void Decl::ProcessDecls(Output *out_h, Output *out_cc)
	{
	if ( ! decl_list_ )
		return;

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->Prepare();
		}

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenExternDeclaration(out_h);
		}

	out_h->println("namespace binpac {\n");
	out_cc->println("namespace binpac {\n");

	AnalyzerContextDecl *analyzer_context =
		AnalyzerContextDecl::current_analyzer_context();

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenForwardDeclaration(out_h);
		}

	if ( analyzer_context )
		analyzer_context->GenNamespaceEnd(out_h);

	out_h->println("");

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenCode(out_h, out_cc);
		}

	if ( analyzer_context )
		{
		analyzer_context->GenNamespaceEnd(out_h);
		analyzer_context->GenNamespaceEnd(out_cc);
		}

	out_h->println("}  // namespace binpac");
	out_cc->println("}  // namespace binpac");
	}

void Decl::Output_Info(Output *out_h)
{
	if ( ! decl_list_ )
		return;

	foreach (i, DeclList, decl_list_)	//print all decls
	{
		Decl *decl = *i;
		current_decl_id = decl->id();

		if (decl->decl_type_ == TYPE)	{
			TypeDecl* type_decl = static_cast<TypeDecl*>(decl);
			out_h->println("a TYPE declaration");
			out_h->println("Declaration ID = %s {", type_decl->id()->Name());
			if (type_decl->id()->is_anonymous())	{
				out_h->println("The ID is anonymous");
				}

			Type* pType = type_decl->type();
			if (pType->tot() == Type::RECORD)	{
				out_h->println("\tThis is a record type");
				}
			else if (pType->tot() == /*CASE*/Type::CASE)	{
				out_h->println("\tThis is a case type");
				out_h->println("\t-----for case type only-----");
				CaseType* pCaseType = static_cast<CaseType*>(pType);
				foreach(k, CaseFieldList, pCaseType->cases_)	{
					CaseField* pCaseField = *k;
					out_h->print("\t%s", pCaseField->id()->Name());

					if (pCaseField->type_->tot() == /*RECORD*/3)	{
						out_h->print("\t(This is a record type)");
					}
					else if (pCaseField->type_->tot() == /*CASE*/4)	{
						out_h->print("\t(This is a case type)");
					}
					else if (pCaseField->type_->tot() == /*STRING*/6)	{
						StringType* strType_ = static_cast<StringType*>(pCaseField->type_);
						if (strType_->type_ == /*CSTR*/ 0)	{
							out_h->print(" : %s", strType_->str_->c_str()); 
							out_h->print("\t\t(This is a const string type)");
							}
						else if (strType_->type_ == /*REGEX*/ 1)	{
							out_h->print(" : %s", strType_->regex_->str().c_str());
							out_h->print("\t\t(This is a regex string type)");
							}
						else	if (strType_->type_ == /*ANYSTR*/ 2)	{
							out_h->print("\t\t(This is an anystring type)");
							}
						else	{
							out_h->print("\t\t(This string type is error");
							}
					}
					else if (pCaseField->type_->tot() == /*ARRAY*/5)		{
						out_h->print("\t(This is an array type)");
						
					}
					else	 if (pCaseField->type_->tot() == /*UNDEF*/-1)	{
						out_h->print("\t(This is an undefined type)");
					}
					else if (pCaseField->type_->tot() == /*EMPTY*/0)	{
						out_h->print("\t(This is an empty type)");
					}
					else if (pCaseField->type_->tot() == /*BUILTIN*/1)	{
						out_h->print("\t(This is an builtin type)");
					}
					else if (pCaseField->type_->tot() == /*PARAMETERIZED*/2)	{
						ParameterizedType* paramType_ = static_cast<ParameterizedType*>(pCaseField->type_);
						out_h->print(" : %s", paramType_->type_id_->Name());
						out_h->print("\t\t(This is an parameterized type)");
					}
					else if (pCaseField->type_->tot() == /*EXTERN*/7)	{
						out_h->print("\t(This is an extern type)");
					}
					else if (pCaseField->type_->tot() == /*DUMMY*/8)	{
						out_h->print("\t(This is an dummy type)");
					}
					else	{
						out_h->print("\t(This is error)");
					}
				out_h->println("");
					}
				out_h->println("-------------------");
					
				}
			else if (pType->tot() == /*STRING*/Type::STRING)	{
				out_h->println("\tThis is a string type");
				}
			else if (pType->tot() == /*ARRAY*/Type::ARRAY)		{
				out_h->println("\tThis is an array type");
				out_h->println("\t-----for array type only-----");
				ArrayType* pArrayType = static_cast<ArrayType*>(pType);
				out_h->print("\tThe element is ");
				if (pArrayType->elemtype_->tot() == Type::RECORD)	{
					out_h->println("Record type");
					}
				else if (pArrayType->elemtype_->tot() == Type::PARAMETERIZED)	{
					out_h->print("Parameterized type");
					ParameterizedType* paramType_ = static_cast<ParameterizedType*>(pArrayType->elemtype_);
					out_h->print(", the type name is %s", paramType_->type_id_->Name());
					Type* lookupresult = TypeDecl::LookUpType(paramType_->type_id_);
					if (lookupresult)	{
						if (lookupresult->tot() == Type::RECORD)	{
							out_h->println(", the real type is Record type");
							}
						else	{
							out_h->println(", the real type is not Record type");
						}
					}
					else	{
						out_h->println(", error occures when lookup up this type");
						}
				}
				else	{
					out_h->println("not Record or Parameterized type");
				}
				if (pArrayType->attr_generic_until_expr_)	{
					out_h->println("the generic until expr is set");
					}
				else if (pArrayType->attr_until_element_expr_)	{
					out_h->println("the until element expr is set");
					}
				else	 if (pArrayType->attr_until_input_expr_)	{
					out_h->println("the until input expr is set");
					}
				else	{
					out_h->println("error, not until field is set");
					}
				out_h->println("---- end of array specific ----");
			}
			else	if (pType->tot() == Type::UNDEF)	{
				out_h->println("\tThis is an undefined type");
				}
			else if (pType->tot() == Type::EMPTY)	{
				out_h->println("\tThis is an empty type");
				}
			else if (pType->tot() == Type::BUILTIN)	{
				out_h->println("\tThis is an buitin type");
				}
			else if (pType->tot() == Type::PARAMETERIZED)	{
				out_h->println("\tThis is an parameterized type");
				}
			else if (pType->tot() ==Type::STRING)	{
				out_h->println("\tThis is an string type");
				}
			else if (pType->tot() == Type::EXTERN)	{
				out_h->println("\tThis is an extern type");
				}
			else if (pType->tot() == Type::DUMMY)	{
				out_h->println("\tThis is an dummy type");
				}
			else {
				out_h->println("\tThis type is an error");
				}

			out_h->println("\tThe size expression is \"%s\"", pType->size_expr_);
			out_h->println("\tThe field list is");
			foreach (j, FieldList, pType->fields_)
			{
				Field* pField = *j;
				assert(pField->type_);
				out_h->print("\t%s", pField->id()->Name());

				if (pField->type_->tot() == /*RECORD*/3)	{
					out_h->print("\t(This is a record type)");
				}
				else if (pField->type_->tot() == /*CASE*/4)	{
					out_h->print("\t(This is a case type)");
				}
				else if (pField->type_->tot() == /*STRING*/6)	{
					StringType* strType_ = static_cast<StringType*>(pField->type_);
					if (strType_->type_ == /*CSTR*/ 0)	{
						out_h->print(" : %s", strType_->str_->c_str()); 
						out_h->print("\t\t(This is a const string type)");
						}
					else if (strType_->type_ == /*REGEX*/ 1)	{
						out_h->print(" : %s", strType_->regex_->str().c_str());
						out_h->print("\t\t(This is a regex string type)");
						}
					else	if (strType_->type_ == /*ANYSTR*/ 2)	{
						out_h->print("\t\t(This is an anystring type)");
						}
					else	{
						out_h->print("\t\t(This string type is error");
						}
				}
				else if (pField->type_->tot() == /*ARRAY*/5)		{
					out_h->print("\t(This is an array type)");
				}
				else	 if (pField->type_->tot() == /*UNDEF*/-1)	{
					out_h->print("\t(This is an undefined type)");
				}
				else if (pField->type_->tot() == /*EMPTY*/0)	{
					out_h->print("\t(This is an empty type)");
				}
				else if (pField->type_->tot() == /*BUILTIN*/1)	{
					out_h->print("\t(This is an builtin type)");
				}
				else if (pField->type_->tot() == /*PARAMETERIZED*/2)	{
					ParameterizedType* paramType_ = static_cast<ParameterizedType*>/*(ParameterizedType*)*/(pField->type_);
					out_h->print(" : %s", paramType_->type_id_->Name());
					out_h->print("\t\t(This is an parameterized type)");
					Type* lookupresult = TypeDecl::LookUpType(paramType_->type_id_);
				if (lookupresult)	{
					out_h->print("\t(by looking up result, ");
					if (pType->tot() == Type::RECORD)	{
						out_h->print("This is a record type");
					}
					else if (pType->tot() == /*CASE*/Type::CASE)	{
						out_h->print("This is a case type");	
					}
					else if (pType->tot() == /*STRING*/Type::STRING)	{
						out_h->print("This is a string type");
					}
					else if (pType->tot() == /*ARRAY*/Type::ARRAY)		{
						out_h->print("This is an array type");
					}
					else	if (pType->tot() == Type::UNDEF)	{
						out_h->print("This is an undefined type");
					}
					else if (pType->tot() == Type::EMPTY)	{
						out_h->print("This is an empty type");
					}
					else if (pType->tot() == Type::BUILTIN)	{
						out_h->print("This is an buitin type");
					}
					else if (pType->tot() == Type::PARAMETERIZED)	{
						out_h->print("This is an parameterized type");
					}
					else if (pType->tot() ==Type::STRING)	{
						out_h->print("This is an string type");
					}
					else if (pType->tot() == Type::EXTERN)	{
						out_h->print("This is an extern type");
					}
					else if (pType->tot() == Type::DUMMY)	{
						out_h->print("This is an dummy type");
					}
					else {
						out_h->print("This type is an error");
					}
					out_h->print(")");
				}
				else	{
					out_h->print("\t(no result for looking up)");
					}
				}
				else if (pField->type_->tot() == /*EXTERN*/7)	{
					out_h->print("\t(This is an extern type)");
				}
				else if (pField->type_->tot() == /*DUMMY*/8)	{
					out_h->print("\t(This is an dummy type)");
				}
				else	{
					out_h->print("\t(This is error)");
				}

				
				
				#if 0
				if (pField->type_->tot() == /*PARAMETERIZED*/ 2)	{
					ParameterizedType* paramType_ = static_cast<ParameterizedType*>/*(ParameterizedType*)*/(pField->type_);
					out_h->print(" : %s", paramType_->type_id_->Name());
					}
				else	{
					out_h->print(", the type is not a declared type");
					}
				#endif
				out_h->println("");
			}
			
			out_h->println("}");
			out_h->println("");
			}
		else if (decl->decl_type_ == REGEX)	{
			RegExDecl* RegEx_decl = (RegExDecl*)decl;
			out_h->println("an REGEX declaration");
			out_h->println("Declaration ID = %s {", RegEx_decl->id()->Name());
			if (RegEx_decl->id()->is_anonymous())	{
				out_h->println("The ID is anonymous");
				}
			out_h->println("\t%s", RegEx_decl->regex_->str().c_str());
			out_h->println("\t%s", RegEx_decl->regex_->matcher_id()->Name());
			out_h->println("}");
			out_h->println("");
			}
		else if (decl->decl_type_ == LET)	{
			out_h->println("a LET declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == ENUM)	{
			out_h->println("an ENUM declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == FUNC)	{
			out_h->println("a FUNC declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == CONN)	{
			out_h->println("a CONN declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == FLOW)	{
			out_h->println("a FLOW declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == ANALYZER)	{
			out_h->println("an ANALYZER declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else if (decl->decl_type_ == HELPER)	{
			out_h->println("an HELPER declaration");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
		else	{
			out_h->println("error: declaration type not right");
			out_h->println("Decleartion ID = %s", decl->id()->Name());
			out_h->println("");
			}
	}

	Decl* rootdecl = FindRootNode(out_h);
	if (!rootdecl)	{
		out_h->println("\t error in finding root node");
		}
	else	{
		out_h->println("\t the root node is %s", rootdecl->id()->Name());
		}

	if (rootdecl == NULL)	{
		cout <<"rootdecl not found in first finding"<<endl;
		}
	else	{
		cout <<"rootdecl found in first finding"<<endl;
		}
	
	return;

	out_h->println("namespace binpac {\n");

	AnalyzerContextDecl *analyzer_context =
		AnalyzerContextDecl::current_analyzer_context();

	/*foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenForwardDeclaration(out_h);
		}*/

	if ( analyzer_context )
		analyzer_context->GenNamespaceEnd(out_h);

	out_h->println("");

	/*foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenCode(out_h, out_cc);
		}*/

	//add code here

	if ( analyzer_context )
		{
		analyzer_context->GenNamespaceEnd(out_h);
		}

	
	
	out_h->println("}  // namespace binpac");
	}

	
void Decl::ProcessDecls_FastParser(Output *out_h, Output *out_cc)
	{
	if ( ! decl_list_ )	{
		cout <<"do not enter fast_parser"<<endl;
		return;
		}
	else	{
		cout <<"enter fast_parser"<<endl;
		}

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->Prepare();
		}

	cout <<"decl prepare completed"<<endl;
	
	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenExternDeclaration(out_h);
		}
	cout <<"decl gen extern declaration completed"<<endl;

	out_h->println("namespace binpac {\n");
	out_cc->println("namespace binpac {\n");

	out_h->println("class FastParser;");			//special line under Windows
	out_h->println("#include \"http_matcher.h\"");	//special line under Windows
	out_h->println("int strncasecmp(const char *s1, const char *s2, size_t n);");	//special funtion declaration under Windows
	out_h->println("char *strcasestr(const char *s, const char *find);");		//special function declaration under Windows

	
	AnalyzerContextDecl *analyzer_context =
		AnalyzerContextDecl::current_analyzer_context();

	foreach(i, DeclList, decl_list_)
	{
		Decl *decl = *i;
		current_decl_id = decl->id();
		if (decl->decl_type_ == ENUM)	{
			decl->GenForwardDeclaration(out_h);
		}
		else if (decl->decl_type_ == FUNC)	{
			decl->GenCode(out_h, out_cc);
			}
		else if (decl->decl_type() == HELPER)	{
			decl->GenCode(out_h, out_cc);
			}
	}
#if 0
	if ( analyzer_context )
		analyzer_context->GenNamespaceEnd(out_h);
#endif
	out_h->println("");

	cout <<"gen helper code completed"<<endl;
	
	Decl* rootdecl = FindRootNode(out_h);

	if (rootdecl == NULL)	{
		cout <<"rootdecl not found in second finding"<<endl;
		return;
		}
	else	{
		cout <<"rootdecl found in second finding"<<endl;
		}

	out_temp = new Output("testforEvalExpr.out");
	TypeDecl* typerootdecl = static_cast<TypeDecl*>(rootdecl);
	FieldTable myTable;
	myTable.GenStartField(typerootdecl->type(), typerootdecl->id());
	cout <<"gen start field complete"<<endl;
	myTable.GenOtherFields();
	myTable.GenLengthColumn();
	myTable.GenGarbageLengthColumn();
	myTable.GenCode(out_h, out_cc);
	

#if 0
		if ( analyzer_context )
		{
		analyzer_context->GenNamespaceEnd(out_h);
		analyzer_context->GenNamespaceEnd(out_cc);
		}
#endif

	out_h->println("}  // namespace binpac");
	out_cc->println("}  // namespace binpac");
	}

Decl* Decl::FindRootNode(Output* out_h)
{
	if ( ! decl_list_ )
		return NULL;
	
	foreach (i, DeclList, decl_list_)	//find the root node
	{
		Decl *decl = *i;
		//current_decl_id = decl->id();
									//find the FlowDecl
		if (decl->decl_type() == FLOW)	{
			FlowDecl* flowdecl = static_cast<FlowDecl*>(decl);
			AnalyzerDataUnit* dataunit = flowdecl->dataunit_;
			assert(dataunit);
				
			cout <<"the id for root node is "<<dataunit->id()->Name()<<endl;
			
			DeclMap::iterator rootnode =  decl_map_.find(dataunit->id());
			if (rootnode == decl_map_.end())	{
				return NULL;
			}
			else	{
				return rootnode->second;
			}
		}

	}

	return NULL;
#if 0
	DeclMap::iterator rootnode =  decl_map_.find(new ID("HTTP_PDU"));
	if (rootnode == decl_map_.end())	{
		return NULL;
		}
	else	{
		return rootnode->second;
		}
#endif
}
	
		

		

		

	
Decl* Decl::LookUpDecl(const ID* id)
	{
	//cout <<"starting lookupdecl in legacy code, looking for "<<id->name<<endl;
	//assert(decl_map_.size() > 0);
	DeclMap::iterator it;
	//cout <<"declared it in legacy code"<<endl;
	it = decl_map_.find(id);
	//cout <<"end looking in decl_map_ in legacy code"<<endl;
	if ( it == decl_map_.end() )
		return 0;
	return it->second;
	}

int HelperDecl::helper_id_seq = 0;

HelperDecl::HelperDecl(HelperType helper_type, 
                       ID* context_id, 
                       EmbeddedCode* code)
 	: Decl(new ID(fmt("helper_%d", ++helper_id_seq)), HELPER), 
	  helper_type_(helper_type),
	  context_id_(context_id),
	  code_(code)
	{
	}

HelperDecl::~HelperDecl()
	{
	delete context_id_;
	delete code_;
	}

void HelperDecl::Prepare()
	{
	// Do nothing
	}

void HelperDecl::GenExternDeclaration(Output *out_h)
	{
	if ( helper_type_ == EXTERN )
		code_->GenCode(out_h, global_env());
	}

void HelperDecl::GenCode(Output *out_h, Output *out_cc)
	{
	Env *env = global_env();

#if 0
	if ( context_id_ )
		{
		Decl *decl = Decl::LookUpDecl(context_id_);
		if ( ! decl )
			{
			throw Exception(context_id_, 
			                fmt("cannot find declaration for %s", 
			                    context_id_->Name()));
			}
		env = decl->env();
		if ( ! env )
			{
			throw Exception(context_id_,
			                fmt("not a type or analyzer: %s",
			                    context_id_->Name()));
			}
		}
#endif

	if ( helper_type_ == HEADER )
		code_->GenCode(out_h, env);
	else if ( helper_type_ == CODE )
		code_->GenCode(out_cc, env);
	else if ( helper_type_ == EXTERN )
		; // do nothing
	else
		ASSERT(0);
	}
