#ifndef pac_field_h
#define pac_field_h

#include "pac_common.h"
#include "pac_datadep.h"

// A "field" is a member of class.

enum FieldType {
	CASE_FIELD, 
	CONTEXT_FIELD,
	FLOW_FIELD,
	LET_FIELD, 
	PADDING_FIELD, 
	PARAM_FIELD,
	RECORD_FIELD, 
	PARSE_VAR_FIELD,
	PRIV_VAR_FIELD,
	PUB_VAR_FIELD,
	TEMP_VAR_FIELD,
	WITHINPUT_FIELD,
};

class Field : public Object, public DataDepElement
{
friend class decl;
public:
	Field(FieldType tof, int flags, ID *id, Type *type);
	// Field flags

	// Whether the field will be evaluated by calling the Parse()
	// function of the type
	static const int TYPE_TO_BE_PARSED = 1;	
	static const int TYPE_NOT_TO_BE_PARSED = 0;

	// Whether the field is a member of the class or a temp
	// variable
	static const int CLASS_MEMBER = 2;
	static const int NOT_CLASS_MEMBER = 0;

	// Whether the field is public readable
	static const int PUBLIC_READABLE = 4;
	static const int NOT_PUBLIC_READABLE = 0;

	virtual ~Field();

	const FieldType tof() const 	{ return tof_; }
	const ID* id() const		{ return id_; }
	Type *type() const		{ return type_; }
	const ID* decl_id() const	{ return decl_id_; }

	bool anonymous_field() const;

	void AddAttr(AttrList* attrs);

	// The field interface
	virtual void ProcessAttr(Attr *attr);
	virtual void Prepare(Env* env);

	virtual void GenPubDecls(Output* out, Env* env);
	virtual void GenPrivDecls(Output* out, Env* env);
	virtual void GenTempDecls(Output* out, Env* env);

	virtual void GenInitCode(Output* out, Env* env);
	virtual void GenCleanUpCode(Output* out, Env* env);

	virtual bool RequiresAnalyzerContext() const;

protected:
	int ValueVarType() const;
	bool ToBeParsed() const;

	bool DoTraverse(DataDepVisitor *visitor);

//protected:
public:
	FieldType tof_;		//type of current field, RecordField or something. Indicates what kind of structure does current field belong to
	int flags_;			//TYPE_NOT_TO_BE_PARSED is set for LetField
						//TYPE_TO_BE_PARSED is set for RecordField
	ID* id_;				//the id of current field
	Type *type_;			//the data type of current field, StringType or something
	const ID* decl_id_;	//the id of current declaration, which is the larger structure that contains current field
	string field_id_str_;	//the name of current declaration + the name of current field
	AttrList* attrs_;		//initialized to 0 for String type(const and regex). Haven't seen structure with Attr yet.
};

#endif  // pac_field_h
