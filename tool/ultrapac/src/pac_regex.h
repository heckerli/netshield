#ifndef pac_regex_h
#define pac_regex_h

#include "pac_common.h"
#include "pac_decl.h"

class RegExDecl;

class RegEx : public Object
{
public:
	RegEx(const string &str);
	~RegEx();

	const string &str() const	{ return str_; }
	ID *matcher_id() const		{ return matcher_id_; }

//private:
public:
	string str_;		//the actual regex string	
	ID *matcher_id_;	//= ID::NewAnonymousID(prefix), while prefix = "current_declaration_name" + "_re_".
						//means the name of larger structure that contains this regex + "_re_"
	RegExDecl *decl_;

public:
	static const char *kREMatcherType;
	static const char *kMatchPrefix;
};

class RegExDecl : public Decl
{
//friend class Decl;
public:
	RegExDecl(RegEx *regex);

	void Prepare();
	void GenForwardDeclaration(Output *out_h); 
	void GenCode(Output *out_h, Output *out_cc);
	void GenCode(Output *out_cc);

//private:
public:
	RegEx *regex_;		//pointer to regex that is declared
};

#endif  // pac_regex_h
