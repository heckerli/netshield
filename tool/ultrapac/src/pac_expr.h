#ifndef pac_expr_h
#define pac_expr_h

#include "pac_common.h"
#include "pac_datadep.h"


class CaseExpr;

class Expr : public Object, public DataDepElement
{
public:
	enum ExprType {
#		define EXPR_DEF(type, x, y) type,
#		include "pac_expr.def"
#		undef EXPR_DEF
	};

	void init();

	Expr(ID *id);
	Expr(Number *num);
	Expr(ConstString *s);
	Expr(RegEx *regex);
	Expr(ExprList *args);	// for EXPR_CALLARGS
	Expr(Expr *index, CaseExprList *cases);

	Expr(ExprType type, Expr *op1);
	Expr(ExprType type, Expr *op1, Expr *op2);
	Expr(ExprType type, Expr *op1, Expr *op2, Expr *op3);

	virtual ~Expr();

	const char *orig() const	{ return orig_.c_str(); }
	const ID *id() const 		{ return id_; }
	const char *str() const		{ return str_.c_str(); }
	ExprType expr_type() const	{ return expr_type_; }

	void AddCaseExpr(CaseExpr *case_expr);

	// Returns the data "type" of the expression. Here we only
	// do a serious job for the EXPR_MEMBER and EXPR_SUBSCRIPT
	// operators. For arithmetic operations, we fall back
	// to "int".
	Type *DataType(Env *env) const;
	string DataTypeStr(Env *env) const;

	// Note: EvalExpr() may generate C++ statements in order to evaluate 
	// variables in the expression, so the following is wrong:
	//
	// out->print("int x = ");
	// out->println("%s", expr->EvalExpr(out, env));
	//
	// While putting them together is right:
	//
	// out->println("int x = %s", expr->EvalExpr(out, env));
	//
	const char *EvalExpr(Output *out, Env *env);
	//const char *EvalExpr(Output *out);

	// force evaulation of IDs contained in this expression;
	// necessary with case expr and conditional let fields (&if)
	// for correct parsing of fields
	void ForceIDEval(Output *out_cc, Env *env);

	// Returns the set_* function of the expression. 
	// The expression must be of form ID or x.ID.
	string SetFunc(Output *out, Env *env);

	// Returns true if the expression folds to an integer
	// constant with env, and puts the constant in *pn.
	//
	bool ConstFold(Env *env, int *pn) const;

	// Whether id is referenced in the expression
	bool HasReference(const ID *id) const;

	// Suppose the data for type might be incomplete, what is
	// the minimal number of bytes from data head required to
	// compute the expression? For example, how many bytes of frame
	// header do we need to determine the length of the frame?
	//
	// The parameter <env> points to the Env of a type.
	// 
	// Returns -1 if the number is not a constant.
	//
	int MinimalHeaderSize(Env *env);

	// Whether evaluation of the expression requires the analyzer context
	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

//private:
public:
	ExprType expr_type_;	//initialized to EXPR_ID, if this expression comes from an ID
						//initialized to EXPR_CALLARGS if this expression is parameters of function calling
						//initialized to EXPR_CALL if it is a function call

	int num_operands_;	//initialized to 0, if is from an ID. Initialized to -1, if is from parameters of function calling
						//initialized to 2, if it is a function calling
	Expr *operand_[3];	//if this expression is a function call, there are 2 operands. The first one is function name, the seconds one is the function arguments

	ID *id_;		// EXPR_ID, the ID that creats this expression, if it comes from an ID	//expression with attributes below are basic expressions
	Number *num_;		// EXPR_NUM
	ConstString *cstr_;	// EXPR_CSTR
	RegEx *regex_;		// EXPR_REGEX
	ExprList *args_;	// EXPR_CALLARGS, a list of Expr, they are the arguments of function calling
	CaseExprList *cases_;	// EXPR_CASE

	string str_;		// value string
	string orig_;		// original string for debugging info. Equals to the name of ID, if it comes from an ID. Is the concatination of all Exprs, if it is arguments of funtion calling

	void GenStrFromFormat();
	void GenStrFromFormat(Env *env);
	void GenEval(Output *out, Env *env);
	//void GenEval(Output *out);
	void GenCaseEval(Output *out_cc, Env *env);
};

string OrigExprList(ExprList *exprlist);
string EvalExprList(ExprList *exprlist, Output *out, Env *env);

// An entry of the case expression, consisting of one or more constant
// expressions for the case index and a value expression.
class CaseExpr : public Object, public DataDepElement
{
public:
	CaseExpr(ExprList *index, Expr *value);
	virtual ~CaseExpr();

	ExprList *index() const 	{ return index_; }
	Expr *value() const 		{ return value_; }

	bool HasReference(const ID *id) const;
	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

private:
	ExprList *index_;
	Expr *value_;
};

#endif  // pac_expr_h
