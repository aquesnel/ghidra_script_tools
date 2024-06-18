package aquesnel.ghidra.debugger.breaklang;



public enum BreaklangReadExpressionType {
	REGISTER,
	SYMBOL,
	BREAKLANG_VARIABLE,
	LAZY_NAMED_LOOKUP,
	DEREFERENCE,
	ADDRESS_OF,
	TYPE_INFO,
	FIELD_LOOKUP,
	ARRAY_LOOKUP,
	ARRAY_SLICE_LOOKUP,
}