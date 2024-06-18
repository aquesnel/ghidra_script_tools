package aquesnel.ghidra.debugger.breaklang;



public enum BreaklangTokenTypeGroup {
	LITERAL(true),
	WHITESPACE(false),
	CHARACTERS(false),
	KEYWORD(true),
	;
	
	private final boolean mIsConstant;
	
	private BreaklangTokenTypeGroup(boolean isConstant) {
		mIsConstant = isConstant;
	}
	
	public boolean isConstant() {
		return mIsConstant;
	}
}