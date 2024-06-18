package aquesnel.ghidra.debugger.breaklang;



import java.util.Optional;


public record BreaklangReadExpression(
		BreaklangReadExpressionType type,
		Optional<String> targetName,
		Optional<BreaklangReadExpression> innerExpression
		)
{
	public static BreaklangReadExpression fromRegister(String targetName) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.REGISTER,
				Optional.of(targetName),
				Optional.empty());
	}
	
	public static BreaklangReadExpression fromSymbol(String targetName) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.SYMBOL,
				Optional.of(targetName),
				Optional.empty());
	}
	
	public static BreaklangReadExpression fromLazyLookup(String targetName) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.LAZY_NAMED_LOOKUP,
				Optional.of(targetName),
				Optional.empty());
	}
	
	public static BreaklangReadExpression fromBreaklangVariable(String targetName) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.BREAKLANG_VARIABLE,
				Optional.of(targetName),
				Optional.empty());
	}
	
	public static BreaklangReadExpression fromDereference(BreaklangReadExpression innerExpression) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.DEREFERENCE,
				Optional.empty(),
				Optional.of(innerExpression));
	}
	
	public static BreaklangReadExpression fromAddressOf(BreaklangReadExpression innerExpression) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.ADDRESS_OF,
				Optional.empty(),
				Optional.of(innerExpression));
	}
	
	public static BreaklangReadExpression fromTypeInfo(BreaklangReadExpression innerExpression) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.TYPE_INFO,
				Optional.empty(),
				Optional.of(innerExpression));
	}
	
	public static BreaklangReadExpression fromFieldLookup(BreaklangReadExpression innerExpression, String fieldName) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.FIELD_LOOKUP,
				Optional.of(fieldName),
				Optional.of(innerExpression));
	}
	
	public static BreaklangReadExpression fromArrayLookup(BreaklangReadExpression innerExpression, int arrayIndex) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.ARRAY_LOOKUP,
				Optional.of(Integer.toString(arrayIndex)),
				Optional.of(innerExpression));
	}

	public static BreaklangReadExpression fromArraySliceLookup(BreaklangReadExpression innerExpression, int arrayIndexStart, int arrayIndexEnd) {
		return new BreaklangReadExpression(
				BreaklangReadExpressionType.ARRAY_SLICE_LOOKUP,
				Optional.of(Integer.toString(arrayIndexStart) + ":" + Integer.toString(arrayIndexEnd)),
				Optional.of(innerExpression));
	}
}
