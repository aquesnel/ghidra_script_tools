package aquesnel.ghidra.debugger.breaklang;



import java.util.Optional;

public record BreaklangPrintDirective(
		BreaklangPrintDirectiveType type,
		Optional<CharSequence> literal,
		Optional<BreaklangReadExpression> readExpression
		)
{		
	public static BreaklangPrintDirective fromLiteral(String value) {
		return new BreaklangPrintDirective(
				BreaklangPrintDirectiveType.LITERAL,
				Optional.of(value),
				Optional.empty());
	}
	
	public static BreaklangPrintDirective fromReadExpression(BreaklangReadExpression readExpression) {
		return new BreaklangPrintDirective(
				BreaklangPrintDirectiveType.READ_EXPRESSION,
				Optional.empty(),
				Optional.of(readExpression));
	}
}