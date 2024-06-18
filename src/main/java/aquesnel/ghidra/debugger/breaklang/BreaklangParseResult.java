package aquesnel.ghidra.debugger.breaklang;




import java.util.List;


public record BreaklangParseResult(
		String description,
		boolean doBreak,
		boolean verbose,
		boolean printLocals,
		boolean parseComment,
		List<BreaklangAssignmentDirective> assignments,
		List<BreaklangPrintDirective> prints)
{}