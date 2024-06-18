package aquesnel.ghidra.debugger.breaklang;

public record BreaklangAssignmentDirective(
		String variableName,
		BreaklangReadExpression readExpression)
{}