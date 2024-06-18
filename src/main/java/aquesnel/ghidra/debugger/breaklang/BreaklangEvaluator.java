package aquesnel.ghidra.debugger.breaklang;

import java.util.Comparator;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import aquesnel.ghidra.utils.FlatDebuggerAPIUtils;
import aquesnel.ghidra.utils.FlatDecompilerAPIUtils;
import aquesnel.ghidra.utils.data.DataUtils;

import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.pcode.HighVariable;

public final class BreaklangEvaluator {

	public static class EvaluationContext
	{
		private final GhidraScript mScript;
		private Map<String, Data> mVariables = new HashMap<>();
		private boolean mBreak;
		private boolean mVerbose;	
		private String mMessage;
		
		public EvaluationContext(GhidraScript script) {
			this.mScript = Objects.requireNonNull(script);
		}
		
		public GhidraScript script() {
			return mScript;
		}
		public Map<String, Data> variables() {
			return mVariables;
		}
		public EvaluationContext withVariables(Map<String, Data> variables) {
			this.mVariables = Objects.requireNonNull(variables);
			return this;
		}
		public boolean isBreak() {
			return mBreak;
		}
		public EvaluationContext withBreak(boolean doBreak) {
			this.mBreak = doBreak;
			return this;
		}
		public boolean verbose() {
			return mVerbose;
		}
		public EvaluationContext withVerbose(boolean verbose) {
			this.mVerbose = verbose;
			return this;
		}
//		public boolean printLocals() {
//			return mPrintLocals;
//		}
//		public EvaluationContext withPrintLocals(boolean printLocals) {
//			this.mPrintLocals = printLocals;
//			return this;
//		}
		public String message() {
			return mMessage;
		}
		public EvaluationContext withMessage(String message) {
			this.mMessage = message;
			return this;
		}
		
		
//		public FlatDebuggerAPI debugger() {
//			return FlatDebuggerAPIUtils.fromScript(script);
//		}
	}
	
	public static void evaluateParseResult(EvaluationContext context, BreaklangParseResult parseResult) {
		
		context.withBreak(parseResult.doBreak());
		context.withVerbose(parseResult.verbose());
//		context.withPrintLocals(parseResult.printLocals());
		
		evaluateAssignments(context, parseResult.assignments());
		
		StringBuilder message = new StringBuilder();
		message.append(evaluatePrintExpressions(context, parseResult.prints()));
		if(parseResult.printLocals()) {
			message.append(evaluatePrintLocals(context));
		}
		context.withMessage(message.toString());
	}

	public static Data evaluateReadExpression(EvaluationContext context, BreaklangReadExpression expression) {
	
		try {
			return switch (expression.type()) {
				case REGISTER -> readRegister(context, expression.targetName().get());
				case SYMBOL -> readSymbol(context, expression.targetName().get());
				case BREAKLANG_VARIABLE -> readBreaklangVariable(context, expression.targetName().get());
				case LAZY_NAMED_LOOKUP -> readLazyNamedLookup(context, expression.targetName().get());
				case DEREFERENCE -> 
					FlatDebuggerAPIUtils.dereferencePointer(
							context.script(), 
							evaluateReadExpression(context, expression.innerExpression().get()));
				case ADDRESS_OF ->
					DataUtils.getPointerToData(
							evaluateReadExpression(context, expression.innerExpression().get()));
				case FIELD_LOOKUP, ARRAY_LOOKUP -> 
					DataUtils.getField(
							context.script(),
							evaluateReadExpression(context, expression.innerExpression().get()), 
							expression.targetName().get());
				case ARRAY_SLICE_LOOKUP -> {
					String[] indices = expression.targetName().get().split(":");
					yield DataUtils.getDataSlice(
							context.script(),
							evaluateReadExpression(context, expression.innerExpression().get()), 
							Integer.parseInt(indices[0]),
							Integer.parseInt(indices[1]));
				}
				case TYPE_INFO -> {
					Data data = evaluateReadExpression(context, expression.innerExpression().get());
					yield DataUtils.asConstantData(
							data.getBaseDataType().getName(),
							data.getProgram());
				}
			};
		}
		catch (Exception e) {
			throw new IllegalArgumentException(
					"Evaluating read expression: " + expression.toString(),
					e);
		}
	}

	private static Data readRegister(EvaluationContext context, String registerName) {
		return FlatDebuggerAPIUtils.readRegister(context.script(), registerName);
	}
	
	private static Data readSymbol(EvaluationContext context, String symbolName) {
		
		return FlatDecompilerAPIUtils.readLocalVariable(context.script(), symbolName)
				.or(() -> FlatDebuggerAPIUtils.readGlobalSymbol(context.script(), symbolName))
				.get();
	}

	private static Data readBreaklangVariable(EvaluationContext context, String variableName) {

		Data result = context.variables().get(variableName);
		if (result == null) {
			throw new IllegalArgumentException("Unkown variable name: " + variableName);
		}
		return result;
	}
	
	private static Data readLazyNamedLookup(EvaluationContext context, String targetName) {
		
		if (context.variables().containsKey(targetName)) {
			return readBreaklangVariable(context, targetName);
		}
		else if (FlatDebuggerAPIUtils.fromScript(context.script()).getCurrentPlatform().getLanguage().getRegister(targetName) != null) {
			return readRegister(context, targetName);
		}
		else {
			return readSymbol(context, targetName);
		}
	}
	
	private static String evaluatePrintExpressions(EvaluationContext context, List<BreaklangPrintDirective> printExpressions) {
		
		StringBuilder sb = new StringBuilder();
		
		for (BreaklangPrintDirective printExpression : printExpressions) {
			String printMessage = switch (printExpression.type()) {
				case LITERAL -> Objects.toString(printExpression.literal().get(), "<null - literal>");
				case READ_EXPRESSION -> {
					Data data = evaluateReadExpression(context, printExpression.readExpression().get());
					Object dataValue = data.getValue();
					yield DataUtils.toString(dataValue)
//							+ " (java type: "
//							+ Optional.ofNullable(dataValue).map(Object::getClass).orElse((Class) Void.class).getName()
//							+ ") "
							;
				}
			};
			
			sb.append(printMessage);
		}
		return sb.toString();
	}
	
	private static void evaluateAssignments(EvaluationContext context, List<BreaklangAssignmentDirective> assignments) {
		
		for (BreaklangAssignmentDirective assignment : assignments) {
			context.variables().put(
					assignment.variableName(),
					evaluateReadExpression(context, assignment.readExpression()));
		}
	}
	

	
	private static String evaluatePrintLocals(EvaluationContext context) {
		
		Map<String, HighVariable> localVars = FlatDecompilerAPIUtils.getLocalVariables(context.script());
		SortedMap<String, HighVariable> sortedLocalVars = new TreeMap<>(Comparator.naturalOrder());
		sortedLocalVars.putAll(localVars);
		
		StringBuilder result = new StringBuilder();
		
		result.append(".\n"); // force newline even when stripping the final result
		result.append("----------------------------------------\n");
		result.append("   Local Variables @ PC = " 
				+ FlatDebuggerAPIUtils.fromScript(context.script()).getProgramCounter().toString()
				+ "\n");
		result.append("----------------------------------------\n");
		{
			@SuppressWarnings("resource")
			Formatter formatter = new Formatter(result, Locale.US);
			formatter.format("%1$-19s | %2$-25s | %3$-20s | %6$-20s | %4$-30s = %5$s\n",
					// 1. Address
					"Address",
					// 2. Field/register name
					"Fields Name",
					// 3. Ghidra Data type
					"Ghidra Data Type",
					// 4. Variable name
					"Variable name",
					// 5. Value
					"Value",
					// 6. Java Data Type
					"Java Data Type");
			formatter.format("-------------------------------------------------------------------------------------------------------------------------------------------------\n");
			formatter.flush();
		}	
		if (sortedLocalVars.isEmpty()) {
			result.append("none\n");
		}
		else
		{

			for (Entry<String, HighVariable> entry : sortedLocalVars.entrySet())
			{
				Optional<Data> optionalData = FlatDecompilerAPIUtils.readVariable(context.script(), entry.getValue());

//				result.append(optionalData
//					.map(Data::getAddress)
//					.map(Objects::toString)
//					.orElse("<unknown>"));
//				result.append("  ");
//				
//				result.append(optionalData
//					.map(Data::getFieldName)
//					.map(name -> "(" + name + ")   ")
//					.orElse(""));
				
//				result.append(entry.getValue().getDataType().getName());
				
//				if (optionalData.isPresent() && entry.getValue().getDataType() instanceof PointerDataType pointerDataType) {
//					
//					Settings settings = new DataTypeSettingsAdapter(
//							context.script().getCurrentProgram().getDataTypeManager(), 
//							optionalData.get());
//					result.append(" (");
//					result.append(PointerTypeSettingsDefinition.DEF.getType(settings));
//					result.append(" | ");
//					result.append(AddressSpaceSettingsDefinition.DEF.getValue(settings));
//					result.append(" | ");
//					result.append(context.script().getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getName());
//					result.append(")");
//				}
				
//				result.append("  ");
//				result.append(entry.getKey());
//				result.append(" = ");
//				result.append(optionalData
//						.map(DataUtils::getValue)
//						.map(Objects::toString)
//						.orElse("<null>"));
//				result.append("\n");
				
				@SuppressWarnings("resource")
				Formatter formatter = new Formatter(result, null);
				formatter.format("%1$-19s | %2$-25s | %3$-20s | %6$-20s | %4$-30s = %5$s\n",
						// 1. Address
						optionalData
							.map(Data::getAddress)
							.map(Objects::toString)
							.orElse("<unknown>"),
						// 2. Field/register name
						optionalData
							.map(Data::getFieldName)
							.orElse(""),
						// 3. Ghidra Data type
						entry.getValue().getDataType().getName(),
						// 4. Variable name
						entry.getKey(),
						// 5. Value
						optionalData
							.map(DataUtils::getValue)
							.map(Objects::toString)
							.orElse("<null>"),
						// 6. Java Data Type
						optionalData
							.map(DataUtils::getValue)
							.map(Object::getClass)
							.map(Class::getSimpleName)
							.orElse("<Unknown class>"));
				formatter.flush();
				
			}
		}
		result.append("-------------------------------------------------------------------------------------------------------------------------------------------------\n");
		
		return result.toString();
	}
}
