package aquesnel.ghidra.debugger.breaklang;

import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.Lists;

import aquesnel.collections.CopyableListIterator;

/**
 * BNF of Breaklang:
 * 
 * expression := description? directive* print?
 * description := (anyChar | whitespace)+
 * directive := break | continue | verbose | printLocals | assignment
 * assignment := "#SET" whitespace breaklangVariableName whitespace? "=" whitespace? readExpr
 * print := ("#PRINT" | "#P") whitespace (anyChar | printVar | readExpr)+ ("\n" | EOL)
 * printVar := ("#PRINT_VAR" | "#PV") whitespace? readExpr
 * readExpr := "{" whitespace? ("#READ" whitespace)? rootStructRef structPath* arraySlice? "#TYPE"? whitespace? "}"
 * rootStructRef := registerName | breaklangVariableName | symbol | lazyLookupName
 * structPath := ("." | "->") fieldName | "*" | "[" numeric "]" | "&"
 * arraySlice := "[" numeric ":" numeric "]" 
 * variableName := "#VAR:" alphaNumeric
 * symbol := "#SYM:" alphaNumeric
 * registerName := "#REG:" alphaNumeric
 * lazyLookupName := fieldName
 * fieldName := (alphaNumeric | "_")+
 * break := "#BREAK"
 * continue := "#CONTINUE" | "#C"
 * verbose := "#VERBOSE" | "#V"
 * printLocals := "#PRINT_LOCALS" | "#PL"
 * whitespace := [ \t\n]+
 * anyChar := .+
 * alphaNumeric := [a-zA-Z0-9]+
 * numeric := [0-9]+
 */
public final class BreaklangParser {

	
	public BreaklangParseResult parse(String input) {
		CopyableListIterator<BreaklangToken> tokens = 
				new CopyableListIterator<>(BreaklangTokenizer.parseTokens(CharBuffer.wrap(input)));//.listIterator();
		return parseExpression(tokens);
	}
	
	private BreaklangParseResult parseExpression(CopyableListIterator<BreaklangToken> tokens) {
		List<BreaklangAssignmentDirective> assignments = new ArrayList<>();
		boolean doBreak = true;
		boolean verbose = false;
		boolean printLocals = false;
		boolean parseComment = false;
		List<BreaklangPrintDirective> printDirective = new ArrayList<>();
		
		String description = parseDescription(tokens);
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
			switch(token.type()) {
			case KEYWORD_BREAK -> doBreak = true;
			case KEYWORD_CONTINUE -> doBreak = false;
			case KEYWORD_VERBOSE -> verbose = true;
			case KEYWORD_PARSE_COMMENT -> parseComment = true;
			case KEYWORD_PRINT_LOCALS -> printLocals = true;
			case KEYWORD_SET -> {
				tokens.previous();
				assignments.add(parseAssignment(tokens));
			}
			case KEYWORD_PRINT -> {
				tokens.previous();
				printDirective = parsePrint(tokens);
			}
//			case CHAR_END_OF_LINE -> {}
			default -> 
				throw new IllegalStateException("Expected a set/break/continue/verbose/print directive. Received: " + token.type());
			}
			consumeWhitespace(tokens);
		}
		return new BreaklangParseResult(description, doBreak, verbose, printLocals, parseComment, assignments, printDirective);
	}

	private String parseDescription(CopyableListIterator<BreaklangToken> tokens) {
		StringBuilder sb = new StringBuilder();
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
			if (token.type().isKeyword()) {
				tokens.previous();
				break;
			}
			else {
				sb.append(token.value());
			}
		}
		return sb.toString().stripTrailing();
	}

	private BreaklangAssignmentDirective parseAssignment(CopyableListIterator<BreaklangToken> tokens) {

//		BreaklangToken setToken = tokens.next();
//		if(setToken.type() != BreaklangTokenType.KEYWORD_SET) {
//			throw new IllegalStateException("Expected a SET directive. Received: " + setToken.type());
//		}
		consumeExpectedToken(BreaklangTokenType.KEYWORD_SET, tokens);
		consumeWhitespace(tokens);
		
//		BreaklangToken variableNameToken = tokens.next();
//		if(variableNameToken.type() != BreaklangTokenType.CHAR_FIELD_NAME) {
//			throw new IllegalStateException("Expected a CHAR_FIELD_NAME token. Received: " + variableNameToken.type());
//		}
		BreaklangToken variableNameToken = consumeExpectedToken(BreaklangTokenType.CHAR_FIELD_NAME, tokens);
		consumeWhitespace(tokens);
		
//		BreaklangToken equalsToken = tokens.next();
//		if(equalsToken.type() != BreaklangTokenType.CHAR_EQUALS) {
//			throw new IllegalStateException("Expected a CHAR_EQUALS token. Received: " + equalsToken.type());
//		}
		consumeExpectedToken(BreaklangTokenType.CHAR_EQUALS, tokens);
		consumeWhitespace(tokens);
		
		BreaklangReadExpression readExpression = parseReadExpression(tokens);
		
		return new BreaklangAssignmentDirective(variableNameToken.value().toString(), readExpression);
	}

	/*
 * readExpr := "{" whitespace? ("#READ" whitespace)? rootStructRef structPath* arraySlice? "#TYPE"? whitespace? "}"
 * rootStructRef := registerName | breaklangVariableName | symbol | lazyLookupName
 * structPath := ("." | "->") fieldName | "*" | "[" numeric "]" | "&"
 * arraySlice := "[" numeric ":" numeric "]" 
 * variableName := "#VAR:" alphaNumeric
 * symbol := "#SYM:" alphaNumeric
 * registerName := "#REG:" alphaNumeric
 * lazyLookupName := fieldName
 * fieldName := (alphaNumeric | "_")+
	 */
	private BreaklangReadExpression parseReadExpression(CopyableListIterator<BreaklangToken> tokens) {
		
		// PARSE: `{`
//		BreaklangToken openBraceToken = tokens.next();
//		if(openBraceToken.type() != BreaklangTokenType.CHAR_OPEN_BRACE) {
//			throw new IllegalStateException("Expected a CHAR_OPEN_BRACE token. Received: " + openBraceToken.type());
//		}
		consumeExpectedToken(BreaklangTokenType.CHAR_OPEN_BRACE, tokens);
		consumeWhitespace(tokens);

		// PARSE: `#READ` (optional)
		Optional<BreaklangToken> readToken = tryConsumeToken(BreaklangTokenType.KEYWORD_READ, tokens);
		if(readToken.isPresent()) {
			// Found `#READ`
			consumeWhitespace(tokens);
		}
		else {
//			throw new IllegalStateException("Expected a READ directive. Received: " + readToken.type());
		}
		
		// PARSE: rootStructRef
		BreaklangReadExpression readExpression;
		BreaklangToken rootVariableToken = tokens.next();
		switch(rootVariableToken.type()) {
			case KEYWORD_REGISTER -> {
				readExpression = BreaklangReadExpression.fromRegister(consumeFieldName(tokens));
				boolean foundDereference = tryParseDereference(tokens);
				if (foundDereference) {
					readExpression = BreaklangReadExpression.fromDereference(readExpression);
				}
			}
			case KEYWORD_SYMBOL -> {
				readExpression = BreaklangReadExpression.fromSymbol(consumeFieldName(tokens));
			}
			case KEYWORD_BREAKLANG_VARIABLE -> {
				readExpression = BreaklangReadExpression.fromBreaklangVariable(consumeFieldName(tokens));
			}
			case CHAR_FIELD_NAME -> {
				tokens.previous();
				readExpression = BreaklangReadExpression.fromLazyLookup(consumeFieldName(tokens));
			}
			default -> 
				throw new IllegalStateException("Expected a REGISTER/SYMBOL/VARIABLE/FIELD_NAME directive. Received: " + rootVariableToken.type());
		}
		
		// PARSE: structPath
		STRUCT_PATH_LOOP: 
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
			switch(token.type()) {
			case CHAR_DOT -> {
				readExpression = BreaklangReadExpression.fromFieldLookup(readExpression, consumeFieldName(tokens));
			}
			case CHAR_STAR -> {
				readExpression = BreaklangReadExpression.fromDereference(readExpression);
			}
			case KEYWORD_ARROW -> {
				readExpression = BreaklangReadExpression.fromFieldLookup(
						BreaklangReadExpression.fromDereference(readExpression), 
						consumeFieldName(tokens));
			}
			case CHAR_AMPERSAND -> {
				readExpression = BreaklangReadExpression.fromAddressOf(readExpression);
			}
			case CHAR_OPEN_SQUARE_BRACKET -> {
				int arrayIndex = consumeNumber(tokens);
				
				Optional<BreaklangToken> colonToken = tryConsumeToken(BreaklangTokenType.CHAR_COLON, tokens);
				if (colonToken.isEmpty()) {
					readExpression = BreaklangReadExpression.fromArrayLookup(readExpression, arrayIndex);
					consumeExpectedToken(BreaklangTokenType.CHAR_CLOSE_SQUARE_BRACKET, tokens);
				}
				else {
					// PARSE: arraySlice
					int arrayIndexEnd = consumeNumber(tokens);
					readExpression = BreaklangReadExpression.fromArraySliceLookup(readExpression, arrayIndex, arrayIndexEnd);
					consumeExpectedToken(BreaklangTokenType.CHAR_CLOSE_SQUARE_BRACKET, tokens);
					break STRUCT_PATH_LOOP;
				}
			}
			case CHAR_CLOSE_BRACE -> {
				tokens.previous();
				break STRUCT_PATH_LOOP;
			}
			
			default -> 
				throw new IllegalStateException("Expected a DOT/STAR/OPEN_SQUARE_BRACKET/CLOSE_BRACE token. Received: " + token.type());
			}
		}
		
		// PARSE: `#TYPE` optional
		Optional<BreaklangToken> typeToken = tryConsumeToken(BreaklangTokenType.KEYWORD_TYPE, tokens);
		if (typeToken.isPresent()) {
			readExpression = BreaklangReadExpression.fromTypeInfo(readExpression);
		}
		
		// PARSE: `}`
		consumeExpectedToken(BreaklangTokenType.CHAR_CLOSE_BRACE, tokens);
		return readExpression;
	}

	private List<BreaklangPrintDirective> parsePrint(CopyableListIterator<BreaklangToken> tokens) {
		
//		BreaklangToken printToken = tokens.next();
//		if(printToken.type() != BreaklangTokenType.KEYWORD_PRINT) {
//			throw new IllegalStateException("Expected a PRINT directive. Received: " + printToken.type());
//		}
		consumeExpectedToken(BreaklangTokenType.KEYWORD_PRINT, tokens);
		consumeWhitespace(tokens);
		
		List<BreaklangPrintDirective> printExpressions = new ArrayList<>();
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
//			if (token.type() == BreaklangTokenType.CHAR_END_OF_LINE) {
//				break;
//			}
//			else 
			if (token.type() == BreaklangTokenType.CHAR_OPEN_BRACE) {
				tokens.previous();
				printExpressions.add(BreaklangPrintDirective.fromReadExpression(parseReadExpression(tokens)));
			}
			else if (token.type() == BreaklangTokenType.KEYWORD_PRINT_VAR) {
				consumeWhitespace(tokens);
				BreaklangReadExpression rootReadExpression = parseReadExpression(tokens);
				ArrayList<String> readExpressionText = new ArrayList<>();
				BreaklangReadExpression readExpression = rootReadExpression;
				while(readExpression != null) {
					String text = switch (readExpression.type()) {
						case REGISTER, SYMBOL, BREAKLANG_VARIABLE, LAZY_NAMED_LOOKUP -> readExpression.targetName().get();
						case FIELD_LOOKUP -> "." + readExpression.targetName().get();
						case DEREFERENCE -> "*";
						case ADDRESS_OF -> "&";
						case ARRAY_LOOKUP, ARRAY_SLICE_LOOKUP -> "[" + readExpression.targetName().get() + "]";
						case TYPE_INFO -> throw new IllegalArgumentException("PRINT_VAR read expressions are not allowed to have TYPE_INFO lookup.");
					};
					readExpressionText.add(text);
					readExpression = readExpression.innerExpression().orElse(null);
				}
				StringBuilder sb = new StringBuilder();
				Lists.reverse(readExpressionText)
						.stream()
						.forEach(sb::append);
				sb.append(" = ");
				printExpressions.add(BreaklangPrintDirective.fromLiteral(sb.toString()));
				printExpressions.add(BreaklangPrintDirective.fromReadExpression(rootReadExpression));
				printExpressions.add(BreaklangPrintDirective.fromLiteral(" ("));
				printExpressions.add(BreaklangPrintDirective.fromReadExpression(
						BreaklangReadExpression.fromTypeInfo(rootReadExpression)));
				printExpressions.add(BreaklangPrintDirective.fromLiteral(")"));
			}
//			else if(token.type().isConstant()) {
//			}
			else {

				CharSequence literal = token.value();
				if (printExpressions.size() > 0 
						&& printExpressions.get(printExpressions.size() - 1).type() == BreaklangPrintDirectiveType.LITERAL) {
					
					BreaklangPrintDirective prevPrintExpression = printExpressions.remove(printExpressions.size() - 1);
					StringBuilder builder = new StringBuilder();
					builder.append(prevPrintExpression.literal().get());
					builder.append(literal);
					literal = builder;
				}
				printExpressions.add(BreaklangPrintDirective.fromLiteral(literal.toString()));
//				throw new IllegalStateException("Expected a TODO directive. Received: " + printToken.type());
			}
		}
		return printExpressions;
	}
	
	private static void consumeWhitespace(CopyableListIterator<BreaklangToken> tokens) {
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
			if (token.type() != BreaklangTokenType.CHAR_WHITESPACE
					&& token.type() != BreaklangTokenType.CHAR_END_OF_LINE) {
				tokens.previous();
				break;
			}
		}
	}
	
	private static String consumeFieldName(CopyableListIterator<BreaklangToken> tokens) {
		StringBuilder builder = new StringBuilder();
		while(tokens.hasNext()) {
			BreaklangToken token = tokens.next();
			if (token.type() == BreaklangTokenType.CHAR_FIELD_NAME
					|| token.type() == BreaklangTokenType.CHAR_NUMERIC
					|| token.type() == BreaklangTokenType.CHAR_ALPHANUMERIC) {

				builder.append(token.value());
			}
			else {
				tokens.previous();
				break;
			}
		}
		return builder.toString();
	}
	
	private int consumeNumber(CopyableListIterator<BreaklangToken> tokens) {
		BreaklangToken numberToken = consumeExpectedToken(BreaklangTokenType.CHAR_NUMERIC, tokens);
		return Integer.parseInt(numberToken.value().toString());
	}
	
	private boolean tryParseDereference(CopyableListIterator<BreaklangToken> tokens)
	{
		return tryConsumeToken(BreaklangTokenType.CHAR_STAR, tokens).isPresent();
	}
	
	private Optional<BreaklangToken> tryConsumeToken(BreaklangTokenType expectedTokenType, CopyableListIterator<BreaklangToken> tokens)
	{
		if(!tokens.hasNext()) {
			return Optional.empty();
		}
		BreaklangToken token = tokens.next();
		if (token.type() == expectedTokenType) {
			return Optional.of(token);
		}
		else {
			tokens.previous();
			return Optional.empty();
		}
	}
	
	private BreaklangToken consumeExpectedToken(BreaklangTokenType expectedTokenType, CopyableListIterator<BreaklangToken> tokens)
	{
		if(!tokens.hasNext()) {
			throw new IllegalStateException(
					"Expected a " + expectedTokenType + " token. Received: end-of-token-stream.");
		}
		BreaklangToken token = tokens.next();
		if (token.type() != expectedTokenType) {
			throw new IllegalStateException(
					"Expected a " + expectedTokenType + " token. Received: " + token);
		}
		return token;
	}
}
