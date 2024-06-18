package aquesnel.ghidra.debugger.breaklang;
import java.util.Arrays;
import java.util.Collections;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;

import aquesnel.ghidra.debugger.breaklang.BreaklangAssignmentDirective;
import aquesnel.ghidra.debugger.breaklang.BreaklangParseResult;
import aquesnel.ghidra.debugger.breaklang.BreaklangParser;
import aquesnel.ghidra.debugger.breaklang.BreaklangPrintDirective;
import aquesnel.ghidra.debugger.breaklang.BreaklangReadExpression;

public final class BreaklangParserTest {

	@Test
	public void test_parse_whenDescriptionOnly_returnsDescriptionOnly() {
		
		// test
		BreaklangParseResult result = new BreaklangParser().parse("Hello World#!");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo("Hello World#!"));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenBreakOnly_returnsBreakOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#BREAK");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenContinueOnly_returnsContinueOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#CONTINUE");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenContinueShorthandOnly_returnsContinueOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#C");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}

	@Test
	public void test_parse_whenVerboseOnly_returnsVerboseOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#VERBOSE");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}

	@Test
	public void test_parse_whenVerboseShorthandOnly_returnsVerboseOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#V");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenPrintLocalsOnly_returnsPrintLocalsOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT_LOCALS");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenPrintLocalsShorthandOnly_returnsPrintLocalsOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PL");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenAssignmentOnly_returnsAssignmentOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#SET a = {#READ #REG:eax}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(
				Collections.singletonList(
						new BreaklangAssignmentDirective(
								"a",
								BreaklangReadExpression.fromRegister("eax")))));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(Collections.emptyList()));
	}
	
	@Test
	public void test_parse_whenPrintLiteralOnly_returnsPrintOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a literal value");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a literal value"))));
	}
	
	@Test
	public void test_parse_whenPrintShorthandOnly_returnsPrintOnly() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#P a literal value");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a literal value"))));
	}
	
	@Test
	public void test_parse_whenPrintMultiLine_returnsPrintMultiLine() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {aVar} \n b = {bVar}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromLazyLookup("aVar")),
						BreaklangPrintDirective.fromLiteral(" \n b = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromLazyLookup("bVar")))));
	}
	
	@Test
	public void test_parse_whenPrintReadRegister_returnsPrintReadRegister() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #REG:eax}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromRegister("eax")))));
	}
	
	@Test
	public void test_parse_whenPrintReadBreaklangVariable_returnsPrintReadBreaklangVariable() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #VAR:temp}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromBreaklangVariable("temp")))));
	}
	
	@Test
	public void test_parse_whenPrintReadSymbol_returnsPrintReadSymbol() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:var}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromSymbol("var")))));
	}
	
	@Test
	public void test_parse_whenPrintReadDereference_returnsPrintReadDereference() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:var*}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromDereference(
										BreaklangReadExpression.fromSymbol("var"))))));
	}
	
	@Test
	public void test_parse_whenPrintReadFieldLookup_returnsPrintReadFieldLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:var.field_0x10}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromFieldLookup(
										BreaklangReadExpression.fromSymbol("var"),
										"field_0x10")))));
	}
	
	@Test
	public void test_parse_whenPrintReadArrowFieldLookup_returnsPrintReadArrowFieldLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:var->field_0x10}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromFieldLookup(
										BreaklangReadExpression.fromDereference(
												BreaklangReadExpression.fromSymbol("var")),
										"field_0x10")))));
	}
	
	@Test
	public void test_parse_whenPrintReadAddressOf_returnsPrintReadAddressOf() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:var&}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromAddressOf(
										BreaklangReadExpression.fromSymbol("var"))))));
	}
	
	@Test
	public void test_parse_whenPrintReadArray_returnsPrintReadArray() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:array[0]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArrayLookup(
										BreaklangReadExpression.fromSymbol("array"), 0)))));
	}
	
	@Test
	public void test_parse_whenPrintReadArraySlice_returnsPrintReadArraySlice() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ #SYM:array[0:5]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArraySliceLookup(
										BreaklangReadExpression.fromSymbol("array"), 0, 5)))));
	}
	
	@Test
	public void test_parse_whenPrintReadLazyLookup_returnsPrintReadLazyLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#READ lazy}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromLazyLookup("lazy")))));
	}
	
	@Test
	public void test_parse_whenPrintRegister_returnsPrintReadRegister() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#REG:eax}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromRegister("eax")))));
	}
	
	@Test
	public void test_parse_whenPrintBreaklangVariable_returnsPrintReadBreaklangVariable() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#VAR:temp}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromBreaklangVariable("temp")))));
	}
	
	@Test
	public void test_parse_whenPrintSymbol_returnsPrintReadSymbol() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:var}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromSymbol("var")))));
	}
	
	@Test
	public void test_parse_whenPrintDereference_returnsPrintReadDereference() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:var*}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromDereference(
										BreaklangReadExpression.fromSymbol("var"))))));
	}
	
	@Test
	public void test_parse_whenPrintFieldLookup_returnsPrintReadFieldLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:var.field_0x10}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromFieldLookup(
										BreaklangReadExpression.fromSymbol("var"),
										"field_0x10")))));
	}
	
	@Test
	public void test_parse_whenPrintArrowFieldLookup_returnsPrintReadArrowFieldLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:var->field_0x10}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromFieldLookup(
										BreaklangReadExpression.fromDereference(
												BreaklangReadExpression.fromSymbol("var")),
										"field_0x10")))));
	}
	
	@Test
	public void test_parse_whenPrintAddressOf_returnsPrintReadAddressOf() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:var&}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromAddressOf(
										BreaklangReadExpression.fromSymbol("var"))))));
	}
	
	@Test
	public void test_parse_whenPrintArray_returnsPrintReadArray() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:array[0]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArrayLookup(
										BreaklangReadExpression.fromSymbol("array"), 0)))));
	}
	
	@Test
	public void test_parse_whenPrintArraySlice_returnsPrintReadArraySlice() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {#SYM:array[0:5]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArraySliceLookup(
										BreaklangReadExpression.fromSymbol("array"), 0, 5)))));
	}
	
	@Test
	public void test_parse_whenPrintLazyLookup_returnsPrintLazyLookup() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT a = {lazy}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("a = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromLazyLookup("lazy")))));
	}
	
	@Test
	public void test_parse_whenPrintVariable_returnsPrintVariableWithPrefix() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT #PRINT_VAR {#READ #REG:eax*.array_0x10[2].slice[1:5]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("eax*.array_0x10[2].slice[1:5] = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArraySliceLookup(
										BreaklangReadExpression.fromFieldLookup(
												BreaklangReadExpression.fromArrayLookup(
														BreaklangReadExpression.fromFieldLookup(
																BreaklangReadExpression.fromDereference(
																		BreaklangReadExpression.fromRegister("eax")),
																"array_0x10"),
														2),
												"slice"), 
										1, 5)),
						BreaklangPrintDirective.fromLiteral(" ("),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromTypeInfo(
									BreaklangReadExpression.fromArraySliceLookup(
											BreaklangReadExpression.fromFieldLookup(
													BreaklangReadExpression.fromArrayLookup(
															BreaklangReadExpression.fromFieldLookup(
																	BreaklangReadExpression.fromDereference(
																			BreaklangReadExpression.fromRegister("eax")),
																	"array_0x10"),
															2),
													"slice"), 
											1, 5))),
						BreaklangPrintDirective.fromLiteral(")"))));
	}
	
	@Test
	public void test_parse_whenPrintVariableShorthand_returnsPrintVariableWithPrefix() {
		// test
		BreaklangParseResult result = new BreaklangParser().parse("#PRINT #PV {#READ #REG:eax*.array_0x10[2].slice[1:5]}");
		
		// verify
		
		MatcherAssert.assertThat(result.description(), CoreMatchers.equalTo(""));
		MatcherAssert.assertThat(result.doBreak(), CoreMatchers.equalTo(true));
		MatcherAssert.assertThat(result.verbose(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.printLocals(), CoreMatchers.equalTo(false));
		MatcherAssert.assertThat(result.assignments(), CoreMatchers.equalTo(Collections.emptyList()));
		MatcherAssert.assertThat(result.prints(), CoreMatchers.equalTo(
				Arrays.asList(
						BreaklangPrintDirective.fromLiteral("eax*.array_0x10[2].slice[1:5] = "),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromArraySliceLookup(
										BreaklangReadExpression.fromFieldLookup(
												BreaklangReadExpression.fromArrayLookup(
														BreaklangReadExpression.fromFieldLookup(
																BreaklangReadExpression.fromDereference(
																		BreaklangReadExpression.fromRegister("eax")),
																"array_0x10"),
														2),
												"slice"), 
										1, 5)),
						BreaklangPrintDirective.fromLiteral(" ("),
						BreaklangPrintDirective.fromReadExpression(
								BreaklangReadExpression.fromTypeInfo(
									BreaklangReadExpression.fromArraySliceLookup(
											BreaklangReadExpression.fromFieldLookup(
													BreaklangReadExpression.fromArrayLookup(
															BreaklangReadExpression.fromFieldLookup(
																	BreaklangReadExpression.fromDereference(
																			BreaklangReadExpression.fromRegister("eax")),
																	"array_0x10"),
															2),
													"slice"), 
											1, 5))),
						BreaklangPrintDirective.fromLiteral(")"))));
	}	
}
