package aquesnel.ghidra.debugger.breaklang;



import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public enum BreaklangTokenType {
		KEYWORD_SET("#SET", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_PRINT("#PRINT", Arrays.asList("#P"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_PRINT_VAR("#PRINT_VAR", Arrays.asList("#PV"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_PARSE_COMMENT("#PARSE_COMMENT", Arrays.asList("#PC"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_PRINT_LOCALS("#PRINT_LOCALS", Arrays.asList("#PL"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_READ("#READ", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_BREAKLANG_VARIABLE("#VAR:", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_SYMBOL("#SYM:", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_REGISTER("#REG:", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_BREAK("#BREAK", BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_CONTINUE("#CONTINUE", Arrays.asList("#C"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_VERBOSE("#VERBOSE", Arrays.asList("#V"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_TYPE("#TYPE", Arrays.asList("#T"), BreaklangTokenTypeGroup.KEYWORD),
		KEYWORD_ARROW("->", BreaklangTokenTypeGroup.KEYWORD),
		CHAR_EQUALS("=", BreaklangTokenTypeGroup.LITERAL),
		CHAR_DOT("\\.", ".", BreaklangTokenTypeGroup.LITERAL),
		CHAR_STAR("\\*", "*", BreaklangTokenTypeGroup.LITERAL),
		CHAR_OPEN_BRACE("\\{", "{", BreaklangTokenTypeGroup.LITERAL),
		CHAR_CLOSE_BRACE("}", BreaklangTokenTypeGroup.LITERAL),
		CHAR_OPEN_SQUARE_BRACKET("\\[", "[", BreaklangTokenTypeGroup.LITERAL),
		CHAR_CLOSE_SQUARE_BRACKET("]", BreaklangTokenTypeGroup.LITERAL),
		CHAR_AMPERSAND("&", BreaklangTokenTypeGroup.LITERAL),
		CHAR_POUND("#", BreaklangTokenTypeGroup.LITERAL),
		CHAR_COLON(":", BreaklangTokenTypeGroup.LITERAL),
		CHAR_END_OF_LINE("\n", BreaklangTokenTypeGroup.LITERAL),
		CHAR_NUMERIC("[0-9]+", BreaklangTokenTypeGroup.CHARACTERS),
		CHAR_ALPHANUMERIC("[a-zA-Z0-9]+", BreaklangTokenTypeGroup.CHARACTERS),
		CHAR_FIELD_NAME(  "[a-zA-Z0-9_]+", BreaklangTokenTypeGroup.CHARACTERS),
		CHAR_WHITESPACE("[ \t\n]+", BreaklangTokenTypeGroup.WHITESPACE),
		CHAR_OTHER(".*", BreaklangTokenTypeGroup.CHARACTERS),
		;
		
		private static final List<BreaklangTokenType> WILDCARD_TYPES_BY_SPECIFICITY =
				Collections.unmodifiableList(Arrays.asList(
					CHAR_WHITESPACE,
					CHAR_NUMERIC,
					CHAR_FIELD_NAME,
					CHAR_ALPHANUMERIC,
					CHAR_OTHER
					));
//		private static final EnumSet<BreaklangTokenType> VARIABLE_REGEX =
//				EnumSet.copyOf(
//						EnumSet.allOf(BreaklangTokenType.class)
//							.stream()
//							.filter(Predicate.not(BreaklangTokenType::isConstant))
//							.collect(Collectors.toSet())
////						CHAR_ALPHANUMERIC,
////						CHAR_FIELD_NAME,
////						CHAR_WHITESPACE,
////						CHAR_ANY
//						);
//		private static final EnumSet<BreaklangTokenType> CONSTANT_REGEX =
//				EnumSet.complementOf(VARIABLE_REGEX);
		
		private static final Map<String, BreaklangTokenType> TYPES_BY_CONSTANT_REGEX =
				EnumSet.allOf(BreaklangTokenType.class)
				.stream()
				.filter(BreaklangTokenType::isConstant)
				.collect(
						Collectors.toMap(
								type -> type.constant(),
								Function.identity()));
		
		private static record ConstantTpyePair(String constant, BreaklangTokenType type) {};
		
		private static final NavigableMap<String, BreaklangTokenType> TYPES_BY_KEYWORD =
				EnumSet.allOf(BreaklangTokenType.class)
				.stream()
				.filter(BreaklangTokenType::isKeyword)
				.flatMap(type -> type.allConstants()
										.stream()
										.map(constant -> new ConstantTpyePair(constant, type)))
				.collect(
						Collectors.toMap(
								pair -> pair.constant(),
								pair -> pair.type(),
								(a,b) -> a,
								TreeMap::new));
		
		public static BreaklangTokenType getCharType(char tokenValue) {
			
			CharSequence charAsSequence = CharBuffer.wrap(new char[] {tokenValue});
			BreaklangTokenType constanceTokenType = TYPES_BY_CONSTANT_REGEX.get(charAsSequence.toString());
			if (constanceTokenType != null) {
				return constanceTokenType;
			}
			
			for (BreaklangTokenType type: WILDCARD_TYPES_BY_SPECIFICITY) {
				if (type.matches(charAsSequence)) {
					return type;
				}
			}

			throw new IllegalArgumentException("Unknown BreaklangTokenType for value: '" + tokenValue + "'");
		}
		
		public static Optional<BreaklangTokenType> prefixOfKeywordType(String candidate) {
			Entry<String, BreaklangTokenType> entry = TYPES_BY_KEYWORD.ceilingEntry(candidate);
			if (entry!= null && entry.getKey().toString().startsWith(candidate)) {
				return Optional.of(entry.getValue());
			}
			else {
				return Optional.empty();
			}
		}
		
		private final BreaklangTokenTypeGroup mGroup;
		private final Pattern mRegex;
		private final String mConstant;
		private final List<String> mAlternativeConstants;
		
		private BreaklangTokenType(String regex, BreaklangTokenTypeGroup group) {
			this(regex, group.isConstant() ? regex : null, Collections.emptyList(), group);
		}
		private BreaklangTokenType(String regex, List<String> alternativeConstants, BreaklangTokenTypeGroup group) {
			this(regex, group.isConstant() ? regex : null, alternativeConstants, group);
		}
		private BreaklangTokenType(String regex, String constant, BreaklangTokenTypeGroup group) {
			this(regex, constant, Collections.emptyList(), group);
		}
		private BreaklangTokenType(String regex, String constant, List<String> alternativeConstants, BreaklangTokenTypeGroup group) {
			if (group == BreaklangTokenTypeGroup.LITERAL) {
				Objects.requireNonNull(constant);
			}

			mRegex = Pattern.compile(regex);
			mConstant = constant;
			mGroup = Objects.requireNonNull(group);
			mAlternativeConstants = Objects.requireNonNull(alternativeConstants);
		}
		public boolean isConstant() {
			return mGroup.isConstant();
		}
		
		public boolean isKeyword() {
			return mGroup == BreaklangTokenTypeGroup.KEYWORD;
		}
		
		public String constant() {
			return mConstant;
		}
		
		public List<String> allConstants() {
			List<String> result = new ArrayList<>(mAlternativeConstants.size() + 1);
			if(mConstant != null) {
				result.add(mConstant);
			}
			result.addAll(mAlternativeConstants);
			return result;
		}
		
		public boolean matchesConstant(CharSequence value) {
			if(mConstant != null && mConstant.equals(value)) {
				return true;
			}
			return mAlternativeConstants.stream().anyMatch(s -> s.equals(value));
		}
		
		public boolean matches(CharSequence value) {
			return mRegex.matcher(value).matches();
		}
		
		public boolean canAppend(String value) {
			if (isConstant()) {
				return false;
			}
			
			return mRegex.matcher(value).matches();
		}
		
		public boolean canMerge(BreaklangTokenType other) {
			if (isConstant() || other.isConstant()) {
				return false;
			}
			
			return mGroup == other.mGroup;
		}
	}