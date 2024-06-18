package aquesnel.ghidra.debugger.breaklang;

import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class BreaklangTokenizer {

	public static List<BreaklangToken> parseTokens(CharBuffer input) {
		List<BreaklangToken> rawTokens = new ArrayList<>();
		CharSequence remainingInput = input;
		while (remainingInput.length() > 0) {
			BreaklangToken token = parseNextToken(remainingInput);
			rawTokens.add(token);
			remainingInput = remainingInput.subSequence(token.value().length(), remainingInput.length());
		}
		return mergeTokensIntoKeywords(rawTokens);
	}
	
	private static BreaklangToken parseNextToken(CharSequence input) {
		if (input.length() == 0) {
			return new BreaklangToken(BreaklangTokenType.CHAR_END_OF_LINE, "");
		}
		
		char nextChar = input.charAt(0);
		BreaklangTokenType tokenType = BreaklangTokenType.getCharType(nextChar);
		
		int nextCharIndex = 1;
		for (; nextCharIndex < input.length(); nextCharIndex++) {
			nextChar = input.charAt(nextCharIndex);
			BreaklangTokenType candidateTokenType = BreaklangTokenType.getCharType(nextChar);
			if(tokenType != candidateTokenType) {
				break;
			}
		}
		CharSequence tokenValue = input.subSequence(0, nextCharIndex);
		return new BreaklangToken(tokenType, tokenValue);
	}
	
	private static List<BreaklangToken> mergeTokensIntoKeywords(List<BreaklangToken> rawTokens) {

		List<BreaklangToken> result = new ArrayList<>();
		for (int i = 0; i < rawTokens.size(); i++) {
			BreaklangToken currentToken = rawTokens.get(i);
			StringBuilder mergedTokenValue = new StringBuilder();
//			mergedTokenValue.append(currentToken.value());
			int j = 0;
			int extraTokensConsumed = 0;
			while (i + j < rawTokens.size()) {
				mergedTokenValue.append(rawTokens.get(i+j).value());
				String mergedTokenString = mergedTokenValue.toString();
				Optional<BreaklangTokenType> prefixOfKeyword = BreaklangTokenType.prefixOfKeywordType(mergedTokenString);
				if (prefixOfKeyword.isPresent()) {
					BreaklangTokenType keywordType = prefixOfKeyword.get();
					if (keywordType.matchesConstant(mergedTokenString)) {
						currentToken = new BreaklangToken(keywordType, mergedTokenString);
						extraTokensConsumed = j;
					}
					j++;
				}
				else
				{
					break;
				}
			}
			i += extraTokensConsumed;
			result.add(currentToken);
		}
		return result;
	}
}
