/**
 * Stuart Millar 13616005 
 */

package source_code;
import java.util.regex.*;

/**
 * class for a RegexObj with the pattern and human readable description
 * @author Stuart
 *
 */
public class RegexObj {
	
	/**
	 * constructor with args
	 * @param regexPattern - string with regex pattern
	 * @param description - string with human readable description
	 */
	public RegexObj(String regexPattern, String description){
		this.regexPattern = Pattern.compile(regexPattern);
		this.description = description;
	}
	
	// the pattern to compile
	private Pattern regexPattern;
	/**
	 * @return the regexPattern
	 */
	public Pattern getRegexPattern() {
		return regexPattern;
	}
	/**
	 * @param regexPattern the regexPattern to set
	 */
	public void setRegexPattern(Pattern regexPattern) {
		this.regexPattern = regexPattern;
	}
	/**
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}
	/**
	 * @param description the description to set
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	// more human readable description / explanation
	private String description;

}
