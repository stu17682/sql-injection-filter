/*
 * Stuart Millar 13616005
 */

package source_code;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.io.FileNotFoundException;

/**
 * SQL Filter class
 * 
 * @author Stuart Millar 13616005
 *
 */
public class SQLFilter {

	// declare array of commands to check against, can add to this easily
	public static final String stringsToCheck[] = { "select", "drop", "from",
			"exec", "exists", "update", "delete", "insert", "cast", "http",
			"sql", "null", "like", "mysql", "()", "information_schema",
			"sleep", "version", "join", "declare", "having", "signed", "alter",
			"union", "where", "create", "shutdown", "grant", "privileges" };

	// for reference, regex metachars that need escaped <([{\^-=$!|]})?*+.>

	// instantiate each RegexObj with the expression and a plain english
	// description

	// /* and */
	public static RegexObj regex1 = new RegexObj("(/\\*).*(\\*/)",
			"Found /* and */");

	// -- at the end
	public static RegexObj regex2 = new RegexObj("(--.*)$", "-- at end of sql");

	// ; and at least one " or '
	public static RegexObj regex3 = new RegexObj(";+\"+\'",
			"One or more ; and at least one \" or \'");

	// two or more "
	public static RegexObj regex4 = new RegexObj("\"{2,}+", "Two or more \"");

	// two or more '
	public static RegexObj regex5 = new RegexObj("\'{2,}+", "Two or more \'");

	// anydigit=anydigit
	public static RegexObj regex6 = new RegexObj("\\d=\\d", "anydigit=anydigit");

	// two or more white spaces in a row
	public static RegexObj regex7 = new RegexObj("(\\s\\s)+",
			"two or more white spaces in a row");

	// # at the end
	public static RegexObj regex8 = new RegexObj("(#.*)$", "# at end of sql");

	// two or more %
	public static RegexObj regex9 = new RegexObj("%{2,}+",
			"Two or more \\% signs");

	// admin and one of [; ' " =] before or after admin
	public static RegexObj regex10 = new RegexObj(
			"([;\'\"\\=]+.*(admin.*))|((admin.*).*[;\'\"\\=]+)",
			"admin (and variations like administrator) and one of [; ' \" =] before or after admin");

	// ASCII in hex
	public static RegexObj regex11 = new RegexObj("%+[0-7]+[0-9|A-F]+",
			"ASCII Hex");

	// declare array to hold each regex, can add to this easily
	public static final RegexObj regexes[] = { regex1, regex2, regex3, regex4,
			regex5, regex6, regex7, regex8, regex9, regex10, regex11 };

	/**
	 * Main method / starting point
	 * 
	 * @param args
	 */
	public static void main(String[] args) {

		// hardcode the name of the output file e.g. output80.txt for results from Queries80.txt, or output20.txt for results from Queries20.txt
		// this will be created in the project directory unless you specify an absolute path
		File file = new File("output20.txt");
				
		// if file doesn't exist then create it
		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			// otherwise delete it for fresh output
			file.delete();
		}

		// vars for stats classification
		int condPos = 0;
		int condNeg = 0;
		int truePos = 0;
		int trueNeg = 0;
		int falsePos = 0;
		int falseNeg = 0;

		// string counter
		int stringCounter = 0;

		System.out.println("--Welcome to the CSIT SQL Injection Filter--");

		// for each line in the text file, read each line of the SQL strings in
		// from the text file - the label and the string itself
		try {

			// create new file object, hardcode and pass in the dataset file e.g. Queries80.txt or Queries20.txt.  If the file is not present in the project directory
			// you will need to specify the absolute path
			File sqlFile = new File("Queries20.txt");
					
			// create new file reader
			FileReader fileReader = new FileReader(sqlFile);

			// create new buffered reader
			BufferedReader buffReader = new BufferedReader(fileReader);

			// declare string to hold a line
			String line;
			// initialise it to hold an empty string
			line = "";

			// int hold 0 or 1, 0 is benign and 1 is malicious string
			int prediction;

			// read in a line of text from the file
			line = buffReader.readLine();

			while (line != null) {

				// increment string counter
				stringCounter++;

				// print it
				System.out.printf("-----------------------------");
				System.out.printf("\nSample %d = %s\n", stringCounter, line);

				// get the label and store it
				char label = line.charAt(0);

				// increment the true totals accordingly
				if (label == '0') {
					condNeg++;
				} else if (label == '1') {
					condPos++;
				} else {
					System.out.println("Invalid label...");
				}
				// trace
				System.out.printf("True Label = %c\n", label);

				// get the sql string
				String sqlString = line.substring(2);
				System.out.printf("SQL = %s\n", sqlString.toLowerCase());

				// if true is returned, then classify as malware, otherwise
				// benign
				if (sqlHandler(sqlString)) {
					prediction = 1;
					if (Character.getNumericValue(label) == prediction) {
						// hit
						truePos++;
					} else {
						// false alarm
						falsePos++;
					}
				} else {
					prediction = 0;
					if (Character.getNumericValue(label) == prediction) {
						// correctly rejected
						trueNeg++;
					} else {
						// missed it
						falseNeg++;
					}
				}

				// write to output file - line, label,
				outputToFile(sqlString, label, prediction, file);

				// and read in the next line
				line = buffReader.readLine();

			}

			// close resources
			buffReader.close();
			fileReader.close();

			// print results
			System.out.println("*******************************");
			System.out.printf(
					"Results for dataset file %s.\nOutput file is %s\n",
					sqlFile.getAbsolutePath(), file.getAbsolutePath());
			System.out.printf("\nTotal strings read = %s\n", stringCounter);
			System.out
					.printf("True malware = %d : Hits (true positives) = %d, Misses (false negatives) = %d\n",
							condPos, truePos, falseNeg);
			System.out
					.printf("True benign = %d : Correct Rejections (true negatives) = %d, False Alarms (false positives) = %d\n",
							condNeg, trueNeg, falsePos);
			System.out.println();
			System.out
					.printf("Detection Rate (True Positive Rate - how well the filter correctly classifies malware) = %.1f%%\n",
							(double) truePos / (double) condPos * 100);
			System.out
					.printf("Rejection Rate (True Negative Rate - how well the filter correctly classifies benign) = %.1f%%\n",
							(double) trueNeg / (double) condNeg * 100);
			System.out.printf("Accuracy = %.1f%%\n",
					(double) (truePos + trueNeg) / (double) (condPos + condNeg)
							* 100);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Method to kick off filtering a SQL string
	 * @param sqlString - the SQL sample
	 * @return a bool, if it true then it is malicious, if false it is benign
	 */
	public static boolean sqlHandler(String sqlString) {

		// use two more bools for returns from sqlStringChecker and sqlRegexChecker
		boolean pass1 = false;
		boolean pass2 = false;

		// call both, pass in the string
		pass1 = sqlStringChecker(sqlString);
		pass2 = sqlRegexChecker(sqlString);

		// if either checker is true return true otherwise return false
		if (pass1 || pass2) {
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Method to check for stringsToCheck in the string passed in
	 * @param sqlToCheck - the SQL sample
	 * @return a bool, if true then it is malicious, if false then benign
	 */
	public static boolean sqlStringChecker(String sqlToCheck) {

		boolean pass = false;

		System.out.println("\nRunning SQL String Checker");

		// convert to lower case to handle obfuscation with mixed upper and
		// lower case
		sqlToCheck = sqlToCheck.toLowerCase();

		// for each string in stringsToCheck
		for (String command : stringsToCheck) {

			if (sqlToCheck.contains(command)) {

				System.out
						.printf("SQL string found (%s), predicted label = 1\n",
								command);

				if (!pass) {
					pass = true;
				}
			}

		}

		if (!pass) {
			System.out.println("No SQL command found, predicted label = 0");
		}

		return pass;
	}

	/**
	 * Method to check SQL sample against the regexes
	 * @param sqlToCheck
	 * @return a bool, true if malicious, false if benign
	 */
	public static boolean sqlRegexChecker(String sqlToCheck) {

		System.out.println("\nRunning SQL Regex Checker");

		// bool for each regex
		boolean pass = false;
		// bool to return overall
		boolean overall = false;

		Matcher matcher;

		// convert to lower case to handle obfuscation with mixed upper and
		// lower case
		sqlToCheck = sqlToCheck.toLowerCase();

		// regex checking
		for (RegexObj regex : regexes) {

			// check sqlToCheck vs regex, if pattern returns i.e. regex returns
			// true

			matcher = regex.getRegexPattern().matcher(sqlToCheck);

			pass = matcher.find();

			if (pass) {

				System.out
						.printf("Malicious input found via regex (%s), predicted label = 1\n",
								regex.getDescription());

			} else {
				System.out
						.printf("No malicious input found via regex (%s), predicted label = 0\n",
								regex.getDescription());

			}

			// if a regex returns true for the first time (i.e. overall is still
			// false), then make overall true
			if ((pass) && (!overall)) {
				overall = true;
			}
		}
		return overall;
	}

	/**
	 * Method for outputing basic classification info to file
	 * @param SQL - the SQL sample
	 * @param label - the true label
	 * @param prediction - the predicted label
	 * @param file - the file to write to
	 */
	public static void outputToFile(String SQL, char label, int prediction,
			File file) {

		// create result string
		String result = SQL + " True Label = " + label + " Predicted Label = "
				+ prediction + "\r\n";

		try {

			// true = append to end of file, false = write from the start
			FileWriter fileWriter = new FileWriter(file.getAbsolutePath(), true);

			// do the writing
			BufferedWriter bufferWriter = new BufferedWriter(fileWriter);
			bufferWriter.write(result);
		
			// close resources
			bufferWriter.close();
			fileWriter.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
