/**
 * @author Jeremy Giese
 * Written for Dr. Wahjudi in CS 430
 * date: February 15, 2018
 * This programs purpose is to find passwords using mangles upon strings from a dictionary and the crypt method from JCrypt.
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;


public class PassCrack{
	static String[] dictionary;
	static String userPassList = "";
	
	//main
	public static void main(String[] args) {
		createDictionary();
		String fileName = "";
		int numToFind = 0;
		String userPass = "";
		int numberFound = 0;
		String[] notFound=new String[20];
		
		for (int n = 0; n < notFound.length; n++) {
			notFound[n]="thisStringIsLongerThanEleven";
		}
		boolean fileFound = false;
		boolean fileWritten = false;
		while (!fileFound) {
			System.out.println("Please input filename, if not in current directory input full directory");
			Scanner aScan = new Scanner(System.in);
			fileName = aScan.nextLine();
			long startTime = System.currentTimeMillis();
			String[] fileContent = readFile(fileName);
			if (fileContent.length > 3) {
				fileFound = true;
				while (numToFind < fileContent.length) {
					userPass = cracker(fileContent[numToFind]);
					numToFind++;
					if (!userPass.equals("thisStringIsLongerThanEleven")) {
						userPassList += userPass + "\n";
						numberFound++;
						System.out.println(userPass);

					}else {
						notFound[numToFind-1]=fileContent[numToFind-1];
					}
				}

				long endTime = System.currentTimeMillis();
				System.out.println((endTime - startTime) / 1000.0 + " seconds for "+numberFound+" out of "+(fileContent.length)+" passwords.");
				fileWritten=writeFile(userPassList);
				if (fileWritten) {
					System.out.println("saved to output.txt");
				} else {
					System.out.println("File was not written");
				}
			}
		}/*System.out.println("Beginning brute force");
		String[] userHashArray=new String[20-numberFound];
		for (int i = 0; i < userHashArray.length; i++) {
			userHashArray[i]="HELP";
		}
		int j=0;
		for (int i = 0; i < notFound.length; i++) {
			if(!notFound[i].equals("thisStringIsLongerThanEleven")) {
				String[] userArray=notFound[i].split(":");
				userHashArray[j]=userArray[1];
				j++;
				System.out.println(userHashArray[j-1]);
			}
			if(userHashArray.length>0) {
			String[] found=findRandom(userHashArray);
			
			System.out.println("User: "+notFound[i].split(":")[0]+" Password: "+found);
			}
		}*/
	}

/**
 * 
 * @param userString the line containing user information from passwd file
 * @return the user password if found using mangle methods
 */
	public static String cracker(String userString) {
		String[] brokenDownUser = userString.split(":");
		// System.out.println(brokenDownUser.length);
		int currentKey = -2;
		boolean foundBoolean = false;
		String found = "";
		String toCheck = brokenDownUser[0];
		String toReturn = "thisStringIsLongerThanEleven";
		String passHash=brokenDownUser[1];
		int charCheck = 32;
		String userLast = brokenDownUser[4].split("\\s")[1];
		//System.out.println(userLast);
		String salt = passHash.substring(0, 2);
		String passFound = "";
		// System.out.println(userString);
		if(dictionary.length>0) {
			while (!foundBoolean&&currentKey < dictionary.length) {
				if (currentKey < dictionary.length && currentKey > -1) {
					toCheck = dictionary[currentKey];

					charCheck = 32;
				}
				if (currentKey == -1) {
					charCheck=32;
					toCheck = userLast.toLowerCase();
				}

				// reflectString check in method stringgnirts
				if (!foundBoolean) {
					passFound = reflectString(toCheck, 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}
				// reflectString check in method gnirtsstring
				if (!foundBoolean) {
					passFound = reflectString(toCheck, 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}
				// check for pass with no mangle
				if (!foundBoolean) {
					passFound = toCheck;
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}

				// reverse mangle check
				if (!foundBoolean) {
					passFound = reverseString(toCheck);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// duplicate mangle check
				}
				if (!foundBoolean) {
					passFound = duplicateString(toCheck);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}

				// lowercase string check
				if (!foundBoolean) {
					passFound = lowerString(toCheck);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				// uppercase string check
				if (!foundBoolean) {
					passFound = upperString(toCheck);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				// togglestring check in case TeSt
				if (!foundBoolean) {
					passFound = toggleString(toCheck, 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				// togglestring check in case tEsT
				if (!foundBoolean) {
					passFound = toggleString(toCheck, 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				// ncapitalize check
				if (!foundBoolean) {
					passFound = capitalizeString(toCheck, 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				} // first letter capital check
				if (!foundBoolean) {
					passFound = capitalizeString(toCheck, 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}if (!foundBoolean) {
					passFound = capitalizeString(toCheck, 2);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}if (!foundBoolean) {
					passFound = capitalizeString(toCheck, 3);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}if (!foundBoolean) {
					passFound = reverseString(capitalizeString(toCheck, 2));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}if (!foundBoolean) {
					passFound = reverseString(capitalizeString(toCheck, 3));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				} // deletes first character and checks
				if (!foundBoolean) {
					passFound = deleteString(toCheck, 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				} // deletes the last character and checks
				if (!foundBoolean) {
					passFound = deleteString(toCheck, 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				} // capitalizes string and reverses output ex: gnirtS
				if (!foundBoolean) {
					passFound = reverseString(capitalizeString(toCheck, 0));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				} // ncapitalizes string and reverses output ex: GNIRTs
				if (!foundBoolean) {
					passFound = deleteString(reverseString(capitalizeString(toCheck, 0)), 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// reverses lower case version of string
				}
				if (!foundBoolean) {
					passFound = reverseString(lowerString(toCheck));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// reverses uppercase version of String
				}
				if (!foundBoolean) {
					passFound = reverseString(upperString(toCheck));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// reverses a toggled string in case TeSt
				}
				if (!foundBoolean) {
					passFound = reverseString(toggleString(toCheck, 0));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// reverses a toggled string in case tEsT
				}
				if (!foundBoolean) {
					passFound = reverseString(toggleString(toCheck, 1));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
					// reflect and toggle in all configs
				}
				if (!foundBoolean) {
					passFound = reflectString(toggleString(toCheck, 1), 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				if (!foundBoolean) {
					passFound = reflectString(toggleString(toCheck, 1), 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				if (!foundBoolean) {
					passFound = reflectString(toggleString(toCheck, 0), 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}
				if (!foundBoolean) {
					passFound = reflectString(toggleString(toCheck, 0), 1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);
				}//deletes first character, reverses, then capitalizes first character ex: string=Gnirt
				if (!foundBoolean) {
					passFound = capitalizeString(reverseString(deleteString(toCheck, 0)), 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}	if (!foundBoolean) {
					passFound = capitalizeString(userLast, 0)+capitalizeString(brokenDownUser[0],0).substring(0,1);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}/*if (!foundBoolean) {
					passFound = reverseString(capitalizeString(brokenDownUser[0]+userLast.substring(0,1), 0));
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}*/	if (!foundBoolean) {
					passFound = capitalizeString(deleteString(toCheck, 1), 0);
					found = jcrypt.crypt(salt, passFound);
					foundBoolean = checkPass(found, passHash);

				}
				
				currentKey++;

			}
			if(!foundBoolean) {
				passFound=pendingFunctions(brokenDownUser[0], userLast, passHash, salt);
				if(!passFound.equals("thisStringIsLongerThanEleven"))
				foundBoolean=true;
			}

			if (foundBoolean) {
				toReturn = formatUser(passFound, brokenDownUser[0]);

			}
		}
		return toReturn;
	}
	public static String pendingFunctions(String userName, String userLast, String passHash, String salt) {
		int charCheck=32;
		boolean foundBoolean=false;
		String passFound="";
		String toCheck=userName;
		int currentKey=-2;
		String found="";
		
		for (int i = -2; i < dictionary.length; i++) {
			
			if (i < dictionary.length && i > -1) {
				toCheck = dictionary[i];

				charCheck = 32;
			}
			if (currentKey == -1) {
				charCheck=32;
				toCheck = userLast.toLowerCase();
			}
		while (charCheck < 176 && !foundBoolean) {

			charCheck++;
			/*if(charCheck==65) {
			charCheck=91;
		}if(charCheck==97) {
			charCheck=123;
		}*/
			if (!foundBoolean) {
				passFound = pendChar(toCheck, charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);


			}
			if (!foundBoolean) {
				passFound = pendChar(toCheck, charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reflectString(toCheck,0), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reflectString(toCheck,1), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reflectString(toCheck,0), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reflectString(toCheck,1), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reverseString(toCheck), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(reverseString(toCheck), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(upperString(toCheck), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(lowerString(toCheck), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(deleteString(toCheck, 1), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(deleteString(toCheck, 0), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(deleteString(toCheck, 1), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(deleteString(toCheck, 0), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(capitalizeString(toCheck, 1), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(capitalizeString(toCheck, 0), charCheck, 1);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = pendChar(capitalizeString(toCheck, 1), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}if (!foundBoolean) {
				passFound = pendChar(capitalizeString(toCheck, 0), charCheck, 0);
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			if (!foundBoolean) {
				passFound = reverseString(pendChar(capitalizeString(toCheck, 3), charCheck, 1));
				found = jcrypt.crypt(salt, passFound);
				foundBoolean = checkPass(found, passHash);

			}
			/*if (!foundBoolean) {
			passFound = pendChar(toggleString(toCheck, 0), charCheck, 0);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}
		if (!foundBoolean) {
			passFound = pendChar(toggleString(toCheck, 1), charCheck, 0);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound = pendChar(toggleString(toCheck, 0), charCheck, 1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}
		if (!foundBoolean) {
			passFound = pendChar(toggleString(toCheck, 1), charCheck, 1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar( capitalizeString(reverseString(deleteString(toCheck, 0)), 0),charCheck,0);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 0)), 0),charCheck,1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 0)), 1),charCheck,1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 1)), 0),charCheck,0);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 1)), 0),charCheck,1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 1)), 1),charCheck,0);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}if (!foundBoolean) {
			passFound =pendChar(capitalizeString(reverseString(deleteString(toCheck, 1)), 1),charCheck,1);
			found = jcrypt.crypt(salt, passFound);
			foundBoolean = checkPass(found, passHash);

		}*/
		}
		}
		if(foundBoolean) {
		return passFound;
		}else {
			return "thisStringIsLongerThanEleven";
		}
			
	}
	
	public static String formatUser(String password, String userName) {
		return ("User: " + userName + "\t    Password: " + password);
	}

	public static boolean checkPass(String found, String userHash) {
		return found.equals(userHash);
	}

	/**
	 * 
	 * @param filename the name of the file to be read
	 * @return The file's contents
	 */
	public static String[] readFile(String filename) {
		String toReturnString = "";
		String[] toReturnArray = new String[3];
		try {
			// FileReader fr=new FileReader(filename);

			File file = new File(filename);
			FileInputStream fis = new FileInputStream(file);
			byte fileContent[] = new byte[(int) file.length()];
			fis.read(fileContent);
			toReturnString = new String(fileContent);
			toReturnArray = toReturnString.split("\n");
			// BufferedReader reader = new BufferedReader(new FileReader(filename));
			// String line=reader.readLine();
			// while(line!=null) {
			// toReturn+=line;
			// line=reader.readLine();
			//
			// }

		} catch (IOException e) {
			System.out.println("File Not Found");
			String[] errorArray = new String[3];
			return errorArray;
			// TODO: handle exception
		}

		return toReturnArray;
	}
	public static boolean writeFile(String toWrite){
		File file=new File("output.txt");
		Scanner aScan=new Scanner(System.in);
		boolean written=false;
		byte[] fileBytes=toWrite.getBytes();
		if(file.exists()) {
			System.out.println("File with the name output.txt already exists, would you like to overwrite?(y/n)");
			String overWrite=aScan.nextLine();
			if(overWrite.toLowerCase().contains("n")&&!overWrite.toLowerCase().contains("y")) {
				return false;
			}else if(!overWrite.toLowerCase().contains("n")&&!overWrite.toLowerCase().contains("y")||overWrite.toLowerCase().contains("n")&&overWrite.toLowerCase().contains("y")) {
				System.out.println("input not accepted");
				return writeFile(toWrite);
			}
		}
		try {
			FileOutputStream fos=new FileOutputStream("output.txt");   
			fos.write(fileBytes);    
			fos.close();    
			written=true;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			return false;
		}



		return written;
	}
	/**
	 * 
	 * @param input A String
	 * @return
	 */
	public static String reverseString(String input) {
		char[] toReverse = input.toCharArray();
		char[] reversed = new char[toReverse.length];
		int j = toReverse.length - 1;
		for (int i = 0; i < toReverse.length; i++) {
			reversed[i] = toReverse[j];
			j--;
		}
		return String.copyValueOf(reversed);
	}

	/**
	 * 
	 * @param input
	 * @return
	 */
	public static String duplicateString(String input) {
		input += input;
		return input;
	}

	/**
	 * 
	 * @param input the input as a string
	 * @param first an int which determines whether the input is first or the
	 *              reverse is first, with 1 meaning stringgnirts, and any other
	 *              meaning gnirtsstring
	 * @return the input reflected upon the requested axis
	 */
	public static String reflectString(String input, int first) {
		if (first == 1) {
			input += reverseString(input);
		} else {
			input = reverseString(input) + input;
		}
		return input;
	}

	/**
	 * 
	 * @param input
	 * @return the input in lowercase
	 */
	public static String lowerString(String input) {
		return input.toLowerCase();
	}

	/**
	 * 
	 * @param input
	 * @return the input in uppercase
	 */
	public static String upperString(String input) {
		return input.toUpperCase();
	}

	/**
	 * 
	 * @param input
	 * @param forConvert if forConvert ==1 then the output is tEsT, and if it ==0
	 *                   then it is TeSt
	 * @return The input with the string toggled
	 */
	public static String toggleString(String input, int forConvert) {
		char[] inputArray = input.toCharArray();

		for (int i = 0; i < inputArray.length; i++) {
			if (i % 2 == forConvert) {
				inputArray[i] = Character.toUpperCase(inputArray[i]);
			} else {
				inputArray[i] = Character.toLowerCase(inputArray[i]);
			}
		}

		return String.copyValueOf(inputArray);
	}

	/**
	 * 
	 * @param input      the string to be capitalized
	 * @param forConvert if forConvert == 1 then all characters are capitalized save
	 *                   the first if it is 0 then only the first is capitalized
	 * @return The string with the characters selected capitalized
	 */
	public static String capitalizeString(String input, int forConvert) {
		char[] inputArray = input.toCharArray();

		for (int i = 0; i < inputArray.length; i++) {
			if (forConvert == 1) {
				if(i>0)
					inputArray[i] = Character.toUpperCase(inputArray[i]);
				if(i==0)
					inputArray[i]=Character.toLowerCase(inputArray[i]);
			} else if (forConvert == 0) {
				if(i==0)
					inputArray[i] = Character.toUpperCase(inputArray[i]);
				if(i>0)
					inputArray[i]=Character.toLowerCase(inputArray[i]);
			}else if(forConvert==2) {
				if(i==inputArray.length-1||i==0)
					inputArray[i] = Character.toUpperCase(inputArray[i]);
				if(i<inputArray.length-1&&i>1)
					inputArray[i]=Character.toLowerCase(inputArray[i]);
			}else if(forConvert==3) {
				if(i<inputArray.length-1&&i>1)
					inputArray[i] = Character.toUpperCase(inputArray[i]);
				if(i==inputArray.length-1||i==0)
					inputArray[i]=Character.toLowerCase(inputArray[i]);
			}
		}

		return String.copyValueOf(inputArray);
	}

	/**
	 * 
	 * @param input      the String to be used
	 * @param forConvert The command to decide if the first character is removed or
	 *                   the last if 1 then the last is removed, any other number
	 *                   removes the first
	 * @return The string with the portion deleted
	 */
	public static String deleteString(String input, int forConvert) {
		if (forConvert == 1) {
			return input.substring(0, input.length() - 1);
		} else {
			return input.substring(1, input.length());
		}

	}
	/**
	 * 
	 * @param input
	 * @return the input with all 'a' replaced with '@'
	 */
	public static String replaceA(String input) {
		String toReturn="";
		char[] inputArray=input.toCharArray();
		for (int i = 0; i < inputArray.length; i++) {
			if(Character.toLowerCase(inputArray[i])=='a') {
				inputArray[i]='@';
			}
		}
		return toReturn;

	}
	/**
	 * 
	 * @param input
	 * @return the input with all 'o' replaced with '0'
	 */
	public static String replaceO(String input) {
		String toReturn="";
		char[] inputArray=input.toCharArray();
		for (int i = 0; i < inputArray.length; i++) {
			if(Character.toLowerCase(inputArray[i])=='o') {
				inputArray[i]='0';
			}
		}
		return toReturn;

	}
	/**
	 * 
	 * @param input
	 * @return the input with all 's' replaced with '$'
	 */
	public static String replaceS(String input) {
		String toReturn="";
		char[] inputArray=input.toCharArray();
		for (int i = 0; i < inputArray.length; i++) {
			if(Character.toLowerCase(inputArray[i])=='s') {
				inputArray[i]='$';
			}
		}
		return toReturn;

	}
	/**
	 * 
	 * @param input
	 * @return the input with all 'e' replaced with '3'
	 */
	public static String replaceE(String input) {
		String toReturn="";
		char[] inputArray=input.toCharArray();
		for (int i = 0; i < inputArray.length; i++) {
			if(Character.toLowerCase(inputArray[i])=='e') {
				inputArray[i]='3';
			}
		}
		return toReturn;
	}
	/**
	 * 
	 * @param input     The String to be used as an input
	 * @param character the character to be Ap/Prependend
	 * @param preAp     The command to Pre/Ap where if 0 the char is prepended and
	 *                  if 1 the character is appended
	 * @return Returns the input with the character appended/prepended
	 */
	public static String pendChar(String input, int character, int preAp) {
		if (preAp == 0) {
			input = (char) character + input;
		} else if (preAp == 1) {
			input = input + (char) character;
		}
		return input;
	}
	public static String[] findRandom(String[] passHash) {
		boolean passwordFound=false;
		String[] toReturn=new String[passHash.length];
		String found="";
		String passToTest;
		int charToCheck1=32;
		int charToCheck2=32;
		int charToCheck3=32;
		int charToCheck4=32;
		int charToCheck5=32;
		int charToCheck6=32;
		int charToCheck7=32;
		int charToCheck8=32;
		int charToCheck9=32;
		int charToCheck10=32;
		int charToCheck11=32;
		char[] randomChar=new char[11];
//		char[] randomChar2=new char[11];
//		char[] randomChar3=new char[11];
		/*String known="hI6d$pC2";
		found=jcrypt.crypt(salt, known);
		passwordFound=checkPass(found, passHash);
		if(passwordFound) {
			toReturn=known;
		}*/
		randomChar[0]=(char)(charToCheck1);
		randomChar[1]=(char)(charToCheck1);
		randomChar[2]=(char)(charToCheck1);
		randomChar[3]=(char)(charToCheck1);
		randomChar[4]=(char)(charToCheck1);
		randomChar[5]=(char)(charToCheck1);
		randomChar[6]=(char)(charToCheck1);
		randomChar[7]=(char)(charToCheck1);
		randomChar[8]=(char)(charToCheck1);
		randomChar[9]=(char)(charToCheck1);
		while(!passwordFound&&charToCheck1<128) {
			
			if(charToCheck1==127) {
				randomChar[1]=(char)(charToCheck2++);
				charToCheck1=32;
			}if(charToCheck2==127) {
				randomChar[2]=(char)(charToCheck3++);
				charToCheck2=32;
			}if(charToCheck3==127) {
				randomChar[3]=(char)(charToCheck4++);
				charToCheck3=32;
			}if(charToCheck4==127) {
				randomChar[4]=(char)(charToCheck5++);
				charToCheck4=32;
			}if(charToCheck5==127) {
				randomChar[5]=(char)(charToCheck6++);
				charToCheck5=32;
			}if(charToCheck6==127) {
				randomChar[6]=(char)(charToCheck7++);
				charToCheck6=32;
			}if(charToCheck7==127) {
				randomChar[7]=(char)(charToCheck8++);
				charToCheck7=32;
			}if(charToCheck8==127) {
				randomChar[8]=(char)(charToCheck9++);
				charToCheck8=32;
			}if(charToCheck9==127) {
				randomChar[9]=(char)(charToCheck10++);
				charToCheck9=32;
			}
			if(charToCheck10==127) {
				randomChar[10]=(char)(charToCheck11++);
				charToCheck10=32;
			}if(charToCheck11==127) {
				charToCheck1=128;
			}
			
			for (int i = 1; i < randomChar.length; i++) {
				//System.out.println(String.copyValueOf(randomChar));
				passToTest=String.copyValueOf(randomChar).substring(0,i);
				for (int j = 0; j < passHash.length; j++) {
					if(!passHash[j].equals("HELP")) {
					found=jcrypt.crypt(passHash[j].substring(0,2), passToTest);
					passwordFound=checkPass(found, passHash[j]);
					if(passwordFound) {
						toReturn[j]=passToTest;
					}
				}
				}
				
			}
			randomChar[0]=(char)(charToCheck1++);
			

		}
		
		/*while(!passwordFound){
			for (int i = 0; i < 176; i++) {
				randomChar[10]=(char)i;
				randomChar2[10]=(char)(i+33);
				randomChar3[10]=(char)(i+65);
				if(passwordFound) {
					break;
				}
				for (int j = 32; j < 127; j++) {
					randomChar[9]=(char)j;
					randomChar2[9]=(char)(j+33);
					randomChar3[9]=(char)(j+65);
					if(passwordFound) {
						break;
					}
					for (int k= 32;  k< 127; k++) {
						randomChar[8]=(char)k;
						randomChar2[8]=(char)(k+33);
						randomChar3[8]=(char)(k+65);
						if(passwordFound) {
							break;
						}
						for (int l = 32; l < 127; l++) {
							randomChar[7]=(char)l;
							randomChar2[7]=(char)(l+33);
							randomChar3[7]=(char)(l+65);
							if(passwordFound) {
								break;
							}
							for (int m = 32; m < 127; m++) {
								randomChar[6]=(char)m;
								randomChar2[6]=(char)(m+33);
								randomChar3[6]=(char)(m+65);
								if(passwordFound) {
									break;
								}
								for (int n = 32; n < 127; n++) {
									randomChar[5]=(char)n;
									randomChar2[5]=(char)(n+33);
									randomChar3[5]=(char)(n+65);
									if(passwordFound) {
										break;
									}
									for (int o = 32; o < 127; o++) {
										randomChar[4]=(char)o;
										randomChar2[4]=(char)(o+33);
										randomChar3[4]=(char)(o+65);
										if(passwordFound) {
											break;
										}
										for (int p = 32; p < 127; p++) {
											randomChar[3]=(char)p;
											randomChar2[3]=(char)(p+33);
											randomChar3[3]=(char)(p+65);
											if(passwordFound) {
												break;
											}
											for (int q = 32; q < 127; q++) {
												randomChar[2]=(char)q;
												randomChar2[2]=(char)(q+33);
												randomChar3[2]=(char)(q+65);
												if(passwordFound) {
													break;
												}
												for (int r = 32; r < 127; r++) {
													randomChar[1]=(char)r;
													randomChar2[1]=(char)(r+33);
													randomChar3[1]=(char)(r+65);
													if(passwordFound) {
														break;
													}
													for (int s = 32; s < 127; s++) {
														randomChar[0]=(char)s;
														randomChar2[0]=(char)(s+33);
														randomChar3[0]=(char)(s+65);
														for (int t = 0; t < randomChar3.length; t++) {
															if(!passwordFound) {
																toReturn=String.copyValueOf(randomChar).substring(0,t);
																found=jcrypt.crypt(salt, toReturn);
																passwordFound=checkPass(found, passHash);
																}if(!passwordFound) {
																	toReturn=String.copyValueOf(randomChar2).substring(0,t);
																	found=jcrypt.crypt(salt, toReturn);
																	passwordFound=checkPass(found, passHash);
																	}if(!passwordFound) {
																		toReturn=String.copyValueOf(randomChar3).substring(0,t);
																		found=jcrypt.crypt(salt, toReturn);
																		passwordFound=checkPass(found, passHash);
																		}
														}

														if(passwordFound) {
															break;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

			}
		}*/
		
		return toReturn;
	}
	
	/**
	 * This creates the Dictionary used to check if the BruteDecrypt has happened
	 * correctly it first checks to see if a dictionary file exists and if none is
	 * found it uses one that is hard coded
	 * 
	 * @return this returns a HashMap<String, Integer> which contains all words for
	 *         the dictionary
	 */
	public static void createDictionary() {
		String[] dictionaryCreate = new String[0];
		File file = new File("wordlist.txt");

		if (!file.exists()) {
			System.out.println("no wordlist found");
		} else {
			dictionaryCreate = readFile("wordlist.txt");


		}

		dictionary = dictionaryCreate;
	}


}
