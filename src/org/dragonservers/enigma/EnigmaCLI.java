package org.dragonservers.enigma;

import java.io.Console;

public class EnigmaCLI {

	public static char[] getPassword(Console con){
		char[] Pass;
		if(con != null) {
			Pass = con.readPassword();
		}else{
			String s = Enigma.scn.nextLine();
			Pass = s.toCharArray();
		}
		return Pass;
	}
}
