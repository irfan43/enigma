package org.dragonservers.enigmaclient;

public class EnigmaConsoleUtil {


	public static char GetChar(int keyCode){
		if(keyCode >= 32 && keyCode < 127)
			return (char)keyCode;
		return (char)0;
	}
}
