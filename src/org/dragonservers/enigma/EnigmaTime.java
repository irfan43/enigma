package org.dragonservers.enigma;

import java.text.SimpleDateFormat;
import java.util.Date;

public class EnigmaTime {

	public static String GetFormattedTime(){
		return GetFormattedTime("yyyy-MM-dd HH:mm:ss");
	}
	public static String GetFormattedTime(String Format)throws IllegalArgumentException{
		SimpleDateFormat sdfDate = new SimpleDateFormat(Format);//dd/MM/yyyy
		Date now = new Date();
		return sdfDate.format(now);
	}
}
