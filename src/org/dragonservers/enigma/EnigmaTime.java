package org.dragonservers.enigma;

import java.text.SimpleDateFormat;
import java.util.Date;

public class EnigmaTime {

	public static String GetFormattedTime(long time, String Format){
		Date now = new Date();
		now.setTime(time);
		SimpleDateFormat sdfDate = new SimpleDateFormat(Format);
		return sdfDate.format(now);
	}
	public static String GetFormattedTime(){
		return GetFormattedTime("yyyy-MM-dd HH:mm:ss");
	}
	public static String GetFormattedTime(String Format)throws IllegalArgumentException{
		SimpleDateFormat sdfDate = new SimpleDateFormat(Format);//dd/MM/yyyy
		Date now = new Date();
		return sdfDate.format(now);
	}
	public static long GetMilisSinceMidnight(){
		Date now = new Date();
		return 1000*((now.getHours()* 3600L) + (now.getMinutes()* 60L) + now.getSeconds());
	}
	public static long GetUnixTime(){
		return System.currentTimeMillis() / 1000L;
	}
}
