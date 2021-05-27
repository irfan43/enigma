package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaTime;

import java.io.Serializable;
import java.security.SecureRandom;

public class RegistrationCode implements Serializable {

	private final long Expiry;
	private final String Code;
	private final String CodeClean;
	private boolean Used;

	public RegistrationCode(long expiry) {
		Expiry = expiry;
		Code = RandomCode();
		CodeClean = GetCleanString(Code);
		Used = false;
	}

	//General purpose
	public void MarkUnused() {
		Used = false;
	}
	public boolean redeem(){
		if(isValid()){
			Used = true;
			return true;
		}
		return false;
	}
	public boolean isValid(){
		//we don't do !(A && B)
		//since if it's used it should not need
		//to calculate the the time dif
		return !Used  && !isExpired();
	}
	public boolean isExpired(){
		return  Expiry < EnigmaTime.GetUnixTime();
	}
	//getters
	public String getCode(){
		return Code;
	}
	public String GetCleanCode(){
		return CodeClean;
	}
	private String RandomCode(){
		char[] charSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
		SecureRandom rand = new SecureRandom();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 35; i++) {
			char c = charSet[rand.nextInt(charSet.length)];
			sb.append(c);
			if (i % 5 == 4 && i != 34) sb.append('-');
		}
		return sb.toString();
	}
	//static Functions
	public static String GetCleanString(String code){
		char[] codeChars = code.toUpperCase().toCharArray();

		StringBuilder sb = new StringBuilder();
		for (char a:codeChars ) {
			if( (a <= '9' && a >= '0') || (a >= 'A' && a <= 'Z') ){
				sb.append(a);
			}
		}
		String rtr = sb.toString();
		if (rtr.length() != 35)
			rtr = null;
		return rtr;
	}

}
