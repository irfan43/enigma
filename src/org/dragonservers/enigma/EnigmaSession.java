package org.dragonservers.enigma;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;

public class EnigmaSession implements Serializable {

	public byte[] publicKey;
	public final long Expiry;
	public final String SessionID;

	public EnigmaSession(String sessionID,long expiry){
		SessionID = sessionID;
		Expiry = expiry;
	}
	public EnigmaSession(byte[] OwnersPublicKey){
		publicKey = OwnersPublicKey;
		Expiry = EnigmaTime.GetUnixTime() + 3600;//gives each session a hour
		SessionID = GenerateRandomSessionID();
	}

	private String GenerateRandomSessionID() {
		SecureRandom sr = new SecureRandom();
		byte[] i = new byte[64];
		sr.nextBytes(i);
		return Base64.getEncoder().encodeToString(i);
	}

	public boolean IsValid(){
		//time remaining is greater then 0
		return (Expiry > EnigmaTime.GetUnixTime());
	}
}
