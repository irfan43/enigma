package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaSession;

import java.util.Arrays;
import java.util.HashMap;

public class SessionHandler {
	private HashMap <String, EnigmaSession> sessionMap;
	private final Object lockObject = new Object(),lock_NP = new Object();

	public SessionHandler(){
		sessionMap = new HashMap<>();
	}

	public String GenerateSessionID(byte[] publicKeyEncoded){
		EnigmaSession newID = new EnigmaSession(publicKeyEncoded);
		String sessionID = newID.SessionID;
		synchronized (lockObject) {
			sessionMap.put(sessionID, newID);
		}
		return sessionID;
	}



	public boolean VerifySessionID(String sesID,byte[] publicKey){
		EnigmaSession enigmaSession;
		synchronized (lockObject) {
			enigmaSession = sessionMap.get(sesID);
		}
		boolean rtr = false;
		if(enigmaSession != null){
			rtr = enigmaSession.IsValid() && Arrays.equals(enigmaSession.publicKey, publicKey);
		}

		//it's easier to check if it's expired compared to a bit to bit binary check
		return rtr ;
	}
	public void PurgeSessions(){
		String[] key_sets;
		synchronized (lockObject){
			key_sets = new String[sessionMap.keySet().size()];
			sessionMap.keySet().toArray(key_sets);
		}
		for (String keyToCheck:key_sets) {
			synchronized (lockObject) {
				EnigmaSession es = sessionMap.get(keyToCheck);
				if(es != null){
					if(!es.IsValid())
						sessionMap.remove(keyToCheck);
				}
			}
		}
	}

}
