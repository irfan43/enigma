package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaPacket;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class UserInbox implements Serializable {

	private final List<EnigmaPacket> inbox = new ArrayList<>();



	public EnigmaPacket GetPacket(){

		EnigmaPacket enigmaPacket = null;

		synchronized (this) {
			if(!inbox.isEmpty())
				enigmaPacket = inbox.remove(0);
		}

		return enigmaPacket;
	}
	public void AddPacket(EnigmaPacket enigmaPacket){
		synchronized (this) {
			inbox.add(enigmaPacket);
		}
	}



}
