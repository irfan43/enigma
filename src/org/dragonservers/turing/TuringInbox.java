package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaPacket;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;

public class TuringInbox {

	/*
	*
	* This is used to make manage a user inbox
	*
	* */
	private HashMap<String,UserInbox> InboxMap;
	private final Object lockObject = new Object();
	public boolean IO_Flag = false;

	public TuringInbox() throws IOException, ClassNotFoundException {
		if(Files.exists(Path.of(Turing.UserDataFolder + "/" + "UserInboxes.dat"))){
			LoadData();
		}else {
			InboxMap = new HashMap<>();
			SaveData();
		}
	}

	public boolean queuePacket(EnigmaPacket packet) {
		//first we make sure the specified Location Exists
		byte[] key = packet.getToAddr().getEncoded();
		UserInbox toInbox;
		synchronized (lockObject) {
			toInbox = InboxMap.get(
					Base64.getEncoder()
							.encodeToString(key));
		}
		if(toInbox != null)
			toInbox.AddPacket(packet);
		synchronized (lockObject){
			IO_Flag = true;
		}
		return (toInbox != null);
	}

	public void MakeInbox(byte[] publicKeyEncoded) {
		UserInbox userInbox = new UserInbox();
		synchronized (lockObject) {
			IO_Flag = true;
			InboxMap.put(Base64.getEncoder()
					.encodeToString(publicKeyEncoded),
					userInbox);
		}
	}
	//create a function to grab the list of packets,
	// you can add packets and get packets
	// this should be synchronized
	public EnigmaPacket CheckInbox(byte[] publicKeyEncoded){
		EnigmaPacket poppedPacket = null;
		UserInbox userInbox;
		synchronized (lockObject){
			userInbox = InboxMap.get(Base64.getEncoder().encodeToString( publicKeyEncoded ) );
		}

		if(userInbox == null)
			throw new IllegalArgumentException();
		else
			poppedPacket = userInbox.GetPacket();

		synchronized (lockObject){
			IO_Flag = true;
		}
		return poppedPacket;
	}
	//TODO we are deserializing and serializing untrusted data, ie byte[] is sent by the user,
	// 		we should make sure that is not a vulnerability

	public void SaveData() throws IOException {
		FileOutputStream fos = new FileOutputStream(Turing.UserDataFolder + "/" + "UserInboxes.dat");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		HashMap<String, UserInbox> tmp;
		System.out.println("Saving Inbox");
		synchronized (lockObject) {
			//Map<String,String> testing = new HashMap<>();
			//testing.put("key","values");
			oos.writeObject(InboxMap);
			IO_Flag = false;
		}


		oos.close();
		fos.close();

	}
	private void LoadData() throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(Turing.UserDataFolder + "/" + "UserInboxes.dat");
		ObjectInputStream ois = new ObjectInputStream(fis);
		InboxMap = (HashMap<String, UserInbox>) ois.readObject();
		ois.close();
		fis.close();
	}

}
