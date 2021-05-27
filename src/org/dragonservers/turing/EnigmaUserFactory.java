package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaUser;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Set;

public class EnigmaUserFactory {

	private HashMap<String, EnigmaUser> PublicKeyMap;
	private HashMap<String,String> UsernameMap;
	private final Object lockObject = new Object();

	public boolean IO_Flag = false;

	public EnigmaUserFactory() throws IOException, ClassNotFoundException {
		if(!Files.exists(Path.of(Turing.UserDataFolder,Turing.PublicKeyMap))
				|| !Files.exists(Path.of(Turing.UserDataFolder,Turing.UsernameMap))){

			if(!Files.exists(Path.of(Turing.UserDataFolder)))
				Files.createDirectory(Path.of(Turing.UserDataFolder));
			PublicKeyMap = new HashMap<>();
			UsernameMap = new HashMap<>();
			SaveData();
		}else {
			LoadData();
		}
	}
	//TODO overload with base 64 string for public key input to speed things up
	public boolean VerifyPasswordHash(byte[] publicKey,byte[] passwordHash,String hashHeaderUTC) throws NoSuchAlgorithmException {
		boolean rtr = false;
		synchronized (lockObject){
			EnigmaUser enigmaUser = PublicKeyMap.get(Base64.getEncoder().encodeToString(publicKey));
			if(enigmaUser != null)
				rtr = enigmaUser.VerifyPassword(passwordHash,hashHeaderUTC);
		}
		return rtr;
	}
	public int RegisterUser(String username,byte[] EncodedPublicKey,byte[] passwordHash) throws IOException {
		/*
		*  0 good registered
		*  -1 invalid username
		*  -2 already existing username
		*  -3 public key exist
		*  -4 invalid key spec
		*  -5 Server Error
		* */
		if(!EnigmaUser.IsValidUsername(username))return -1;
		if(UsernameExist(username))return -2;
		if(PublicKeyExist(EncodedPublicKey))return -3;

		PublicKey pbk;
		try {
			pbk = EnigmaKeyHandler.PublicKeyFromEnc(EncodedPublicKey);
		} catch (NoSuchAlgorithmException e) {
			return -5;
		} catch (InvalidKeySpecException e) {
			return -4;
		}
		//validated that the parameters are valid
		EnigmaUser toAdd = new EnigmaUser(username, pbk, passwordHash);
		Turing.EnigmaInboxs.MakeInbox(EncodedPublicKey);
		AddUser(toAdd);
		return 0;
	}

	//TODO overload with base 64 input
	public boolean PublicKeyExist(byte[] pbk) {
		return PublicKeyExist(Base64.getEncoder().encodeToString(pbk));
	}
	public boolean PublicKeyExist(String pbk) {
		boolean keyExist;
		synchronized (lockObject){
			keyExist = (PublicKeyMap.get(pbk) != null);
		}
		return keyExist;
	}
	public String[] GetUserBase(){
		Set<String> usernames;
		synchronized (lockObject){
			usernames = UsernameMap.keySet();
		}
		String[] rtr = new String[usernames.size()];
		usernames.toArray(rtr);
		return rtr;
	}
	public boolean UsernameExist(String username){
		boolean userExist;
		synchronized (lockObject){
			userExist = (UsernameMap.get(username) != null);
		}
		return userExist;
	}

	public String GetUsername(String publicKey){
		String foundUsername = null;
		synchronized (lockObject){
			EnigmaUser eu = PublicKeyMap.get(publicKey);
			if(eu != null)
				foundUsername = eu.getUsername();
		}
		if(foundUsername == null)
			throw new IllegalArgumentException("Public Key Does Not Exist");
		return foundUsername;
	}
	public String GetPublicKeyB64(String username){
		String pbk;
		synchronized (lockObject){
			pbk = UsernameMap.get(username);
		}
		return pbk;
	}


	private void AddUser(EnigmaUser eu){
		String euUsername = eu.getUsername();
		String publicKey = Base64.getEncoder().encodeToString( eu.PubKey.getEncoded() );
		synchronized (lockObject) {
			PublicKeyMap.put(publicKey, eu);
			UsernameMap.put(euUsername, publicKey);
			IO_Flag = true;
		}
	}

	private void LoadData() throws IOException, ClassNotFoundException {
		synchronized (lockObject) {
			PublicKeyMap = (HashMap<String, EnigmaUser>) LoadUserMap(Turing.UserDataFolder + "/" + Turing.PublicKeyMap);
			UsernameMap = (HashMap<String, String>) LoadUserMap(Turing.UserDataFolder + "/" + Turing.UsernameMap);
		}
	}
	public void SaveData() throws IOException {

		HashMap<String, EnigmaUser> pbkMapCopy;
		HashMap<String, String> usrMapCopy;
		synchronized (lockObject) {
			pbkMapCopy = (HashMap<String, EnigmaUser>) PublicKeyMap.clone();
			usrMapCopy = (HashMap<String, String>) UsernameMap.clone();
			IO_Flag = false;
		}
		SaveHashMap(Turing.UserDataFolder + "/" + Turing.PublicKeyMap , pbkMapCopy);
		SaveHashMap(Turing.UserDataFolder + "/" + Turing.UsernameMap, usrMapCopy);
	}

	//Save File Functions
	private void SaveHashMap(String FileLoc, Object ToSave) throws IOException {
		FileOutputStream fos = new FileOutputStream(FileLoc);
		ObjectOutputStream oob = new ObjectOutputStream(fos);
		oob.writeObject(ToSave);
		oob.close();
		fos.close();
	}

	//Load File Functions
	private Object LoadUserMap(String FileLoc) throws IOException,  ClassNotFoundException {
		Object tmp;
		FileInputStream fis = new FileInputStream(FileLoc);
		ObjectInputStream ois = new ObjectInputStream(fis);
		tmp = ois.readObject();
		ois.close();
		fis.close();
		return tmp;
	}

}
