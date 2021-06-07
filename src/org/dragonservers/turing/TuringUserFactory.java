package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.enigma.NetworkProtocol.EnigmaRegistrationRequest;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Set;

public class TuringUserFactory {

	private HashMap<String, TuringUser> PublicKeyMap;
	private HashMap<String,String> UsernameMap;
	private final Object lockObject = new Object();

	public boolean IO_Flag = false;


	public TuringUserFactory() throws IOException, ClassNotFoundException {
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
	public void RegisterUser(EnigmaRegistrationRequest registrationRequest){
		/*
		*  0 good registered
		*  -1 invalid username
		*  -2 already existing username
		*  -3 public key exist
		*  -4 invalid key spec
		*  -5 Server Error
		* */
		if(!EnigmaUser.IsValidUsername(registrationRequest.uname))
			throw new TuringConnectionException("bad invalid_username");
		if(UsernameExist(registrationRequest.uname))
			throw new TuringConnectionException("bad username_exist");
		if(PublicKeyExist(registrationRequest.publicKeyEncoded))
			throw new TuringConnectionException("bad public_key_exist");


		//validated that the parameters are valid
		TuringUser toAdd = new TuringUser(registrationRequest);
		Turing.EnigmaInboxs.MakeInbox(registrationRequest.publicKeyEncoded);
		AddUser(toAdd);

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


	private void AddUser(TuringUser turingUser){
		String euUsername = turingUser.getUsername();
		String publicKey = Base64.getEncoder().encodeToString( turingUser.PubKey.getEncoded() );
		synchronized (lockObject) {
			PublicKeyMap.put(publicKey, turingUser);
			UsernameMap.put(euUsername, publicKey);
			IO_Flag = true;
		}
	}

	private void LoadData() throws IOException, ClassNotFoundException {
		synchronized (lockObject) {
			PublicKeyMap = (HashMap<String, TuringUser>) LoadUserMap(Turing.UserDataFolder + "/" + Turing.PublicKeyMap);
			UsernameMap = (HashMap<String, String>) LoadUserMap(Turing.UserDataFolder + "/" + Turing.UsernameMap);
		}
	}
	public void SaveData() throws IOException {

		HashMap<String, TuringUser> pbkMapCopy;
		HashMap<String, String> usrMapCopy;
		synchronized (lockObject) {
			pbkMapCopy = (HashMap<String, TuringUser>) PublicKeyMap.clone();
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
