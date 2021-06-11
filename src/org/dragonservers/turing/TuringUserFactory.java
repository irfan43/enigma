package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.enigma.NetworkProtocol.EnigmaLoginRequest;
import org.dragonservers.enigma.NetworkProtocol.EnigmaRegistrationRequest;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
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
	public void VerifyPasswordHash(byte[] publicKey,String username,byte[] loginHash,String serverRandom)
			throws NoSuchAlgorithmException {
		VerifyPasswordHash(
				Base64.getEncoder().encodeToString(publicKey),
				username,
				loginHash,
				serverRandom);
	}
	public void VerifyPasswordHash(String publicKey,String username,byte[] loginHash,String serverRandom)
			throws NoSuchAlgorithmException {
		TuringUser turingUser;
		synchronized (lockObject) {
			turingUser = PublicKeyMap.get(publicKey);
		}
		if(turingUser == null)
			throw new TuringConnectionException("BAD Public Key");
		if( !(turingUser.getUsername().equals(username) && turingUser.VerifyLoginHash(loginHash,serverRandom)) )
			throw new TuringConnectionException("BAD Credentials");
	}

	public void VerifyLoginRequest(EnigmaLoginRequest loginRequest){
		TuringUser tu;
		synchronized (lockObject){
			tu = PublicKeyMap.get(loginRequest.publicKeyB64);
		}
		if(tu == null)
			throw new TuringConnectionException("BAD Credentials");

		if(!tu.getUsername().equals(loginRequest.uname))
			throw new TuringConnectionException("BAD Credentials");

		try {
			tu.VerifyLoginHash(loginRequest.lHash,loginRequest.serRandom);
		} catch (NoSuchAlgorithmException e) {
			throw new TuringConnectionException("BAD SERVER");
		}
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
			throw new TuringConnectionException("BAD invalid_username");
		if(UsernameExist(registrationRequest.uname))
			throw new TuringConnectionException("BAD username_exist");
		if(PublicKeyExist(registrationRequest.publicKeyEncoded))
			throw new TuringConnectionException("BAD public_key_exist");


		//validated that the parameters are valid
		TuringUser toAdd = null;
		try {
			toAdd = new TuringUser(registrationRequest);
		} catch (NoSuchAlgorithmException e) {
			throw new TuringConnectionException("BAD SERVER");
		}
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
	public void hookPacketListener(String publicKey, Socket socket, InputStream inputStream, OutputStream outputStream) throws IOException {
		TuringUser turingUser;
		synchronized (lockObject){
			turingUser = PublicKeyMap.get(publicKey);
		}
		if(turingUser == null)
			throw new TuringConnectionException("BAD ILLEGAL STATE");
		turingUser.hookPacketListener(socket, inputStream, outputStream);
	}
	public boolean SendPacket(EnigmaPacket enigmaPacket,byte[] FromAddrs) throws IOException{
		if(!Arrays.equals(
				enigmaPacket
						.getFromAddr()
						.getEncoded(),
				FromAddrs
			)
		)
			throw new TuringConnectionException("BAD From Address Forgery");
		return SendPacket(enigmaPacket);
	}
	public boolean SendPacket(EnigmaPacket enigmaPacket) throws IOException {
		TuringUser turingUser;
		String toAddress = Base64.getEncoder().encodeToString( enigmaPacket.getToAddr().getEncoded() );
		synchronized (lockObject){
			turingUser = PublicKeyMap.get(toAddress);
		}

		if(turingUser == null)
			throw new IllegalArgumentException("BAD TOO ADDRESS");
		return turingUser.SendPacket(enigmaPacket);
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
