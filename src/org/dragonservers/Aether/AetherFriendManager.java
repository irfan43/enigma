package org.dragonservers.Aether;

import org.dragonservers.enigma.EnigmaCrypto;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaNetworkHeader;
import org.dragonservers.enigma.EnigmaPacket;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;

public class AetherFriendManager {

	public static int Message_Latest_cache = 100;
	private static HashMap<String, AetherFriend> friendMap;
	private static HashMap<String,String> friendUsernameMap;
	private static List<String> New_friends;
	private static final Object lockObject = new Object();
	private static final Path save_file = Path.of("Friend_list.dat");
	private static boolean IO_FLAG = false;


	public static List<String> GetLatestFriendsList(){
		//todo synchronize this
		Set<String> keySet = friendMap.keySet();
		List<String> enigmaFriendList = new ArrayList<>();
		for (String i :keySet) {
			AetherFriend ef = friendMap.get(i);
			if(ef != null && ef.IsIntroduced()) {
				enigmaFriendList.add(ef.friendsUsername);
				if (enigmaFriendList.size() >= 20)
					break;
			}
		}
		return enigmaFriendList;
	}
	public static String GetIntroductionToken(String friendsUsername) throws GeneralSecurityException, IOException {
		PublicKey friendsPublicKey = Aether.TuringConnection.GetUserPublicKey(friendsUsername);
		return GetIntroductionToken(friendsUsername,friendsPublicKey);
	}
	public static String GetIntroductionToken(String friendsUsername,PublicKey friendsPublicKey) throws GeneralSecurityException, IOException {
		if(friendsPublicKey == null)
			throw new IllegalArgumentException("BAD USERNAME DNE");
		AetherFriend ef  = GetFriendFromPublicKey(friendsPublicKey);
		String token;
		if(ef == null){
			ef = new AetherFriend(friendsPublicKey,friendsUsername);
			AddFriend(ef);
		}
		token = ef.GetIntroductionToken();
		Save();
		return token;
	}
	public static void HandleNewIntroductionToken(String token) throws GeneralSecurityException, IOException {
		//either we sent the first token and this is there response
		//or
		//they sent the first introduction Token
		EnigmaNetworkHeader tkn = new EnigmaNetworkHeader(token);
		String Public_Key = tkn.GetValue("My_RSA_PublicKey");
		PublicKey friendsPublicKey;
		try{
			 friendsPublicKey = EnigmaKeyHandler.PublicKeyFromEnc(
			 		Base64.getDecoder().decode(Public_Key));
		}catch (Exception e){
			throw new IllegalArgumentException("Bad Introduction Token");
		}
		String username = GetUsernameFromPublicKey(Public_Key);
		if(username == null){
			//new request
			username = Aether.TuringConnection.GetUsername(friendsPublicKey);
			if(username == null)
				throw new IllegalArgumentException("Illegal Username");
			AetherFriend ef;
			//TODO handle a bad token
			ef = new AetherFriend(friendsPublicKey, username);
			ef.LoadIntroductionToken(tkn);
			AddFriend(ef);
		}else {
			System.out.println("Got here ");
			AetherFriend ef = GetFriendFromUsername(username);
			ef.LoadIntroductionToken(tkn);
		}
		Save();
	}
	private static void AddFriend(AetherFriend friend){
		friendMap.put(friend.friendsUsername,friend);
		friendUsernameMap.put(
				Base64.getEncoder().encodeToString(friend.friendsPublicKey.getEncoded()),
				friend.friendsUsername);
		New_friends.add(friend.friendsUsername);
	}
	//IO Functions
	public static void Save() throws GeneralSecurityException, IOException {
		final Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, Aether.AESEncryptionKey);

		OutputStream os = Files.newOutputStream(save_file);
		CipherOutputStream cos = new CipherOutputStream(os,c);
		ObjectOutputStream oos = new ObjectOutputStream(cos);

		synchronized (lockObject) {
			oos.writeObject(friendMap);
			oos.writeObject(friendUsernameMap);
			oos.writeObject(New_friends);
			IO_FLAG = false;
		}

		//TODO move all closes to a finally block
		oos.close();
		cos.close();
		os.close();
	}
	public static boolean IsFileMissing(){
		return !Files.exists(save_file);
	}
	public static void Load() throws GeneralSecurityException, IOException, ClassNotFoundException {
		if(IsFileMissing())
			throw new IOException("FILE Friend List NOT FOUND ");

		final Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, Aether.AESEncryptionKey);

		InputStream is = Files.newInputStream(save_file);
		CipherInputStream cis = new CipherInputStream(is, c);
		ObjectInputStream ois = new ObjectInputStream(cis);
		synchronized (lockObject) {
			friendMap = (HashMap<String, AetherFriend>) ois.readObject();
			friendUsernameMap = (HashMap<String, String>) ois.readObject();
			New_friends = (List<String>) ois.readObject();

		}
		ois.close();
		cis.close();
		is.close();
	}
	public static void InitialiseNewFile() throws GeneralSecurityException, IOException {
		friendMap = new HashMap<>();
		friendUsernameMap = new HashMap<>();
		New_friends = new ArrayList<>();
		Save();
	}

	public static EnigmaPacket sendMessage(String data, String username)
			throws GeneralSecurityException, IOException, ClassNotFoundException {
		return GetFriendFromUsername(username).sendMessage(data);
	}
	public static String[] GetRequestsList(){
		String[] rtr;
		//WARNING UNTESTED CODE SNIP
		synchronized (lockObject) {
			rtr = new String[New_friends.size()];
			New_friends.toArray(rtr);
		}
		List<String> temp = new ArrayList<>();

		for (String name :New_friends) {
			synchronized (lockObject){
				AetherFriend ef = GetFriendFromUsername(name);
				if(ef != null && !ef.IsIntroduced())
					temp.add(name);
			}
		}
		rtr = new String[temp.size()];
		temp.toArray(rtr);
		if(rtr.length > 20){
			rtr = Arrays.copyOf(rtr,20);
		}
		return rtr;
	}
	public static String RenderName(String username) throws NoSuchAlgorithmException {
		return RenderName(GetFriendFromUsername(username));
	}
	public static String RenderName(AetherFriend aetherFriend) throws NoSuchAlgorithmException {
		return aetherFriend.friendsUsername +
				":" +
				Base64
					.getEncoder()
					.encodeToString(EnigmaCrypto.SHA256(aetherFriend
							.friendsPublicKey.getEncoded()));
	}
	/**
	 * this places a message in the correct message queue
	 * @param data the message
	 * @param toAddr the address to place the message in
	 * @throws IllegalArgumentException if the given to address is not present in the Friend Manager
	 */
	public static void receivedMessage(byte[] data, byte[] toAddr)
			throws IllegalArgumentException, GeneralSecurityException, IOException, ClassNotFoundException {
		String username = GetUsernameFromPublicKey(toAddr);
		if(username == null)
			throw new IllegalArgumentException("Public Key Does Not Exist in EnigmaFriendManager");
		AetherFriend ef;
		synchronized (lockObject){
			ef = friendMap.get(username);
		}
		ef.pushMessage(data);

	}
	public static AetherFriend GetFriendFromPublicKey(String publicKey){
		String username = GetUsernameFromPublicKey(publicKey);
		return GetFriendFromUsername(username);
	}
	private static AetherFriend GetFriendFromPublicKey(PublicKey friendsPublicKey) {
		return GetFriendFromPublicKey(
				Base64.getEncoder().encodeToString(friendsPublicKey.getEncoded())
		);
	}
	public static AetherFriend GetFriendFromUsername(String username){
		AetherFriend ef;
		synchronized (lockObject){
			ef = friendMap.get(username);
		}
		return ef;
	}
	public static PublicKey GetPublicKeyFromUsername(String username){
		return GetFriendFromUsername(username).friendsPublicKey;
	}
	public static String GetUsernameFromPublicKey(byte[] publicKey) {
		return GetUsernameFromPublicKey(Base64.getEncoder().encodeToString(publicKey));
	}
	public static String GetUsernameFromPublicKey(String publicKey) {
		String foundName;
		synchronized (lockObject){
			foundName = friendUsernameMap.get(publicKey);
		}
		return foundName;
	}

	public static void OpenMessageWindow(String frusername) throws GeneralSecurityException, IOException, ClassNotFoundException {
		AetherFriend ef = GetFriendFromUsername(frusername);
		ef.OpenMessageWindow();
	}
}
