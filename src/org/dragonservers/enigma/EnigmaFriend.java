package org.dragonservers.enigma;

import javax.crypto.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class EnigmaFriend implements Serializable {
	//these are transient for security Reasons
	public PublicKey friendsPublicKey;
	private PublicKey FriendsDHPbk;
	private KeyPair DHKeyPair;
	private byte[] sharedSecret;
	public transient EnigmaMessages enigmaMessages;
	public String friendsUsername;
	private boolean GotToken,SentToken;
	public String friendFile;

	public EnigmaFriend(PublicKey publicKey,String username) throws GeneralSecurityException, IOException {

		friendsPublicKey = publicKey;
		friendsUsername = username;
		enigmaMessages = new EnigmaMessages(friendsUsername,friendsPublicKey);
		GotToken = false;
		SentToken = false;
		initializeFile();
		System.out.println("New Friend Object " + username + " " + friendFile);
	}
	//this is having all the data need to start a key X
	public String GetIntroductionToken() throws GeneralSecurityException {
		if(DHKeyPair == null)
			GenerateKeyPair();
		System.out.println("Introducing " + friendsUsername + " " + friendFile);

		EnigmaNetworkHeader enh = new EnigmaNetworkHeader();
		enh.SetValue("My_RSA_PublicKey",
				Base64.getEncoder().encodeToString(Enigma.OurKeyHandler.GetPublicKey().getEncoded()));
		enh.SetValue("UR_RSA_PublicKey",
				Base64.getEncoder().encodeToString(friendsPublicKey.getEncoded()));
		enh.SetValue("DH_PublicKey",
				Base64.getEncoder().encodeToString(DHKeyPair.getPublic().getEncoded()));
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(Enigma.OurKeyHandler.GetPrivateKey());
		sgn.update(Enigma.OurKeyHandler.GetPublicKey().getEncoded());
		sgn.update(friendsPublicKey.getEncoded());
		sgn.update(DHKeyPair.getPublic().getEncoded());
		enh.SetValue("Sign",
				Base64.getEncoder().encodeToString(sgn.sign()));
		SentToken = true;
		//TryToMakeSecret(); //confirm if this is necessary
		return enh.GetHeader(true);
	}
	public void LoadIntroductionToken(EnigmaNetworkHeader token) throws GeneralSecurityException{
		System.out.println("Got Intro to " + friendsUsername + " " + friendFile);

		byte[] TherePublicKey = Base64
				.getDecoder().decode(
						token.GetValue("My_RSA_PublicKey"));
		byte[] OurReportedPublic = Base64
				.getDecoder().decode(
						token.GetValue("UR_RSA_PublicKey"));
		byte[] ThereDHPublicKey = Base64
				.getDecoder().decode(
						token.GetValue("DH_PublicKey"));
		byte[] signature = Base64
				.getDecoder().decode(
						token.GetValue("Sign"));
		if(!Arrays.equals(OurReportedPublic,
				Enigma.OurKeyHandler.GetPublicKey().getEncoded()))
			throw new IllegalArgumentException("Report BAD RSA our Public Key in introduction token ");
		if(!Arrays.equals(TherePublicKey,
				friendsPublicKey.getEncoded()))
			throw new IllegalArgumentException("Report BAD RSA friends Public Key in introduction token ");

		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(friendsPublicKey);
		sgn.update(friendsPublicKey.getEncoded());
		sgn.update(Enigma.OurKeyHandler.GetPublicKey().getEncoded());
		sgn.update(ThereDHPublicKey);
		if(!sgn.verify(signature))
			throw new IllegalArgumentException("Bad Signature on introduction token");

		KeyFactory kf = KeyFactory.getInstance("EC");
		FriendsDHPbk = kf.generatePublic(new X509EncodedKeySpec(ThereDHPublicKey));
		TryToMakeSecret();
		GotToken = true;
	}
	public boolean IsIntroduced(){
		return (GotToken && SentToken);
	}
	private void TryToMakeSecret() throws GeneralSecurityException {
		if(FriendsDHPbk != null && sharedSecret == null){
			System.out.println("MadeSecret");
			if(DHKeyPair == null)
				GenerateKeyPair();

			KeyAgreement ka =  KeyAgreement.getInstance("ECDH");
			ka.init(DHKeyPair.getPrivate());
			ka.doPhase(FriendsDHPbk,true);
			sharedSecret = ka.generateSecret();
		}
	}
	private void GenerateKeyPair() throws GeneralSecurityException {
		KeyPairGenerator kpg =KeyPairGenerator.getInstance("EC");

		//we are using this curve , however later we should move to a better curve
		//testing shows it works in java 15 so don't touch it
		//IF YOU CHANGE THIS CHECK WITH ALL VERSION OF JAVA BEFORE PUSHING
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		DHKeyPair = kpg.generateKeyPair();
	}

	public void pushMessage(byte[] data)
			throws GeneralSecurityException, IOException, ClassNotFoundException, IllegalArgumentException {
		loadIfNotLoaded();
		enigmaMessages.PutMessage(EnigmaCrypto.AESDecrypt(data,sharedSecret) );
		saveMessagesToFile();
	}
	public EnigmaPacket sendMessage(String data) throws GeneralSecurityException, IOException, ClassNotFoundException {
		loadIfNotLoaded();
		EnigmaPacket ep = new EnigmaPacket(Enigma.OurKeyHandler.GetPublicKey(),friendsPublicKey);
		byte[] Cmdheader = "Text".getBytes(StandardCharsets.UTF_8);
		ByteBuffer bb = ByteBuffer.allocate(4).putInt(Cmdheader.length);
		ep.update(bb.array());
		ep.update(Cmdheader);
		byte[] TMEncoded = EnigmaCrypto.AESEncrypt(
				enigmaMessages.SendMessage(data,Enigma.OurKeyHandler.GetPrivateKey()),sharedSecret );
		ByteBuffer bbtm = ByteBuffer.allocate(4).putInt(TMEncoded.length);
		ep.update(bbtm.array());
		ep.update(TMEncoded);
		return ep;
	}
	public void loadMessagesFromFile() throws GeneralSecurityException, IOException, ClassNotFoundException {
		//TODO handle deleted messages
		if(friendsUsername == null) {
			initializeFile();
		}else{
			InputStream is = Files.newInputStream(Path.of("friends",friendFile));
			final Cipher c = Cipher.getInstance("AES");

			c.init(Cipher.DECRYPT_MODE,Enigma.AESEncryptionKey);
			CipherInputStream cipherInputStream = new CipherInputStream(is,c);

			ObjectInputStream objectInputStream = new ObjectInputStream(cipherInputStream);
			enigmaMessages = (EnigmaMessages) objectInputStream.readObject();

			objectInputStream.close();
			cipherInputStream.close();
			is.close();
		}
	}
	public void saveMessagesToFile() throws GeneralSecurityException, IOException {
		Files.createDirectories(Path.of("friends"));
		OutputStream os = Files.newOutputStream(Path.of("friends",friendFile));
		final Cipher c = Cipher.getInstance("AES");

		c.init(Cipher.ENCRYPT_MODE,Enigma.AESEncryptionKey);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(os,c);

		ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
		objectOutputStream.writeObject(enigmaMessages);
		objectOutputStream.close();
		cipherOutputStream.close();
		os.close();
	}
	private void loadIfNotLoaded() throws GeneralSecurityException, IOException, ClassNotFoundException {
		if(enigmaMessages == null)
			loadMessagesFromFile();
	}
	private void initializeFile() throws GeneralSecurityException, IOException {
		int nchars = 5;
		do {
		//todo try n times before moving to more letters
			friendFile = getRandomString(nchars) + ".msgcrypt";
			nchars++;
		}while (Files.exists(Path.of("friends",friendFile)));
		enigmaMessages = new EnigmaMessages(friendsUsername,friendsPublicKey);
		saveMessagesToFile();
	}
	private String getRandomString(int nChars){
		Random rnd = new Random();
		String availChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < nChars; i++)
			sb.append(availChars.charAt(rnd.nextInt(availChars.length())));
		return sb.toString();
	}

	public void OpenMessageWindow() throws GeneralSecurityException, IOException, ClassNotFoundException {
		loadIfNotLoaded();
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader inputBuffer = new BufferedReader(isr);
		String text;
		String footer = "";
		while (true) {
			EnigmaCLI.CLS();
			PrintNLines(100);
			System.out.println("\t== Chat with " + friendsUsername + " ==");
			System.out.print( enigmaMessages.GetRendered(35) );
			System.out.print(footer);

			System.out.println(":-");
			try {
				EnigmaPacket ep = null;
				text = inputBuffer.readLine();
				if(text.startsWith("!!")){
					text = text.substring(1);
					ep = sendMessage(text);
				}else if(text.startsWith("!")){
					footer = HandleMessageCommand(text);
				}else if(!text.equals("")){
					footer = "";
					ep = sendMessage(text);
				}else {
					footer = "";
				}
				if(ep != null)
					EnigmaPacketFactory.QueueOutgoingPacket(ep);
			} catch (IOException  e) {
				footer = ("ERROR: input buffer IO Exception\n");
			}catch (GeneralSecurityException | ClassNotFoundException e){
				footer = ("ERROR: while Sending Message\n");
			}
			if(footer != null){
				if(footer.equals("==quit")){
					break;
				}
			}
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private String HandleMessageCommand(String text) {
		StringBuilder rtr = new StringBuilder();
		switch (text.substring(1).toLowerCase()){
			case "help" ->{
				rtr.append("\tHelp\n" +
						"!quit Exits the Messaging window back to the friends list\n" +
						"!info prints the information of the friend your chatting with\n" +
						"!help does something???? i think\n" +
						"you can also use the first char of each command\n"
				);
			}
			case "info", "i" -> {
				rtr.append("\t info \n");
			}
			case "quit", "q", "exit" -> {
				rtr.append("==quit");
			}
			/**
			 *TODO add rerender option
			 * 	window size options
			 * 	memory of the window sizes
			 * 	softwrapping
			 * 	color scheme for each chat
			 * 	quick switching
			 * 	notify message from other person has come in
			 *
			 */


		}
		return rtr.toString();
	}

	private void PrintNLines(int n) {
		StringBuilder sb = new StringBuilder();
		for (int j = 0; j < n; j++) {
			sb.append("\n");
		}
		System.out.print(sb);

	}
}
