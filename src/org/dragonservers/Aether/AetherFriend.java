package org.dragonservers.Aether;

import org.dragonservers.enigma.*;

import javax.crypto.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class AetherFriend implements Serializable {
	//these are transient for security Reasons
	public PublicKey friendsPublicKey;
	private PublicKey FriendsDHPbk;
	private KeyPair DHKeyPair;
	private byte[] sharedSecret;
	public transient AetherMessages aetherMessages;
	public String friendsUsername;
	private boolean GotToken,SentToken,reDraw;
	public String friendFile;

	public AetherFriend(PublicKey publicKey, String username) throws GeneralSecurityException, IOException {

		friendsPublicKey = publicKey;
		friendsUsername = username;
		aetherMessages = new AetherMessages(friendsUsername,friendsPublicKey);
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
				Base64.getEncoder().encodeToString(Aether.OurKeyHandler.GetPublicKey().getEncoded()));
		enh.SetValue("UR_RSA_PublicKey",
				Base64.getEncoder().encodeToString(friendsPublicKey.getEncoded()));
		enh.SetValue("DH_PublicKey",
				Base64.getEncoder().encodeToString(DHKeyPair.getPublic().getEncoded()));
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(Aether.OurKeyHandler.GetPrivateKey());
		sgn.update(Aether.OurKeyHandler.GetPublicKey().getEncoded());
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
				Aether.OurKeyHandler.GetPublicKey().getEncoded()))
			throw new IllegalArgumentException("Report BAD RSA our Public Key in introduction token ");
		if(!Arrays.equals(TherePublicKey,
				friendsPublicKey.getEncoded()))
			throw new IllegalArgumentException("Report BAD RSA friends Public Key in introduction token ");

		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(friendsPublicKey);
		sgn.update(friendsPublicKey.getEncoded());
		sgn.update(Aether.OurKeyHandler.GetPublicKey().getEncoded());
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
		aetherMessages.PutMessage(EnigmaCrypto.AESDecrypt(data,sharedSecret) );
		saveMessagesToFile();
		reDraw = true;
	}
	public EnigmaPacket sendMessage(String data) throws GeneralSecurityException, IOException, ClassNotFoundException {
		loadIfNotLoaded();
		EnigmaPacket ep = new EnigmaPacket(Aether.OurKeyHandler.GetPublicKey(),friendsPublicKey);
		byte[] Cmdheader = "Text".getBytes(StandardCharsets.UTF_8);
		ByteBuffer bb = ByteBuffer.allocate(4).putInt(Cmdheader.length);
		ep.update(bb.array());
		ep.update(Cmdheader);
		byte[] TMEncoded = EnigmaCrypto.AESEncrypt(
				aetherMessages.SendMessage(data, Aether.OurKeyHandler.GetPrivateKey()),sharedSecret );
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

			c.init(Cipher.DECRYPT_MODE, Aether.AESEncryptionKey);
			CipherInputStream cipherInputStream = new CipherInputStream(is,c);

			ObjectInputStream objectInputStream = new ObjectInputStream(cipherInputStream);
			aetherMessages = (AetherMessages) objectInputStream.readObject();

			objectInputStream.close();
			cipherInputStream.close();
			is.close();
		}
	}
	public void saveMessagesToFile() throws GeneralSecurityException, IOException {
		Files.createDirectories(Path.of("friends"));
		OutputStream os = Files.newOutputStream(Path.of("friends",friendFile));
		final Cipher c = Cipher.getInstance("AES");

		c.init(Cipher.ENCRYPT_MODE, Aether.AESEncryptionKey);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(os,c);

		ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
		objectOutputStream.writeObject(aetherMessages);
		objectOutputStream.close();
		cipherOutputStream.close();
		os.close();
	}
	private void loadIfNotLoaded() throws GeneralSecurityException, IOException, ClassNotFoundException {
		if(aetherMessages == null)
			loadMessagesFromFile();
	}
	private void initializeFile() throws GeneralSecurityException, IOException {
		int nchars = 5;
		do {
		//todo try n times before moving to more letters
			friendFile = getRandomString(nchars) + ".msgcrypt";
			nchars++;
		}while (Files.exists(Path.of("friends",friendFile)));
		aetherMessages = new AetherMessages(friendsUsername,friendsPublicKey);
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
		String text;
		String footer = "";
		String inputBuffer = "";
		reDraw = true;
		int lines_msg_rendered = 35;
		int blank_lines_to_Add;
		while (true) {
			if(reDraw) {

				String ren = aetherMessages.GetRendered(35);
				blank_lines_to_Add = lines_msg_rendered - aetherMessages.LastRenderArray.length;
				AetherCLI.CLS();
				PrintNLines(100 - blank_lines_to_Add);
				System.out.println("\t== Chat with " + friendsUsername + " ==");
				PrintNLines( blank_lines_to_Add);

				System.out.print(ren);

				System.out.print(footer);
				System.out.print( Aether.Username + ":" + inputBuffer);
				reDraw = false;
			}
			try {
				int keyCode = RawConsoleInput.read(false);
				if (keyCode >= 0) {
					EnigmaPacket ep = null;
					//TODO add some esc variables so we can handles special chars in ubuntu
					char key = EnigmaConsoleUtil.GetChar(keyCode);
					if(key > 0){
						inputBuffer += (char)key;
						System.out.print((char)keyCode);
					}
					if (keyCode == 3) {
						System.out.println("Keyboard Interrupt");
						System.exit(-1);
					}
					if((keyCode == 127 && !AetherCLI.IsWindows) ||
							(keyCode == 8 && AetherCLI.IsWindows)){
						reDraw = true;
						inputBuffer = inputBuffer.substring(0,inputBuffer.length() - 1);
					}
					if( (keyCode == 10 && !AetherCLI.IsWindows) ||
							(keyCode == 13 && AetherCLI.IsWindows) ) {
						reDraw = true;
						//if new line ie enter was sent
						text = inputBuffer;
						inputBuffer = "";
						if (text.startsWith("!!")) {
							text = text.substring(1);
							ep = sendMessage(text);
						} else if (text.startsWith("!")) {
							footer = HandleMessageCommand(text);
						} else if (!text.equals("")) {
							footer = "";
							ep = sendMessage(text);
						} else {
							footer = "";
						}
						if (ep != null)
							AetherPacketFactory.QueueOutgoingPacket(ep);
					}
					if( (!AetherCLI.IsWindows) && keyCode == 27){
						List<Integer> buff = new ArrayList<>();
						do{
							buff.add(keyCode);
							keyCode = RawConsoleInput.read(false);
							try {
								Thread.sleep(3);
							} catch (InterruptedException ignored){}
						}while ( keyCode > 0);
						if(buff.size() != 1){
							footer = "Complex Key Input Not Supported";
						}else {
							//TODO handle ESC key input
						}
					}
				}
			} catch (IOException  e) {
				footer = ("ERROR: input buffer IO Exception\n");
				reDraw = true;
			}catch (GeneralSecurityException | ClassNotFoundException e){
				footer = ("ERROR: while Sending Message\n");
				reDraw = true;
			}
			if(footer.equals("==quit")){
				break;
			}

			try {
				Thread.sleep(5);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		RawConsoleInput.resetConsoleMode();
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
				rtr.append("\t info \n" +
						"Username:-" + friendsUsername + "\n" +
						"");
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
