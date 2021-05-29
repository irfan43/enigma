package org.dragonservers.turing;

import org.dragonservers.enigma.NetworkProtocal.Commands;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaNetworkHeader;
import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.NetworkProtocal.EnigmaRegistrationRequest;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;



public class NetworkConnection implements Runnable{

	private final Socket socket;
	private boolean logged_in;
	private String clientUsername,randomServer,randomClient;
	private PublicKey clientPublicKey;
	private byte[] sharedSecret;
	private SecretKeySpec secretKey;
	private Cipher inboundCipher, outboundCipher;
	private CipherInputStream cis;
	private CipherOutputStream cos;
	private BufferedReader br;
	private BufferedWriter bw;

	public NetworkConnection(Socket sock){
		socket = sock;
	}

	/**
	 * Protocol
	 */

	@Override
	public void run() {

		try {
			DataInputStream dis;
			DataOutputStream dos;
			dis = new DataInputStream(socket.getInputStream());
			dos = new DataOutputStream(socket.getOutputStream());
			//Starting to read introduction
			initializeClient(dis,dos);

			while (!socket.isClosed()){
				try {
					String command = br.readLine();
					EnigmaNetworkHeader enh = readHeader(br);
					switch (command) {
						case Commands.RegistrationCommand -> HandleRegistration(enh);
						case Commands.LoginCommand -> HandleLogin(enh);
						case Commands.GetPacketCommand -> HandleGetPacketCommand(enh);
						case Commands.SendPacketCommand -> HandleSendPacketCommand(enh);
						case Commands.LogoutCommand -> HandleLogoutCommand(enh);
						case Commands.GetHistoryCommand -> HandleGetHistoryCommand(enh);
						case Commands.GetUserPublicKeyCommand -> HandleGetUserPublicKeyCommand(enh);
						case Commands.GetUsernameCommand -> HandleGetUsernameCommand(enh);
						default -> SendBadCommand();
					}

				}catch (TuringConnectionException e){
					bw.write(e.getMessage() + "\n");
					bw.newLine();
				}catch (Exception e){
					bw.write("BAD SERVER ERROR\n");
					bw.newLine();
					break;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e ){
			System.out.println("UNExpected Error");
			Turing.TuringLogger.log(Level.INFO,"un expected error " + Arrays.toString(e.getStackTrace()));
			e.printStackTrace();
		}
	}

	private EnigmaNetworkHeader readHeader(BufferedReader bufferedReader) throws IOException {
		String line = "a";
		StringBuilder headerBuffer = new StringBuilder();
		while (!line.equals("")){
			line = br.readLine();
			headerBuffer.append(line);
			headerBuffer.append("\n");
		}
		return new EnigmaNetworkHeader(headerBuffer.toString());
	}

	private void initializeClient(InputStream is,OutputStream os) throws IOException,GeneralSecurityException {
		//Starting to read introduction
		sendPublicKey(is,os);
		//TODO handle if client is old or incompatible
		HandleECDHExchange(is,os);
		CreateSecretKey(is,os);
		initializeStreams(is,os);
		initializeRandoms();
	}
	private void sendPublicKey(InputStream is,OutputStream os) throws IOException{
		String clientInformation = EnigmaBlock.ReadBlockLine(is);
		EnigmaBlock.WriteBlockLine("Turing Server V1.2",os);
		EnigmaBlock.WriteBlock(os,Turing.TuringKH.GetPublicKey().getEncoded());
	}
	private void initializeRandoms()
			throws IOException, GeneralSecurityException {
		randomServer = "" + (new Random()).nextLong();
		bw.write(randomServer + "\n");
		randomClient = br.readLine();
		bw.write(Base64
				.getEncoder()
				.encodeToString(
						Turing.TuringKH.Sign(
								(randomServer + randomClient).getBytes(StandardCharsets.UTF_8))
				)
		);
	}
	private void initializeStreams(InputStream is,OutputStream os){
		cis = new CipherInputStream(is,inboundCipher);
		cos = new CipherOutputStream(os,outboundCipher);
		br = new BufferedReader(new InputStreamReader(cis));
		bw = new BufferedWriter(new OutputStreamWriter(cos));
	}
	private void SendBadCommand() throws IOException {
		bw.write("BAD COMMAND\n\n");
	}

	private void HandleGetUsernameCommand(EnigmaNetworkHeader enh) {
	}

	private void HandleGetUserPublicKeyCommand(EnigmaNetworkHeader enh) {
	}

	private void HandleGetHistoryCommand(EnigmaNetworkHeader enh) {
	}

	private void HandleSendPacketCommand(EnigmaNetworkHeader enh) {
	}

	private void HandleGetPacketCommand(EnigmaNetworkHeader enh) {
	}


	private void HandleLogin(EnigmaNetworkHeader enh) {
	}

	private void HandleRegistration(EnigmaNetworkHeader enh) throws IOException {
		EnigmaRegistrationRequest err = new EnigmaRegistrationRequest();
		err.decodeRequestHeader(enh,randomServer);
		//verify signature
		err.verifySignature();
		//redeem the code
		if(!Turing.CodeFac.Redeem(err.regCode))
			throw new TuringConnectionException("BAD Code");
		err.verifySignature();

		switch (Turing.EUserFac.RegisterUser(err.uname,err.publicKey,err.passwordHash)){
			case 0 ->{
				bw.write("good");
			}
			case -1 ->{
				bw.write("bad invalid_username");
			}
			case -2 ->{
				bw.write("bad username_exist");
			}
			case -3 ->{
				bw.write("bad public_key_exist");
			}
			default ->{
				bw.write("bad server_error");
			}
		}
		bw.newLine();
		bw.newLine();
	}

	private void HandleLogoutCommand(EnigmaNetworkHeader enh) {
	}

	private void CreateSecretKey(InputStream dis, OutputStream dos)
			throws IOException, GeneralSecurityException {
		secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
		initializeOutboundCipher(dos);
		initializeInboundCipher(dis);

	}
	private AlgorithmParameters readClientParameters(InputStream is)
			throws IOException, GeneralSecurityException {
		//TODO add XOR encryption to params to add additional layers of security
		AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("AES");
		algorithmParameters.init(EnigmaBlock.ReadBlock(is));
		return algorithmParameters;
	}
	private void initializeInboundCipher(InputStream is)
			throws IOException, GeneralSecurityException {
		inboundCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		inboundCipher.init(
				Cipher.DECRYPT_MODE,
				secretKey,
				readClientParameters(is)
		);
	}
	private void initializeOutboundCipher(OutputStream os)
			throws IOException, GeneralSecurityException {
		outboundCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		outboundCipher.init(Cipher.ENCRYPT_MODE,secretKey);

		EnigmaBlock.WriteBlock(os,
				outboundCipher
						.getParameters()
						.getEncoded()
		);
	}


	private void HandleECDHExchange(InputStream dis, OutputStream dos)
			throws IOException, GeneralSecurityException {
		//TODO have some interface to send available curves for client to select
		KeyPair kp = generateECDHKey();
		sendServerECDHKey(dos,kp);
		PublicKey clientPublicKey = getClientPublicKey(dis);
		sharedSecret = makeSecret(kp,clientPublicKey);
	}
	private byte[] makeSecret(KeyPair kp, PublicKey clientPublicKey)
			throws GeneralSecurityException{
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(kp.getPrivate());
		keyAgreement.doPhase(clientPublicKey,true);
		return keyAgreement.generateSecret();
	}
	private KeyPair generateECDHKey() throws GeneralSecurityException {
		KeyPairGenerator kpg =KeyPairGenerator.getInstance("EC");

		//we are using this curve , however later we should move to a better curve
		//testing shows it works in java 15 so don't touch it
		//IF YOU CHANGE THIS CHECK WITH ALL VERSION OF JAVA BEFORE PUSHING
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		return kpg.generateKeyPair();
	}
	private void sendServerECDHKey(OutputStream os, KeyPair kp)
			throws IOException, GeneralSecurityException {
		byte[] publicKeyEncoded = kp.getPublic().getEncoded();
		EnigmaBlock.WriteBlock(os,publicKeyEncoded);
		EnigmaBlock.WriteBlock(os,Turing.TuringKH.Sign(publicKeyEncoded));
	}
	private PublicKey getClientPublicKey(InputStream is)
			throws IOException, GeneralSecurityException {
		byte[] keyEncoded = EnigmaBlock.ReadBlock(is);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return keyFactory.generatePublic(new X509EncodedKeySpec(keyEncoded));
	}



}
