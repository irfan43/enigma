package org.dragonservers.Aether;


import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.enigma.NetworkProtocol.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;

public class TuringConnection implements Runnable{

	//Networking Variables
	private Socket 				sock;
	private final String 		serverIP;
	private final int 			serverPort;
	private String	 			serverVersion;


	//Session Variables
	private boolean 			LoggedIn = false;
	private String				randomServer,
								randomClient;

	//Encryption Variables
	private PublicKey			serverRSAPublicKey;
	private PublicKey			serverECDHPublicKey;
	private byte[] 				sharedSecret;
	private SecretKeySpec 		secretKey;
	private Cipher 				inboundCipher,
								outboundCipher;

	//Streams
	private CipherInputStream 	cis;
	private CipherOutputStream 	cos;
	private BufferedReader 		br;
	private BufferedWriter 		bw;

	private final Object lockObject = new Object();

	public TuringConnection(String serverHost,int port) throws IOException, GeneralSecurityException {
		serverIP = serverHost;
		serverPort = port;
		Connect();
	}

	public void Connect() throws IOException, GeneralSecurityException {
		if(sock.isConnected())
			throw new IllegalArgumentException("Already Connected");
		sock = new Socket(serverIP,serverPort);

		InputStream 	is = sock.getInputStream();
		OutputStream 	os = sock.getOutputStream();
		introduceServer(is,os);
	}


	public void Register(byte[] serverHash,KeyPair kp,String username,String regCode)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
		VerifyLoggedOut();
		EnigmaRegistrationRequest err = new EnigmaRegistrationRequest(
				serverHash,
				kp,
				username,
				regCode,
				randomServer);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(Commands.RegistrationCommand,err.getHeader());
		}
		if(!resp.toLowerCase().contains("good"))
			throw new IllegalArgumentException(resp);
	}
	public void Login(String username,byte[] serverHash,KeyPair kp)
			throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException {

		VerifyLoggedOut();

		EnigmaLoginRequest elr = new EnigmaLoginRequest(
				username,
				serverHash,
				randomServer,
				kp);

		Arrays.fill(serverHash,(byte)0x00);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(
					Commands.LoginCommand,
					elr.getHeader());
		}
		if(!resp.toLowerCase().contains("good"))
			throw new IllegalArgumentException(resp);
		LoggedIn = true;
	}
	public void LogOut() throws IOException {
		try {
			String resp = ExecuteServerCommand(Commands.LogoutCommand,"");
		}
		catch (SocketException ignored){}
		finally {
			sock.close();
		}
	}
	public byte[] GetPublicKey(String searchUsername,KeyPair kp)
			throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		VerifyLoggedIn();

		EnigmaKeyRequest ekr = new EnigmaKeyRequest( searchUsername,randomServer,Aether.OurKeyHandler);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(
					Commands.GetUserPublicKeyCommand,
					ekr.getHeader());
		}
		handle resp
	}
	public String GetUsername(PublicKey searchPublicKey,KeyPair kp){
		VerifyLoggedIn();
		String resp
		synchronized (lockObject){
			resp = ExecuteServerCommand();
		}
		handle resp
	}
	public void	SendPacket(EnigmaPacket enigmaPacket){
		VerifyLoggedIn();
		String resp;
		synchronized (lockObject){
			WriteServerCommand(,);

		}
		handle resp
	}

	private void VerifyLoggedOut(){
		if(LoggedIn)
			throw new IllegalArgumentException("ILLEGAL STATE Already Logged In");
	}
	private void VerifyLoggedIn(){
		if(!LoggedIn)
			throw new IllegalArgumentException("ILLEGAL STATE Command Requires Login");
	}

		//		Server Introduction
	private void introduceServer (InputStream is, OutputStream os)
			throws IOException, GeneralSecurityException {
		getServerInfo				( is, os);
		HandleECDHExchange			( is, os);
		generateStreamsAndRandoms	( is, os);

	}

	private void getServerInfo (InputStream is, OutputStream os)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		EnigmaBlock.WriteBlockLine(Aether.EnigmaVersion, os);

		serverVersion 		= EnigmaBlock.ReadBlockLine(is);
		serverRSAPublicKey 	= EnigmaKeyHandler
				.RSAPublicKeyFromEnc(EnigmaBlock.ReadBlock(is));
	}

	private void HandleECDHExchange (InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		KeyPair kp = EnigmaECDH.generateECDHKey();
		exchangeECDHPublicKey(os, is, kp.getPublic());
		sharedSecret = EnigmaECDH.makeSecret(kp, serverECDHPublicKey);
	}
	private void exchangeECDHPublicKey (OutputStream os, InputStream is, PublicKey publicKey)
			throws IOException, GeneralSecurityException {

		EnigmaBlock.WriteBlock(os, publicKey.getEncoded());
		byte[] serverECDHPublicEnc = EnigmaBlock.ReadBlock(is);
		serverECDHPublicKey = EnigmaECDH.publicECDHKeyFromEncoded(serverECDHPublicEnc);

		verifyServerSignature(serverECDHPublicEnc, EnigmaBlock.ReadBlock(is));
	}

	private void generateStreamsAndRandoms(InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		createSecretKey		(  is, os);
		initializeStreams	(  is, os);
		initializeRandoms	(  is, os);
	}
	private void initializeStreams (InputStream is, OutputStream os){
		cis 	= new CipherInputStream		(is, inboundCipher);
		cos 	= new CipherOutputStream	(os, outboundCipher);
		br 		= new BufferedReader		(new InputStreamReader(cis));
		bw 		= new BufferedWriter		(new OutputStreamWriter(cos));
	}
	private void createSecretKey (InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		secretKey 		= new SecretKeySpec(sharedSecret, 0, 16, "AES");
		outboundCipher	= EnigmaECDH.makeOutboundCipher	(os, secretKey);
		inboundCipher 	= EnigmaECDH.makeInboundCipher	(is, secretKey);
	}
	private void initializeRandoms (InputStream is, OutputStream os)
			throws IOException, GeneralSecurityException {
		randomClient = "" + (new Random()).nextLong();
		bw.write(randomClient + "\n");
		randomServer = br.readLine();

		byte[] sign = Base64
				.getDecoder()
				.decode(br.readLine());

		verifyServerSignature(
				(randomServer + randomClient).getBytes(StandardCharsets.UTF_8),
				sign);
	}

// Util methods

	/**
	 * Sends the server the given command along with the given header and reads the servers response
	 * @param command Command to be sent to the server
	 * @param header <code>EnigmaNetworkHeader</code> object of the command ie the parameters
	 * @return the response given by the server
	 * @throws IOException if a IOException occurs while communicating with the server
	 */
	private String ExecuteServerCommand(String command,EnigmaNetworkHeader header) throws IOException {
		return ExecuteServerCommand(command,header.GetHeader(true));
	}
	/**
	 * Sends the server the given command along with the given header and reads the servers response
	 * @param command Command to be sent to the server
	 * @param header Header of the command ie the parameters
	 * @return the response given by the server
	 * @throws IOException if a IOException occurs while communicating with the server
	 */
	private String ExecuteServerCommand(String command,String header) throws IOException {
		WriteServerCommand(command,header);
		return ReadServerResponse();
	}
	private void WriteServerCommand(String command, EnigmaNetworkHeader header) throws IOException {
		WriteServerCommand(command,header.GetHeader(true));
	}
	private void WriteServerCommand(String command,String header) throws IOException{
		bw.write(command + "\n");
		if(!header.equals(""))
			bw.write(header + "\n");
		bw.newLine();
	}
	private String ReadServerResponse() throws IOException {
		StringBuilder resp = new StringBuilder();
		String line;

		while( !(line = br.readLine()).equals(""))
			resp.append(line).append("\n");

		return resp.toString();
	}
	private void verifyServerSignature ( byte[] data, byte[] signature)
			throws GeneralSecurityException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(serverRSAPublicKey);
		sgn.update(data);
		if(!sgn.verify(signature))
			throw new GeneralSecurityException("BAD SERVER SIGN");
	}



	@Override
	public void run(){

	}

	public PublicKey GetServerPublicKey(){
		return serverRSAPublicKey;
	}

	public String GetServerVersion() {
		return serverVersion;
	}

	public boolean isLoggedIn() {
		return LoggedIn;
	}
}
