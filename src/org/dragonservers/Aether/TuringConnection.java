package org.dragonservers.Aether;


import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaPacket;
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
import java.util.Random;

public class TuringConnection {

	//Networking Variables
	private Socket 				sock;
	private final String 		serverIP;
	private final int 			serverPort;
	private String	 			serverVersion;


	//Session Variables
	private boolean 			LoggedIn = false;
	private boolean				HookedListener = false;
	private String				randomServer,
								randomClient;

	//Encryption Variables
	public	PublicKey			serverRSAPublicKey;
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

	public void HookPacketListener() throws IOException {
		verifySafeCmdExc();
		String resp = ExecuteServerCommand(Commands.GetPacketCommand,"");
		verifyGoodResponse(resp);

	}

	public void Register(byte[] serverHash,String regCode)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
		verifyLoggedOut();
		EnigmaRegistrationRequest err = new EnigmaRegistrationRequest(
				serverHash,
				Aether.OurKeyHandler,
				Aether.Username,
				regCode,
				randomServer);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(Commands.RegistrationCommand,err.getHeader());
		}
		verifyGoodResponse(resp);
	}

	public void Login(String username,byte[] serverHash)
			throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException {

		verifyLoggedOut();

		EnigmaLoginRequest elr = new EnigmaLoginRequest(
				username,
				serverHash,
				randomServer,
				Aether.OurKeyHandler);

		Arrays.fill(serverHash,(byte)0x00);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(
					Commands.LoginCommand,
					elr.getHeader());
		}
		verifyGoodResponse(resp);
		LoggedIn = true;

	}
	public void LogOut() throws IOException {
		verifySafeCmdExc();
		try {
			String resp = ExecuteServerCommand(Commands.LogoutCommand,"");
		}catch (SocketException ignored){}
		finally {
			sock.close();
		}
	}

	public byte[] GetPublicKey(String searchUsername)
			throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		verifySafeCmdExc();

		EnigmaKeyRequest ekr = new EnigmaKeyRequest(
				searchUsername,
				randomServer,
				Aether.OurKeyHandler);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(
					Commands.GetUserPublicKeyCommand,
					ekr.getHeader());
		}

		verifyGoodResponse(resp);
		return decodePublicKey(resp);
	}
	public String GetUsername(PublicKey searchPublicKey)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException{
		verifySafeCmdExc();

		EnigmaNameRequest enr = new EnigmaNameRequest(
				searchPublicKey.getEncoded(),
				randomServer,
				Aether.OurKeyHandler);

		String resp;
		synchronized (lockObject){
			resp = ExecuteServerCommand(
					Commands.GetUsernameCommand,
					enr.getHeader());
		}
		verifyGoodResponse(resp);
		return decodeUsername(resp);
	}
	public void	SendPacket(EnigmaPacket enigmaPacket) throws IOException {
		verifySafeCmdExc();

		byte[] bin = enigmaPacket.EncodedBinary;

		String resp;
		synchronized (lockObject){
			WriteServerCommand(Commands.SendPacketCommand,"");
			EnigmaBlock.WriteBlock(cos,bin);
			resp = ReadServerResponse();
		}
		verifyGoodResponse(resp);
	}

	//util functions
	private void verifyGoodResponse(String response){
		if(!response
				.toLowerCase()
				.contains("good")
		)
			throw new IllegalArgumentException(response);
	}
	private void verifyLoggedOut(){
		if(LoggedIn)
			throw new IllegalArgumentException("ILLEGAL STATE Already Logged In");
	}
	private void verifySafeCmdExc(){
		verifyLoggedIn();
		verifyNotHooked();
	}
	private void verifyLoggedIn(){
		if(!LoggedIn)
			throw new IllegalArgumentException("ILLEGAL STATE Command Requires Login");
	}
	private void verifyHooked(){
		if(!HookedListener)
			throw new IllegalArgumentException("ILLEGAL STATE Connection not hooked");
	}
	private void verifyNotHooked(){
		if(HookedListener)
			throw new IllegalArgumentException("ILLEGAL STATE Connection already hooked");
	}
	private byte[] decodePublicKey(String response){
		try{
			return Base64.getDecoder().decode( decodeObject(response,Commands.PublicKeyKey) );
		}
		catch (IllegalArgumentException | NullPointerException e){
			throw new IllegalArgumentException("BAD Server Response");
		}

	}
	private String decodeUsername(String response) {
		try {
			return decodeObject(response,Commands.UsernameKey);
		}
		catch (IllegalArgumentException | NullPointerException e){
			throw new IllegalArgumentException("BAD Server Response");
		}
	}
	private String decodeObject(String response, String key){
		String rtr = null;
		if( !response.contains(Commands.ObjectNotFound) && response.contains(key) ){
			String[] lines = response.split("\n");
			try {
				for (String line : lines) {
					if (line.contains(key)) {
						rtr = EnigmaNetworkHeader.SplitOnSeparator(line)[1];
						break;
					}
				}
			}
			catch (IllegalArgumentException e){
				throw new IllegalArgumentException("Bad Server Response");
			}
		}
		return rtr;
	}

//		Server Introduction
	private void introduceServer (InputStream is, OutputStream os)
			throws IOException, GeneralSecurityException {
		getServerInfo				( is, os);
		handleECDHExchange			( is, os);
		generateStreamsAndRandoms	( is, os);

	}
	private void getServerInfo (InputStream is, OutputStream os)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		EnigmaBlock.WriteBlockLine(Aether.EnigmaVersion, os);

		serverVersion 		= EnigmaBlock.ReadBlockLine(is);
		serverRSAPublicKey 	= EnigmaKeyHandler.RSAPublicKeyFromEnc(EnigmaBlock.ReadBlock(is));
	}

	private void handleECDHExchange(InputStream is, OutputStream os)
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
	private void createSecretKey (InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		secretKey 		= new SecretKeySpec(sharedSecret, 0, 16, "AES");
		outboundCipher	= EnigmaECDH.makeOutboundCipher	(os, secretKey);
		inboundCipher 	= EnigmaECDH.makeInboundCipher	(is, secretKey);
	}
	private void initializeStreams (InputStream is, OutputStream os){
		cis 	= new CipherInputStream		(is, inboundCipher);
		cos 	= new CipherOutputStream	(os, outboundCipher);
		br 		= new BufferedReader		(new InputStreamReader(cis));
		bw 		= new BufferedWriter		(new OutputStreamWriter(cos));
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

	public PublicKey 	GetServerPublicKey(){
		return serverRSAPublicKey;
	}
	public String 		GetServerVersion() {
		return serverVersion;
	}
	public boolean 		isLoggedIn() {
		return LoggedIn;
	}


}
