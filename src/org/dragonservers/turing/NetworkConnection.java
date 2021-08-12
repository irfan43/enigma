package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.NetworkProtocol.*;
import org.dragonservers.enigma.EnigmaBlock;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;



public class NetworkConnection implements Runnable{

	private final Socket 		socket;
	private boolean 			logged_in,
								listeningPacket;
	private PublicKey			clientRSAKey;
	private byte[]				publicRSAKeyENC;
	private String				publicRSAKeyB64;
	private String 				clientUsername,
								randomServer,
								randomClient;

	private byte[] 				sharedSecret;
	private SecretKeySpec 		secretKey;
	private Cipher 				inboundCipher,
								outboundCipher;
	private CipherInputStream 	cis;
	private CipherOutputStream 	cos;
	private BufferedReader 		br;
	private BufferedWriter 		bw;

	public NetworkConnection(Socket sock){
		socket = sock;
	}

	/**
	 * Protocol
	 */

	@Override
	public void run() {

		try {
			InputStream inputStream = socket.getInputStream();
			OutputStream outputStream = socket.getOutputStream();

			//Starting to read introduction
			InitializeClient(inputStream,outputStream);

			listeningPacket = false;
			while (!(socket.isClosed() || listeningPacket)){
				try {
					String command = br.readLine();
					EnigmaNetworkHeader enh = readHeader();
					HandleCommand(command,enh);
				}
				catch (TuringConnectionException e){
					bw.write(e.getMessage() + "\n");
					bw.newLine();
				}
				catch (Exception e){
					bw.write("BAD SERVER ERROR\n");
					bw.newLine();
					e.printStackTrace();
					break;
				}
				//TODO remove socket Exceptions on disconnect
			}
			if(!(listeningPacket || socket.isClosed()))
				socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e ){
			System.out.println("UNExpected Error");
			Turing.TuringLogger.log(Level.INFO,"un expected error " + Arrays.toString(e.getStackTrace()));
			e.printStackTrace();
		}
	}
	private void HandleCommand(String command, EnigmaNetworkHeader enh) throws IOException{
		switch (command) {
			//Account Commands
			case Commands.RegistrationCommand 			-> HandleRegistration(enh);
			case Commands.LoginCommand 					-> HandleLogin(enh);
			case Commands.LogoutCommand 				-> HandleLogoutCommand(enh);
			//Account Search
			case Commands.GetHistoryCommand 			-> HandleGetHistoryCommand(enh);
			case Commands.GetUserPublicKeyCommand 		-> HandleGetPublicKeyCommand(enh);
			case Commands.GetUsernameCommand 			-> HandleGetUsernameCommand(enh);
			//Packet Commands
			case Commands.GetPacketCommand 				-> HandleGetPacketCommand(enh);
			case Commands.SendPacketCommand 			-> HandleSendPacketCommand(enh);
			default -> SendBadCommand();
		}
	}
	private void SendBadCommand() throws IOException {
		bw.write("BAD COMMAND\n\n");
	}


	//Registration Commands
	private void HandleRegistration(EnigmaNetworkHeader enh) throws IOException {
		if(logged_in)
			throw new TuringConnectionException("Already Logged In");
		EnigmaRegistrationRequest err =
				new EnigmaRegistrationRequest(enh,randomServer,true);
		redeemAndRegister(err);
	}
	private void redeemAndRegister(EnigmaRegistrationRequest err) throws IOException {
		if(!Turing.CodeFac.Redeem(err.regCode))
			throw new TuringConnectionException("BAD Code");
		try {
			Turing.EUserFac.RegisterUser(err);
		}
		catch (Exception e){
			Turing.CodeFac.MarkUnused(err.regCode);
			throw new TuringConnectionException(e.getMessage());
		}
		bw.write("good\n\n");
	}

	//State Commands
	private void HandleLogin(EnigmaNetworkHeader enh) {
		if(logged_in)
			throw new TuringConnectionException("Already Logged In");

		EnigmaLoginRequest req = new EnigmaLoginRequest(enh,randomServer,true);
		Turing.EUserFac.VerifyLoginRequest(req);

		clientUsername 		= req.uname;
		publicRSAKeyB64 	= req.publicKeyB64;
		publicRSAKeyENC 	= req.publicKeyEnc;
		logged_in 			= true;
	}
	private void HandleLogoutCommand(EnigmaNetworkHeader enh) throws IOException {
		bw.write("goodbye\n\n");
		if(!socket.isClosed())socket.close();
	}

	//Database Search Commands
	private void HandleGetUsernameCommand(EnigmaNetworkHeader enh) throws IOException {
		verifyLoggedIn();
		EnigmaNameRequest req = new EnigmaNameRequest(enh,randomServer,clientRSAKey);
		String username;
		try{
			username = Commands.UsernameKey + ":" +
					Turing.EUserFac.GetUsername(req.searchPublicKeyB64);
		}catch (IllegalArgumentException e){
			username = Commands.ObjectNotFound;
		}
		bw.write("good\n");
		bw.write( username + "\n\n" );
	}
	private void HandleGetPublicKeyCommand(EnigmaNetworkHeader enh) throws IOException {
		verifyLoggedIn();
		EnigmaKeyRequest req = new EnigmaKeyRequest(enh,randomServer,clientRSAKey);
		String publicKeyB64;
		try{
			publicKeyB64 = Commands.PublicKeyKey + ":" +
					Turing.EUserFac.GetPublicKeyB64(req.searchName);
		}
		catch (IllegalArgumentException e){
			publicKeyB64 = Commands.ObjectNotFound;
		}
		bw.write("good\n");
		bw.write(publicKeyB64 + "\n\n");
	}
	private void HandleGetHistoryCommand(EnigmaNetworkHeader enh) {
		throw new TuringConnectionException("BAD INOPERABLE");
		//TODO fix this
	}

	//Packet Functions
	private void HandleSendPacketCommand(EnigmaNetworkHeader enh) throws IOException {
		verifyLoggedIn();
		byte[] packetEnc = EnigmaBlock.ReadBlock(cis);
		EnigmaPacket packet;
		try{
			packet = new EnigmaPacket(packetEnc);
		}
		catch (IllegalArgumentException | GeneralSecurityException e){
			throw new TuringConnectionException("BAD PACKET " );
		}
		Turing.EUserFac.SendPacket(packet,publicRSAKeyENC);
		bw.write("good\n");
		bw.newLine();
	}
	private void HandleGetPacketCommand(EnigmaNetworkHeader enh) throws IOException {
		verifyLoggedIn();
		Turing.EUserFac.hookPacketListener(publicRSAKeyB64,socket,cis,cos);
		listeningPacket = true;
	}


	//util methods
	private void verifyLoggedIn(){
		if(!logged_in)
			throw new TuringConnectionException("BAD STATE NOT LOGGED IN");
	}
	private EnigmaNetworkHeader readHeader() throws IOException {
		StringBuilder headerBuffer = new StringBuilder();

		String line;
		while ( !(line = br.readLine()).equals("") ){
			headerBuffer
					.append(line)
					.append("\n");
		}

		return new EnigmaNetworkHeader(headerBuffer.toString());
	}

	//setup new connection
	/**
	 * Initializes incoming clients connection
	 * ECDH key exchange
	 * @param is socket input Stream
	 * @param os socket output Stream
	 * @throws IOException if a IOException occurs while Initialisation
	 * @throws GeneralSecurityException if there is a security exception or a issues
	 */
	private void InitializeClient(InputStream is, OutputStream os)
			throws IOException,GeneralSecurityException {
		//Starting to read introduction
		sendPublicKey(is,os);
		HandleECDHExchange(is,os);
		CreateSecretKey(is,os);
		initializeStreams(is,os);
		initializeRandoms();
	}
	private void sendPublicKey(InputStream is,OutputStream os)
			throws IOException{
		//TODO handle if client is old or incompatible
		EnigmaBlock.WriteBlockLine("Turing Server V1.2",os);
		EnigmaBlock.WriteBlock(os,Turing.TuringKH.getPublic().getEncoded());
		String clientInformation = EnigmaBlock.ReadBlockLine(is);
	}

	//Handle ECDH Key Exchange
	private void HandleECDHExchange(InputStream dis, OutputStream dos)
			throws IOException, GeneralSecurityException {
		//TODO have some interface to send available curves for client to select
		KeyPair kp = EnigmaECDH.generateECDHKey();
		sendServerECDHKey(dos,kp);

		sharedSecret = EnigmaECDH.makeSecret(kp, getClientPublicKeyECDH(dis));
	}
	private void sendServerECDHKey(OutputStream os, KeyPair kp)
			throws IOException, GeneralSecurityException {
		byte[] publicKeyEncoded = kp.getPublic().getEncoded();
		EnigmaBlock.WriteBlock(os,publicKeyEncoded);
		EnigmaBlock.WriteBlock(os,Turing.TuringKH.Sign(publicKeyEncoded));
	}
	private PublicKey getClientPublicKeyECDH(InputStream is)
			throws IOException, GeneralSecurityException {
		return EnigmaECDH
				.publicECDHKeyFromEncoded(
						EnigmaBlock.ReadBlock(is));
	}

	//Create Key and Streams
	private void CreateSecretKey(InputStream is, OutputStream os)
			throws IOException, GeneralSecurityException {
		secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
		initializeCipher( os,is);
	}
	private void initializeCipher(OutputStream os, InputStream is)
			throws GeneralSecurityException, IOException {
		outboundCipher = EnigmaECDH.makeOutboundCipher(os, secretKey);
		inboundCipher = EnigmaECDH.makeInboundCipher(is,secretKey);
	}
	private void initializeStreams(InputStream is,OutputStream os){
		cis = new CipherInputStream(is,inboundCipher);
		cos = new CipherOutputStream(os,outboundCipher);
		br = new BufferedReader(new InputStreamReader(cis));
		bw = new BufferedWriter(new OutputStreamWriter(cos));
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
		bw.newLine();
	}
}
