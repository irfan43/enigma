package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.NetworkProtocol.Commands;
import org.dragonservers.enigma.EnigmaNetworkHeader;
import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.NetworkProtocol.EnigmaECDH;
import org.dragonservers.enigma.NetworkProtocol.EnigmaRegistrationRequest;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;



public class NetworkConnection implements Runnable{

	private final Socket 		socket;
	private boolean 			logged_in;
	private String 				clientUsername,
								randomServer,
								randomClient;
	private PublicKey 			clientPublicKey;

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
			DataInputStream dis;
			DataOutputStream dos;
			dis = new DataInputStream(socket.getInputStream());
			dos = new DataOutputStream(socket.getOutputStream());
			//Starting to read introduction
			InitializeClient(dis,dos);

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

	private void SendBadCommand() throws IOException {
		bw.write("BAD COMMAND\n\n");
	}

	private void HandleRegistration(EnigmaNetworkHeader enh) throws IOException {
		EnigmaRegistrationRequest err =
				new EnigmaRegistrationRequest(enh,randomServer,true);
		redeemAndRegister(err);
	}
	private void redeemAndRegister(EnigmaRegistrationRequest err) throws IOException {
		if(!Turing.CodeFac.Redeem(err.regCode))
			throw new TuringConnectionException("BAD Code");
		try {
			Turing.EUserFac.RegisterUser(err);
		}catch (Exception e){
			Turing.CodeFac.MarkUnused(err.regCode);
			throw new TuringConnectionException(e.getMessage());
		}
		bw.write("good\n\n");
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
	private void HandleLogoutCommand(EnigmaNetworkHeader enh) {
	}
	private void HandleLogin(EnigmaNetworkHeader enh) {
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

	/**
	 * Initializes incoming clients connection
	 * ECDH key exchange
	 * @param is socket input Stream
	 * @param os socket
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private void InitializeClient(InputStream is, OutputStream os) throws IOException,GeneralSecurityException {
		//Starting to read introduction
		sendPublicKey(is,os);
		HandleECDHExchange(is,os);
		CreateSecretKey(is,os);
		initializeStreams(is,os);
		initializeRandoms();
	}

	private void sendPublicKey(InputStream is,OutputStream os) throws IOException{

		//TODO handle if client is old or incompatible
		EnigmaBlock.WriteBlockLine("Turing Server V1.2",os);
		EnigmaBlock.WriteBlock(os,Turing.TuringKH.GetPublicKey().getEncoded());
		String clientInformation = EnigmaBlock.ReadBlockLine(is);
	}

	//Handle ECDH Key Exchange
	private void HandleECDHExchange(InputStream dis, OutputStream dos)
			throws IOException, GeneralSecurityException {
		//TODO have some interface to send available curves for client to select
		KeyPair kp = EnigmaKeyHandler.generateECDHKey();
		sendServerECDHKey(dos,kp);
		clientPublicKey = getClientPublicKeyECDH(dis);
		sharedSecret = EnigmaECDH.makeSecret(kp,clientPublicKey);
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
	//Create Key
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
