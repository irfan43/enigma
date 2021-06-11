package org.dragonservers.Aether;


import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.NetworkProtocol.EnigmaECDH;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

public class TuringConnection implements Runnable{

	private Socket 				sock;
	private final String 		serverIP;
	private final int 			serverPort;

	private String				randomServer,
								randomClient;

	private PublicKey			serverRSAPublicKey,
								serverECDHPublicKey;
	private byte[] 				sharedSecret;
	private SecretKeySpec 		secretKey;
	private Cipher 				inboundCipher,
								outboundCipher;

	private CipherInputStream 	cis;
	private CipherOutputStream 	cos;
	private BufferedReader 		br;
	private BufferedWriter 		bw;

	public String serverVersion;

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

	private void introduceServer(InputStream is,OutputStream os)
			throws IOException, GeneralSecurityException {
		getServerPublicKey(is,os);
		HandleECDHExchange(is,os);
		createSecretKey(is,os);
		initializeStreams(is,os);
		initializeRandoms(is,os);
	}
	private void initializeRandoms(InputStream is, OutputStream os)
			throws IOException, GeneralSecurityException {
		randomClient = "" + (new Random()).nextLong();
		bw.write(randomClient + "\n");
		randomServer = br.readLine();

		byte[] sign = Base64.getDecoder().decode( br.readLine() );
		if(verifyServerSignature(
				(randomServer + randomClient).getBytes(StandardCharsets.UTF_8),sign) ){
			throw new GeneralSecurityException("Bad Server Signature");
		}
	}
	private void initializeStreams(InputStream is,OutputStream os) {
		cis = new CipherInputStream(is,inboundCipher);
		cos = new CipherOutputStream(os,outboundCipher);
		br = new BufferedReader(new InputStreamReader(cis));
		bw = new BufferedWriter(new OutputStreamWriter(cos));
	}
	private void createSecretKey(InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
		outboundCipher = EnigmaECDH.makeOutboundCipher(os, secretKey);
		inboundCipher = EnigmaECDH.makeInboundCipher(is,secretKey);
	}
	private void HandleECDHExchange(InputStream is, OutputStream os)
			throws GeneralSecurityException, IOException {
		KeyPair kp = EnigmaKeyHandler.generateECDHKey();
		exchangeECDHPublicKey(os,is,kp.getPublic());
		sharedSecret = EnigmaECDH.makeSecret(kp,serverECDHPublicKey);
	}
	private void exchangeECDHPublicKey(OutputStream os, InputStream is, PublicKey publicKey)
			throws IOException, GeneralSecurityException{
		//send our key
		EnigmaBlock.WriteBlock(os,publicKey.getEncoded());
		//read server key
		byte[] serverECDHPublicEnc = EnigmaBlock.ReadBlock(is);
		serverECDHPublicKey = EnigmaECDH.publicECDHKeyFromEncoded(serverECDHPublicEnc);
		if(verifyServerSignature(serverECDHPublicEnc, EnigmaBlock.ReadBlock(is)))
			throw new GeneralSecurityException("BAD SERVER SIGNATURE");
	}
	private boolean verifyServerSignature(byte[] data,byte[] signature)
			throws GeneralSecurityException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(serverRSAPublicKey);
		sgn.update(data);
		return !sgn.verify(signature);
	}
	private void getServerPublicKey(InputStream is,OutputStream os)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		EnigmaBlock.WriteBlockLine(Aether.EnigmaVersion,os);
		serverVersion = EnigmaBlock.ReadBlockLine(is);
		byte[] serverPublicKeyEnc = EnigmaBlock.ReadBlock(is);
		serverRSAPublicKey = EnigmaKeyHandler.PublicKeyFromEnc(serverPublicKeyEnc);
	}



	@Override
	public void run(){

	}


}
