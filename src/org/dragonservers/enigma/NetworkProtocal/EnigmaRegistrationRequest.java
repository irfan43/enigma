package org.dragonservers.enigma.NetworkProtocal;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaNetworkHeader;
import org.dragonservers.turing.TuringConnectionException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class EnigmaRegistrationRequest {
	public String uname;
	public String regCode;
	private String randomS;

	public String passwordHashB64;
	public byte[] passwordHash;

	public String publicKeyB64;
	public byte[] publicKeyEncoded;
	public PublicKey publicKey;

	public byte[] sign;
	public String signB64;

	public void buildRequest(byte[] password,
							 KeyPair keyPair,
							 String username,
							 String registrationCode,
							 String randomServer)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		uname = username;
		passwordHash = password;
		passwordHashB64 = Base64.getEncoder().encodeToString(password);
		setupPublicKey(keyPair.getPublic());
		randomS = randomServer;
		regCode = registrationCode;
		sign(keyPair);
	}
	private void sign(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] data = buildSignString().getBytes(StandardCharsets.UTF_8);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(data);
		sign = signature.sign();
		signB64 = Base64.getEncoder().encodeToString(sign);
	}
	private void setupPublicKey(PublicKey pk){
		publicKey = pk;
		publicKeyEncoded = publicKey.getEncoded();
		publicKeyB64 = Base64
				.getEncoder()
				.encodeToString(publicKeyEncoded);
	}
	public void decodeRequestHeader(EnigmaNetworkHeader enigmaNetworkHeader, String randomServer)
			throws TuringConnectionException{
		randomS = randomServer;
		try{
			decodeStrings(enigmaNetworkHeader);
			decodeBase64();
			publicKey = EnigmaKeyHandler.PublicKeyFromEnc(publicKeyEncoded);
		} catch (IllegalArgumentException
				| InvalidKeySpecException
				| NoSuchAlgorithmException
				| NullPointerException e){
			throw new TuringConnectionException("BAD header");
		}
	}
	public void verifySignature() throws TuringConnectionException{
		try {
			Signature sgn = Signature.getInstance("SHA256withRSA");
			sgn.initVerify(publicKey);
			sgn.update(buildSignString().getBytes(StandardCharsets.UTF_8));
			if(!sgn.verify(sign))
				throw new TuringConnectionException("BAD sign");
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new TuringConnectionException("BAD sign");
		}

	}
	private String buildSignString(){
		return randomS +
				uname +
				publicKeyB64 +
				regCode +
				randomS;
	}
	private void decodeStrings(EnigmaNetworkHeader enigmaNetworkHeader){
		uname 			= enigmaNetworkHeader.GetValue("username");
		passwordHashB64 	= enigmaNetworkHeader.GetValue("password");
		publicKeyB64 		= enigmaNetworkHeader.GetValue("publicKey");
		regCode 			= enigmaNetworkHeader.GetValue("regCode");
		signB64 			= enigmaNetworkHeader.GetValue("sign");
	}
	private void decodeBase64(){
		passwordHash 		= Base64.getDecoder().decode(passwordHashB64);
		publicKeyEncoded 	= Base64.getDecoder().decode(publicKeyB64);
		sign 				= Base64.getDecoder().decode(signB64);
	}
}
