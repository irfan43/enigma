package org.dragonservers.enigma.NetworkProtocol;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.turing.TuringConnectionException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.dragonservers.enigma.NetworkProtocol.Commands.*;

public class EnigmaRegistrationRequest {

	public String uname;
	public String regCode;
	private String randomS;

	public String passwordHashB64;
	public byte[] passwordHash;

	public String publicKeyB64;
	public byte[] publicKeyEncoded;
	public PublicKey publicKey;

	public byte[] signBin;
	public String signB64;

	//Constructors
	public EnigmaRegistrationRequest(byte[] password,
									 EnigmaKeyHandler ekh,
									 String username,
									 String registrationCode,
									 String randomServer)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		buildRequest(password,ekh,username,registrationCode,randomServer);
	}
	public EnigmaRegistrationRequest(EnigmaNetworkHeader enigmaNetworkHeader,String randomServer,boolean verify){
		randomS = randomServer;
		decodeRequestHeader(enigmaNetworkHeader);
		if(verify)
			verifySignature();
	}

	//			Server Side
	//header decoding
	private void decodeRequestHeader(EnigmaNetworkHeader enigmaNetworkHeader)
			throws TuringConnectionException{

		try{
			decodeStrings(enigmaNetworkHeader);
			decodeBase64();
			publicKey = EnigmaKeyHandler.RSAPublicKeyFromEnc(publicKeyEncoded);
		} catch (IllegalArgumentException
				| InvalidKeySpecException
				| NoSuchAlgorithmException
				| NullPointerException e){
			throw new TuringConnectionException("BAD header");
		}
	}
	private void decodeStrings(EnigmaNetworkHeader enigmaNetworkHeader){
		uname 				= enigmaNetworkHeader.GetValue(UsernameKey);
		passwordHashB64 	= enigmaNetworkHeader.GetValue(PasswordKey);
		publicKeyB64 		= enigmaNetworkHeader.GetValue(PublicKeyKey);
		regCode 			= enigmaNetworkHeader.GetValue(RegCodeKey);
		signB64 			= enigmaNetworkHeader.GetValue(SignatureKey);
	}
	private void decodeBase64(){
		passwordHash 		= Base64.getDecoder().decode(passwordHashB64);
		publicKeyEncoded 	= Base64.getDecoder().decode(publicKeyB64);
		signBin = Base64.getDecoder().decode(signB64);
	}
	private void verifySignature() throws TuringConnectionException{
		try {
			Signature sgn = Signature.getInstance("SHA256withRSA");
			sgn.initVerify(publicKey);
			sgn.update(buildSignData());
			if(!sgn.verify(signBin))
				throw new TuringConnectionException("BAD sign");
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new TuringConnectionException("BAD sign");
		}
	}

	//			Client Side
	private void buildRequest(byte[] password,
							 EnigmaKeyHandler ekh,
							 String username,
							 String registrationCode,
							 String randomServer)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		setupPassword(password);
		setupPublicKey(ekh.getPublic());

		uname 		= username;
		randomS 	= randomServer;
		regCode 	= registrationCode;

		sign(ekh);
	}
	//load methods
	private void setupPassword(byte[] pass){
		passwordHash = pass;
		passwordHashB64 = Base64
				.getEncoder()
				.encodeToString(passwordHash);
	}
	private void setupPublicKey(PublicKey pk){
		publicKey = pk;
		publicKeyEncoded = publicKey.getEncoded();
		publicKeyB64 = Base64
				.getEncoder()
				.encodeToString(publicKeyEncoded);
	}
	private void sign(EnigmaKeyHandler ekh)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = ekh.GetSignature();
		signature.update(buildSignData());

		signBin = signature.sign();
		signB64 = Base64.getEncoder().encodeToString(signBin);
	}
	//get final output
	public EnigmaNetworkHeader getHeader(){
		EnigmaNetworkHeader enh = new EnigmaNetworkHeader();

		enh.SetValue(UsernameKey	,uname);
		enh.SetValue(PublicKeyKey	,publicKeyB64);
		enh.SetValue(PasswordKey	,passwordHashB64);
		enh.SetValue(RegCodeKey		,regCode);
		enh.SetValue(SignatureKey	,signB64);

		return enh;
	}

	//common
	private byte[] buildSignData(){
		return EnigmaBaseRequest.Sandwich(
				uname + passwordHashB64 + publicKeyB64 + regCode,
				randomS);
	}

}
