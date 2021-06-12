package org.dragonservers.enigma.NetworkProtocol;

import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.turing.TuringConnectionException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.dragonservers.enigma.NetworkProtocol.Commands.*;


public class EnigmaLoginRequest {

	public String uname;
	public String lHashB64;
	public String serRandom;

	public String signB64;
	public String publicKeyB64;

	public byte[] lHash;
	public byte[] signBin;
	public byte[] publicKeyEnc;


	public EnigmaLoginRequest(String username, byte[] serverHash, String serverRandom,KeyPair kp)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		uname 		= username;
		serRandom 	= serverRandom;
		setupPublicKey(kp.getPublic());
		setupServerHash(serverHash);
		sign(kp.getPrivate());
	}

	public EnigmaLoginRequest(EnigmaNetworkHeader enh,String serverRandom,boolean verify){
		serRandom 	= serverRandom;
		decodeRequestHeader(enh);
		if(verify)
			Verify();
	}
	//				Server Side
	private void decodeRequestHeader(EnigmaNetworkHeader enh){
		try {
			uname 				= enh.GetValue(UsernameKey);
			publicKeyB64 		= enh.GetValue(PublicKeyKey);
			lHashB64 			= enh.GetValue(PasswordKey);
			signB64 			= enh.GetValue(SignatureKey);
		}
		catch (IllegalArgumentException e){
			throw new TuringConnectionException("BAD Header");
		}
		decodeBase64();
	}
	private void decodeBase64(){
		try{
			signBin 		= Base64.getDecoder().decode(signB64);
			lHash 			= Base64.getDecoder().decode(lHashB64);
			publicKeyEnc 	= Base64.getDecoder().decode(publicKeyB64);
		}catch (IllegalArgumentException e){
			throw new TuringConnectionException("BAD Header");
		}
	}
	private void Verify() throws TuringConnectionException {
		try {
			Signature sgn = Signature.getInstance("SHA256withRSA");
			sgn.initVerify(getPublicKey());
			sgn.update(buildSignData());
			if(!sgn.verify(signBin))
				throw new TuringConnectionException("BAD Header");
		}
		catch (GeneralSecurityException e){
			throw new TuringConnectionException("BAD Header");
		}
	}
	private PublicKey getPublicKey(){
		try{
			return EnigmaKeyHandler.RSAPublicKeyFromEnc(publicKeyEnc);
		}
		catch (NoSuchAlgorithmException e) {
			throw new TuringConnectionException("Server ERROR");
		}
		catch (InvalidKeySpecException | IllegalArgumentException e) {
			throw new TuringConnectionException("BAD Header");
		}
	}

	//				Client Side
	public EnigmaNetworkHeader getHeader(){
		EnigmaNetworkHeader enh = new EnigmaNetworkHeader();

		enh.SetValue(UsernameKey	,uname);
		enh.SetValue(PasswordKey	,lHashB64);
		enh.SetValue(PublicKeyKey	,publicKeyB64);
		enh.SetValue(SignatureKey	,signB64);

		return enh;
	}
	private void setupPublicKey(PublicKey publicKey) {
		publicKeyEnc = publicKey.getEncoded();
		publicKeyB64 = Base64
				.getEncoder()
				.encodeToString(publicKeyEnc);
	}
	private void setupServerHash(byte[] serverHash) throws NoSuchAlgorithmException {
		lHash = EnigmaUser.GenerateLoginHash(
				serverHash,
				serRandom,
				uname);
		lHashB64 = Base64
				.getEncoder()
				.encodeToString(serverHash);
	}
	private void sign(PrivateKey privateKey) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(privateKey);
		sgn.update(buildSignData());

		signBin = sgn.sign();
		signB64 = Base64.getEncoder().encodeToString(signBin);
	}

	//common
	private byte[] buildSignData(){
		return EnigmaBaseRequest.Sandwich(
				publicKeyB64 + lHashB64 + uname,
				serRandom);
	}
}
