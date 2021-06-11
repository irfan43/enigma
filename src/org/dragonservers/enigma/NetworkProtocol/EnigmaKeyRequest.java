package org.dragonservers.enigma.NetworkProtocol;

import org.dragonservers.turing.TuringConnectionException;

import java.security.*;
import java.util.Base64;

import static org.dragonservers.enigma.NetworkProtocol.Commands.*;

public class EnigmaKeyRequest {

	public String searchName;
	public String serRandom;
	public String signB64;

	public byte[] signBin;

	public EnigmaKeyRequest(String searchUsername,String serverRandom,KeyPair kp)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		serRandom = serverRandom;
		searchName = searchUsername;
		sign(kp.getPrivate());
	}



	public EnigmaKeyRequest(EnigmaNetworkHeader enh, String serverRandom, PublicKey publicKey) {
		serRandom = serverRandom;
		decodeStrings(enh);
		decodeBase64();
		Verify(publicKey);
	}
	private void decodeStrings(EnigmaNetworkHeader enh) {
		try {
			searchName = enh.GetValue(UsernameKey);
			signB64 = enh.GetValue(SignatureKey);
		}catch (IllegalArgumentException e){
			throw new TuringConnectionException("BAD HEADER");
		}
	}
	private void decodeBase64() {
		try{
			signBin 				= Base64.getDecoder().decode(signB64);
		}catch (IllegalArgumentException e) {
			throw new TuringConnectionException("BAD HEADER");
		}
	}
	private void Verify(PublicKey publicKey){
		try {
			Signature sgn = Signature.getInstance("SHA256withRSA");
			sgn.initVerify(publicKey);
			sgn.update(buildSignData());
			if(!sgn.verify(signBin))
				throw new TuringConnectionException("BAD Sign");
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e){
			throw new TuringConnectionException("BAD Sign");
		}
	}

	//		Client side
	public EnigmaNetworkHeader getHeader(){
		EnigmaNetworkHeader enh = new EnigmaNetworkHeader();

		enh.SetValue(SignatureKey	,signB64);
		enh.SetValue(UsernameKey	,searchName);

		return enh;
	}
	private void sign(PrivateKey privateKey)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(privateKey);
		sgn.update(buildSignData());
		signBin = sgn.sign();
		signB64 = Base64.getEncoder().encodeToString(signBin);
	}
	//common
	private byte[] buildSignData(){
		return EnigmaBaseRequest.Sandwich(searchName , serRandom);
	}

}
