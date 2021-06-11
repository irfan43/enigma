package org.dragonservers.enigma.NetworkProtocol;

import org.dragonservers.turing.TuringConnectionException;

import java.security.*;
import java.util.Base64;

import static org.dragonservers.enigma.NetworkProtocol.Commands.*;
public class EnigmaNameRequest {

	public String searchPublicKeyB64;
	public String signB64;
	public String serRandom;
	public byte[] searchPublicKeyEnc;
	public byte[] signBin;

	public EnigmaNameRequest(byte[] searchPubKey, String serverRandom, KeyPair kp)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		serRandom = serverRandom;
		searchPublicKeyEnc = searchPubKey;
		sign(kp.getPrivate());
	}

	public EnigmaNameRequest(EnigmaNetworkHeader enh, String serverRandom, PublicKey publicKey){
		serRandom = serverRandom;
		decodeStrings(enh);
		decodeBase64();
		Verify(publicKey);
	}

	//				Server Side
	private void decodeStrings(EnigmaNetworkHeader enh){
		try {
			searchPublicKeyB64 = enh.GetValue(PublicKeyKey);
			signB64 = enh.GetValue(SignatureKey);
		}catch (IllegalArgumentException e){
			throw new TuringConnectionException("BAD HEADER");
		}
	}
	private void decodeBase64(){
		try{
			searchPublicKeyEnc 		= Base64.getDecoder().decode(searchPublicKeyB64);
			signBin 				= Base64.getDecoder().decode(signB64);
		}catch (IllegalArgumentException e) {
			throw new TuringConnectionException("BAD HEADER");
		}

	}
	private void Verify(PublicKey publicKey) throws TuringConnectionException{
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

	//				Client Side
	public EnigmaNetworkHeader getHeader(){
		EnigmaNetworkHeader enh = new EnigmaNetworkHeader();

		enh.SetValue(PublicKeyKey	,searchPublicKeyB64);
		enh.SetValue(SignatureKey	,signB64);

		return enh;
	}
	private void sign(PrivateKey privateKey)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

		searchPublicKeyB64 = Base64.getEncoder().encodeToString(searchPublicKeyEnc);
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(privateKey);

		sgn.update(buildSignData());

		signBin = sgn.sign();
		signB64 = Base64.getEncoder().encodeToString(signBin);

	}
	//common
	private byte[] buildSignData(){
		return EnigmaBaseRequest.Sandwich(searchPublicKeyB64 , serRandom);
	}

}
