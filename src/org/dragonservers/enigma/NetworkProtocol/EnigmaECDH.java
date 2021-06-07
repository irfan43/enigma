package org.dragonservers.enigma.NetworkProtocol;

import org.dragonservers.enigma.EnigmaBlock;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class EnigmaECDH {

	public static byte[] makeSecret(KeyPair kp, PublicKey publicKey)
			throws GeneralSecurityException{
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(kp.getPrivate());
		keyAgreement.doPhase(publicKey,true);
		return keyAgreement.generateSecret();
	}
	public static PublicKey publicECDHKeyFromEncoded(byte[] encodedPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return keyFactory.generatePublic(
				new X509EncodedKeySpec(encodedPublicKey));
	}

	public static Cipher makeOutboundCipher(OutputStream os, SecretKeySpec secretKey)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		Cipher outboundCipher = Cipher.getInstance("AES/CBC/PKS5Padding");
		outboundCipher.init(Cipher.ENCRYPT_MODE,secretKey);
		EnigmaBlock.WriteBlock(os,
			outboundCipher
					.getParameters()
					.getEncoded()
		);
		return outboundCipher;
	}
	public static Cipher makeInboundCipher(InputStream is, SecretKeySpec secretKey)
			throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,InvalidAlgorithmParameterException, InvalidKeyException {
		Cipher inboundCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		inboundCipher.init(Cipher.DECRYPT_MODE,secretKey,getAlgoParam(is));
		return inboundCipher;
	}
	public static AlgorithmParameters getAlgoParam(InputStream is)
			throws NoSuchAlgorithmException, IOException {
		AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("AES");
		algorithmParameters.init(EnigmaBlock.ReadBlock(is));
		return algorithmParameters;
	}
}
