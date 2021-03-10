package org.dragonservers.enigma;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EnigmaKeyHandler {

    public static PrivateKey PrivateKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PrvKF = KeyFactory.getInstance("DH");
        return PrvKF.generatePrivate(new PKCS8EncodedKeySpec(Encoded));
    }

    public static PublicKey PublicKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PubKF = KeyFactory.getInstance("DH");
        return PubKF.generatePublic(new X509EncodedKeySpec(Encoded));
    }
}
