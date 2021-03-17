package org.dragonservers.enigma;

import javax.crypto.KeyAgreement;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EnigmaKeyHandler {

    private final KeyPair keyPair;
    public EnigmaKeyHandler(KeyPair KeyPair){
        keyPair = KeyPair;
    }
    public EnigmaKeyHandler(File KeyPairFile, String Password) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if(KeyPairFile.exists()){
            //read the file
            keyPair = EnigmaFile.ReadKeyPair(KeyPairFile,EnigmaCrypto.SHA256(Password));
        }else{
            //generate a keypair and save it
            keyPair = GenerateKeypair();
            EnigmaFile.SaveKeyPair(KeyPairFile,keyPair,false,EnigmaCrypto.SHA256(Password));
        }
    }

    public PublicKey GetPublicKey(){
        return keyPair.getPublic();
    }

    public byte[] GetCommonSecret(PublicKey therePublicKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(therePublicKey,true);
        return keyAgreement.generateSecret();
    }

    //STATIC FUNCTION
    public static KeyPair GenerateKeypair() throws NoSuchAlgorithmException {
        KeyPairGenerator KGen = KeyPairGenerator.getInstance("DH");
        KGen.initialize(2048);
        return KGen.generateKeyPair();
    }

    public static PrivateKey PrivateKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PrvKF = KeyFactory.getInstance("DH");
        return PrvKF.generatePrivate(new PKCS8EncodedKeySpec(Encoded));
    }

    public static PublicKey PublicKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PubKF = KeyFactory.getInstance("DH");
        return PubKF.generatePublic(new X509EncodedKeySpec(Encoded));
    }
    public static KeyPair KeyPairFromEnc(byte[] PublicKeyEncoded,byte[] PrivateKeyEncoded) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return new KeyPair( PublicKeyFromEnc(PublicKeyEncoded),PrivateKeyFromEnc(PrivateKeyEncoded) );
    }
}
