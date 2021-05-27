package org.dragonservers.enigma;



import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EnigmaKeyHandler {

    private final KeyPair keyPair;
    private final static String RSAAlgo = "RSA";
    public EnigmaKeyHandler(KeyPair KeyPair){
        keyPair = KeyPair;
    }
    public EnigmaKeyHandler(File KeyPairFile, String Password,String Verification)
            throws GeneralSecurityException, IOException {
        if(KeyPairFile.exists()){
            //read the file
            keyPair = EnigmaFile.ReadKeyPair(KeyPairFile.toPath(),EnigmaCrypto.SHA256(Password),Verification);
        }else{
            //generate a keypair and save it
            keyPair = GenerateKeypair();
            EnigmaFile.SaveKeyPair(KeyPairFile.toPath(),keyPair,false,
                    EnigmaCrypto.SHA256(Password),Verification);
        }
    }

    public PublicKey GetPublicKey(){
        return keyPair.getPublic();
    }
    public PrivateKey GetPrivateKey() {
        return keyPair.getPrivate();
    }

    //STATIC FUNCTIONS
    public static KeyPair GenerateKeypair() throws NoSuchAlgorithmException {
        KeyPairGenerator KGen = KeyPairGenerator.getInstance(RSAAlgo);
        KGen.initialize(512);
        return KGen.generateKeyPair();
    }
    public static PrivateKey PrivateKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PrvKF = KeyFactory.getInstance(RSAAlgo);
        return PrvKF.generatePrivate(new PKCS8EncodedKeySpec(Encoded));
    }
    public static PublicKey PublicKeyFromEnc(byte[] Encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory PubKF = KeyFactory.getInstance(RSAAlgo);
        return PubKF.generatePublic(new X509EncodedKeySpec(Encoded));
    }
    public static KeyPair KeyPairFromEnc(byte[] PublicKeyEncoded,byte[] PrivateKeyEncoded) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return new KeyPair( PublicKeyFromEnc(PublicKeyEncoded),PrivateKeyFromEnc(PrivateKeyEncoded) );
    }
}
