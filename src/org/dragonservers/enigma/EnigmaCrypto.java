package org.dragonservers.enigma;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EnigmaCrypto {

    //Warning unbuffered
    public static byte[] Encrypt(byte[] data,byte[] key){
        return Encrypt(data,key,0);
    }

    public static byte[] Encrypt(byte[] data,byte[] key,int pos){
        byte[] Encrypted = data.clone();
        for (int i = 0; i < Encrypted.length; i++)
            Encrypted[i] ^= key[(pos + i) % key.length];
        return Encrypted;
    }
    public static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
    public static byte[] SHA256(String data) throws NoSuchAlgorithmException{
        return SHA256(data.getBytes(StandardCharsets.UTF_8));
    }
}
