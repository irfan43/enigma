package org.dragonservers.enigma;


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
}
