package org.dragonservers.enigma;


public class EnigmaCrypto {

    public static byte[] Encrypt(byte[] data,byte[] key){
        byte[] dt = data.clone();
        for (int i = 0; i < dt.length; i++)
            dt[i] ^= key[i% key.length];
        return dt;
    }

    //Warning unbuffered

}
