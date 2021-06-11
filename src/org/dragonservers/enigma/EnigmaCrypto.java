package org.dragonservers.enigma;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EnigmaCrypto {

    public static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
    public static byte[] SHA256(String data) throws NoSuchAlgorithmException{
        return SHA256(data.getBytes(StandardCharsets.UTF_8));
    }
    public static byte[] SHA256(char[] data) throws NoSuchAlgorithmException{
        byte[] bin = new byte[data.length];
        for (int i = 0; i < data.length; i++)
            bin[i] = (byte) data[i];
        //this Erases the bin data from memory
        bin = SHA256(bin);
        return bin;
    }
    @Deprecated
    public static byte[] AESEncrypt(byte[] data,byte[] key) throws GeneralSecurityException {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        byte[] salt = SHA256(key);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        // Create SecretKeyFactory object
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        String b64key = Base64.getEncoder().encodeToString(key);

        KeySpec spec = new PBEKeySpec(b64key.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
        byte[] encrypted = cipher.doFinal(data);
        ByteBuffer bb = ByteBuffer.allocate(encrypted.length + 16);
        bb.put(iv);
        bb.put(encrypted);
        return bb.array();
    }
    @Deprecated
    public static byte[] AESDecrypt(byte[] Encrypted,byte[] key) throws GeneralSecurityException {
        byte[] salt = SHA256(key);
        ByteBuffer bb = ByteBuffer.wrap(Encrypted);
        byte[] iv = new byte[16];
        bb.get(iv);
        byte[] data = new byte[bb.remaining()];
        bb.get(data);

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        String b64key = Base64.getEncoder().encodeToString(key);

        KeySpec spec = new PBEKeySpec(b64key.toCharArray(), salt,65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey,ivspec);
        // Return decrypted string
        return  cipher.doFinal(data);
    }
}
