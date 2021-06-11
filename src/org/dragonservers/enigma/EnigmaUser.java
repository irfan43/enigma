package org.dragonservers.enigma;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class EnigmaUser implements Serializable {

    private String Username;
    public PublicKey PubKey;
    private byte[] serverPasswordHash;

    public EnigmaUser(String username, PublicKey pbk, byte[] serverHash){
        PubKey = pbk;
        serverPasswordHash = serverHash;
        Username = username;
    }


    public void setServerHash(byte[] hash) {
        serverPasswordHash = hash;
    }
    public void setServerFromPrimaryHash(byte[] hash) throws NoSuchAlgorithmException {
        serverPasswordHash = GenerateServerHash(hash);
    }
    public void setServerFromPrimaryHash(char[] pass) throws NoSuchAlgorithmException {
        serverPasswordHash = GenerateServerHash(pass,Username);
    }

    public boolean VerifyLoginHash(byte[] loginHash, String serverRandom) throws NoSuchAlgorithmException {
        return Arrays.equals(GenerateLoginHash(serverRandom),loginHash);
    }

    public byte[] GenerateLoginHash(String serverRandom) throws NoSuchAlgorithmException {
        return GenerateLoginHash(serverPasswordHash,serverRandom,Username);
    }

    public PublicKey getPublicKey(){
        return PubKey;
    }

    public String getUsername() {
        return Username;
    }

    public void setUsername(String username) {
        if(!IsValidUsername( username ))
            throw new IllegalArgumentException();
        Username = username;
    }

    public static byte[] GenerateLoginHash(byte[] serverHash,String serverRandom,String username)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(
                (
                        serverRandom + "_" + username +
                        Base64.getEncoder().encodeToString(serverHash) +
                        username + "_" + serverRandom
                ).getBytes(StandardCharsets.UTF_8)
        );
        return md.digest();
    }

    public static byte[] GenerateServerHash(char[] pass,String username) throws NoSuchAlgorithmException {
        return GenerateServerHash(GeneratePrimaryHash(pass,username));
    }
    public static byte[] GenerateServerHash(byte[] primaryHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update((
                "Turing_" +
                Base64.getEncoder().encodeToString(primaryHash) +
                "_Turing"
                ).getBytes(StandardCharsets.UTF_8)
        );
        return md.digest();
    }
    public static byte[] GeneratePrimaryHash(char[] pass,String username) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(("Enigma_Turing_" + username + "_").getBytes(StandardCharsets.UTF_8));

        byte[] bin = new byte[pass.length];
        for (int i = 0; i < bin.length; i++) {
            bin[i] = (byte) pass[i];
            pass[i] = '\0';
        }
        md.update(bin);

        Arrays.fill(bin,(byte)0);

        md.update(("_" + username + "_Turing_Enigma").getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }

    public static boolean IsValidUsername(String username){
        username = username.toUpperCase();
        String acceptableUsernameChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";
        for(int i = 0; i < username.length(); i++) {
            String TestChar = String.valueOf(username.charAt(i));
            if (!acceptableUsernameChars.contains(TestChar))
                return false;
        }
        return true;
    }
}
