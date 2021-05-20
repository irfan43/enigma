package org.dragonservers.enigma;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class EnigmaUser implements Serializable {

    private String Username;
    public PublicKey PubKey;
    private byte[] PasswordHash;
    private final char[] HexTable = "0123456789ABCDEF".toCharArray();
    private final char separator = ' ';

    public EnigmaUser(String username, PublicKey pbk, byte[] passwordHash){
        PubKey = pbk;
        PasswordHash = passwordHash;
        Username = username;
    }

    public void setPasswordHash(byte[] passwordHash) {
        PasswordHash = passwordHash;
    }

    public boolean VerifyPassword(byte[] Hash, String HeaderUTC) throws NoSuchAlgorithmException {
        byte[] ourHash = HashPasswordVerification(PasswordHash,HeaderUTC);
        return Arrays.equals(ourHash,Hash);
    }
    public static byte[] HashPasswordVerification(byte[] Hash, String Header) throws NoSuchAlgorithmException {
        byte[] header = Header.getBytes(StandardCharsets.UTF_8);
        byte[] bin = new byte[header.length + Hash.length];

        System.arraycopy(header,0,bin,0,header.length);
        System.arraycopy(Hash,0,bin,header.length,Hash.length);
        return EnigmaCrypto.SHA256(bin);
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

    private byte[] BinFromHex(String Hex){
        if(Hex.length()%2 == 1)
            Hex = "0" + Hex;
        ByteBuffer bb = ByteBuffer.allocate(Hex.length()/2);
        for (int i = 0; i < Hex.length(); i+=2) {
            byte part = (byte) Integer.parseInt( Hex.substring(i,i+2), 16);
            bb.put(part);
        }

        return bb.array();
    }
    private String HexFromBin(byte[] bin){
        StringBuilder sb = new StringBuilder();
        for(byte part: bin)
            sb.append(String.format("%02X",part));
        return sb.toString();
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
