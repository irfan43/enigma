package org.dragonservers.enigma;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Main {
    private static KeyPairGenerator KeyPGen;



    public static Scanner scn = new Scanner(System.in);

    public static void main(String[] args) {
        try {

            System.out.println("Creating A Key Pair");
            KeyPGen = KeyPairGenerator.getInstance("DH");
            KeyPGen.initialize(2048);
            KeyPair Kpair = KeyPGen.generateKeyPair();
            KeyAgreement KAgree = KeyAgreement.getInstance("DH");
            KAgree.init(Kpair.getPrivate());

            byte[] PubKeyEnc = Kpair.getPublic().getEncoded();
            System.out.println("Enter File Name to Save:-");
            SaveKey(PubKeyEnc,scn.nextLine() + ".pub");
            //System.out.println(toHexString(PubKeyEnc));

            System.out.println("Enter File Name for There Public Key:-");
            byte[] ThPubKeyEnc = readPubkey(scn.nextLine() + ".pub");

            KeyFactory KFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(ThPubKeyEnc);
            PublicKey ThPubKey = KFactory.generatePublic(x509KeySpec);
            KAgree.doPhase(ThPubKey,true);

            byte[] SharedScrt = KAgree.generateSecret();
            System.out.println("Enter Filename for Secret:-");
            SaveKey(SharedScrt, scn.nextLine() + ".sct");
            System.out.println("Shared Secret:-" + toHexString(SharedScrt));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static byte[] readPubkey(String FileName) {
        byte[] KeyEnc = null;
        try {
            KeyEnc = Files.readAllBytes(Paths.get(FileName));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return KeyEnc;
    }
    private static void SaveKey(byte[] pubKeyEnc, String Filename) {
        try {
            Files.write(Paths.get(Filename),pubKeyEnc);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
                if(i%30==29)buf.append("\n");
            }

        }
        return buf.toString();
    }
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
}
