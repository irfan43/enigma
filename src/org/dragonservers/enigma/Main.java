package org.dragonservers.enigma;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    private static KeyPair Kpair = null;
    private static PublicKey TherePubKey = null;

    public static Scanner scn = new Scanner(System.in);

    public static void main(String[] args) {
        while(true) {
            System.out.println("Menu");
            System.out.println("1 - Load or Generate new Key");
            System.out.println("2 - Load There Pub Key");
            System.out.println("3 - Create a Shared Secret");
            System.out.println("4 - Display Keys Generated");
            System.out.println("E - Exit");
            String Response = scn.nextLine();
            switch (Response) {
                case "1":
                    InitialiseKeys();
                    break;
                case "2":
                    InitialiseThem();
                    break;
                case "3":
                    GenerateSecret();
                    break;
                case "4":
                    DisplayKey();
                    break;
                case "E":
                case "e":
                    return;
            }
        }
        /*
        try {

            System.out.println("Creating A Key Pair");
            KeyPairGenerator KeyPGen = KeyPairGenerator.getInstance("DH");
            KeyPGen.initialize(2048);
            Kpair = KeyPGen.generateKeyPair();

            KeyAgreement KAgree = KeyAgreement.getInstance("DH");
            KAgree.init(Kpair.getPrivate());

            byte[] PubKeyEnc = Kpair.getPublic().getEncoded();
            System.out.println("Enter File Name to Save:-");
            SaveKey(PubKeyEnc,scn.nextLine() + ".pub");
            //System.out.println(toHexString(PubKeyEnc));

            System.out.println("Enter File Name for There Public Key:-");
            byte[] ThPubKeyEnc = readkey(scn.nextLine() + ".pub");

            KeyFactory KFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(ThPubKeyEnc);
            PublicKey ThPubKey = KFactory.generatePublic(x509KeySpec);
            KAgree.doPhase(ThPubKey,true);

            byte[] SharedScrt = KAgree.generateSecret();
            System.out.println("Enter Filename for Secret:-");
            SaveKey(SharedScrt, scn.nextLine() + ".sct");
            System.out.println("Shared Secret:-" + toHexString(SharedScrt));

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }*/
    }

    private static void DisplayKey() {
        if(Kpair != null){
            System.out.println("Our Public Key     :-\n" + toHexString(Kpair.getPublic().getEncoded()));
            System.out.println("Our Private Key    :-\n" + toHexString(Kpair.getPrivate().getEncoded()));
        }
        if(TherePubKey != null)
            System.out.println("There Public Key   :-\n" + toHexString(TherePubKey.getEncoded()));

    }

    private static void GenerateSecret() {
    }

    private static void InitialiseThem() {
    }

    private static void InitialiseKeys() {
        String resp;
        try {
            System.out.println("(G)enerate Keys or Load From (F)ile? (G/F) [any to return to main menu]");
            resp = scn.nextLine();
            if(resp.equalsIgnoreCase("f")){
                //load the Key pair from a file
                String FileName = scn.nextLine();
                Kpair = getKeyPair(FileName + ".kpr");
            }else if(resp.equalsIgnoreCase("g")) {
                //Generate new keys
                KeyPairGenerator KPgen = KeyPairGenerator.getInstance("DH");
                KPgen.initialize(2048);
                Kpair = KPgen.generateKeyPair();
                System.out.println("Enter File Name to save the KeyPair:-");
                SaveKeyPair(scn.nextLine() + ".kpr",Kpair);
            }
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void SaveKeyPair(String Filename,KeyPair kp) {
        byte[] Pubenc = kp.getPublic().getEncoded(), Prvenc = kp.getPrivate().getEncoded();
        byte[] FileBin = new byte[Pubenc.length + Prvenc.length + 8];

        ByteBuffer PubBB = ByteBuffer.allocate(4);
        PubBB.putInt(Pubenc.length);
        byte[] PubLenIntEnc = PubBB.array();

        ByteBuffer PrvBB = ByteBuffer.allocate(4);
        PrvBB.putInt(Prvenc.length);
        byte[] PrvLenIntEnc = PrvBB.array();

        System.arraycopy(PubLenIntEnc, 0,FileBin,0,4);
        System.arraycopy(Pubenc, 0, FileBin, 4,Pubenc.length);
        System.arraycopy(PrvLenIntEnc, 0,FileBin,Pubenc.length + 4,4);
        System.arraycopy(Prvenc,0, FileBin,Pubenc.length + 8,Prvenc.length);

        System.out.println(" Public Len = " + Pubenc.length + "private len = " + Prvenc.length );
        SaveKey(FileBin,Filename);

    }

    private static KeyPair getKeyPair(String FileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPair kp;
        byte[] PublicKeyEnc,PrivateKeyEnc;
        byte[] FileBin = readkey(FileName);
        int PubLen,PrvLen;

        byte[] PubLenEnc = Arrays.copyOfRange(FileBin,0,4);
        ByteBuffer PubBB = ByteBuffer.wrap(PubLenEnc);
        PubLen = PubBB.getInt();
        PublicKeyEnc = Arrays.copyOfRange(FileBin,4,PubLen + 4);

        byte[] PrvLenEnc = Arrays.copyOfRange(FileBin,PubLen + 4,PubLen + 8);
        ByteBuffer PrvBB = ByteBuffer.wrap(PrvLenEnc);
        PrvLen = PrvBB.getInt();
        PrivateKeyEnc = Arrays.copyOfRange(FileBin, PubLen + 8,PubLen + 8 + PrvLen);

        KeyFactory PubKF = KeyFactory.getInstance("DH");
        PublicKey pubk = PubKF.generatePublic(new X509EncodedKeySpec(PublicKeyEnc));

        KeyFactory PrvKF = KeyFactory.getInstance("DH");
        PrivateKey prvk = PrvKF.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyEnc));

        kp = new KeyPair(pubk,prvk);
        return kp;
    }

    private static byte[] readkey(String FileName) {
        byte[] KeyEnc = null;
        try {
            KeyEnc = Files.readAllBytes(Paths.get(FileName));
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
