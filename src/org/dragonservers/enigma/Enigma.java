package org.dragonservers.enigma;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Enigma {
    private static KeyPair Kpair = null;
    private static PublicKey TherePubKey = null;
    private static byte[] SharedSct = null;
    public static Scanner scn = new Scanner(System.in);

    public static void main(String[] args) {

            //EnigmaFile.EncryptFile(srcFiles,EnigmaCrypto.SHA256("PasswordEnigma"), "Hash.crypt");
            //EnigmaFile.DecryptFile(new File("Hash.crypt"),"output",EnigmaCrypto.SHA256("PasswordEnigma"));

        while(true) {
            System.out.println("Menu");
            System.out.println("E - Open or Generate new Key");
            System.out.println("D - Load There Pub Key");
            System.out.println("Q - Quit");
            String Response = scn.nextLine();
            switch (Response) {
                case "Q":
                case "q":
                    return;
                case "d":
                case "D":
                    Decrypt();
                    break;
                case "E":
                case "e":
                    Encrypted();
                    break;
            }
        }
    }

    private static void Encrypted()  {
        String FileName = "y";
        List<File> ToEncrypt = new ArrayList<>();
        while(FileName.toLowerCase().startsWith("y")){
            System.out.println("Enter File name to be encrypted:");
            FileName = scn.nextLine();
            File tmp = new File(FileName);
            ToEncrypt.add(tmp);
            System.out.println("Add Another File? (yes/no)");
            FileName = scn.nextLine();
        }
        String Password;
        Console con = System.console();
        while (true){
            System.out.println("Enter Password:-");
            char[] Pass = con.readPassword();

            Password = String.valueOf(Pass);
            System.out.println("Confirm Password:-");
            Pass = con.readPassword();
            String PasswordConfirm = String.valueOf(Pass);

            if(Password.equals(PasswordConfirm))break;

            System.out.println("Passwords do not match, Try again");
        }
        System.out.println("Enter File Name to save your Encrypted Package:-");
        String OutFileName = scn.nextLine() + ".crypt";
        byte[] hash;
        try {
            hash = EnigmaCrypto.SHA256(OutFileName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        try {
            EnigmaFile.EncryptFile((File[]) ToEncrypt.toArray(),hash,OutFileName);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


    }

    private static void Decrypt() {
        String DestFileName,CryptFileName,Password;

        System.out.println(" Destination Directory:-");
        DestFileName = scn.nextLine();
        System.out.println(" Package FileName:-");
        CryptFileName = scn.nextLine();
        System.out.println( "Password");
        char[] pass = System.console().readPassword();
        Password = String.valueOf(pass);

        try {
            EnigmaFile.DecryptFile(new File(CryptFileName),DestFileName,EnigmaCrypto.SHA256(Password));
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }



    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
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
