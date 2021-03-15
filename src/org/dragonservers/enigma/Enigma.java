package org.dragonservers.enigma;

import java.io.*;
import java.security.*;
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
            System.out.println("E - Encrypt File");
            System.out.println("D - Decrypt File");
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

        //asks for password
        String Password;
        Console con = System.console();
        while (true){
            System.out.println("Enter Password:-");
            Password = getPassword(System.console());
            System.out.println("Confirm Password:-");
            if(Password.equals(getPassword(System.console())))break;
            System.out.println("Passwords do not match, Try again");
        }

        System.out.println("Enter File Name to save your Encrypted Package:-");
        String OutFileName = scn.nextLine() + ".crypt";
        byte[] hash;
        try {
            hash = EnigmaCrypto.SHA256(Password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        File[] Set = new File[ToEncrypt.size()];
        for (int i = 0; i < ToEncrypt.size(); i++) {
            Set[i] = ToEncrypt.get(i);
        }
        System.out.println("Encryption Running with \n Key  = " + toHexString(hash));
        try {
            EnigmaFile.EncryptFile( Set,hash,OutFileName);
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
        //char[] pass = System.console().readPassword();
        Password = getPassword(System.console());
        try {
            byte[] hash = EnigmaCrypto.SHA256(Password);
            System.out.println("Running Decryption...\n Key = " + toHexString(hash));
            EnigmaFile.DecryptFile(new File(CryptFileName),DestFileName,hash);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }
    public static String getPassword(Console con){
        String Pass;
        if(con != null) {
            char[] ch = System.console().readPassword();
            Pass = String.valueOf(ch);
        }else{
            Pass = scn.nextLine();
        }
        return Pass;
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
