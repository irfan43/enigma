package org.dragonservers.enigma;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Enigma {
    public static Scanner scn = new Scanner(System.in);
    public static EnigmaKeyHandler OurKeyHandler;
    public static byte[] UserPassword;

    public static String Username,ConfigFileName = "Enigma.conf",KeyPairFile = "keys/Keypair.kpr";
    public static boolean Registered = false,KeypairGenerated= false;

    public static void main(String[] args) {
        //Start of Enigma
        if(args.length != 0){
            //handle any arguments that come up
            System.out.println("Command Line Arguments Not Yet supported ");
        }

        CheckConfigFile();
        GetPasswordFromUser();
        CheckKeyPair();





    }

    private static void GetPasswordFromUser() {
        System.out.println("Enter Encryption Password:");
        char[] pass = EnigmaCLI.getPassword(System.console());
        try {
            UserPassword = EnigmaCrypto.SHA256(pass);
        } catch (NoSuchAlgorithmException e) {
            //highly unlikely we reach here
            e.printStackTrace();
        }
        Arrays.fill(pass,'\0');

    }

    private static void CheckKeyPair() {
        File kpFile = new File(KeyPairFile);
        boolean fileGood = true;
        if(KeypairGenerated){
            if(!kpFile.exists()){
                System.out.println("Can not find KeyPair file.");
                fileGood = false;
            }
            if(kpFile.isDirectory()){
                System.out.println("BAD KeyPair File is Directory");
                fileGood = false;
            }
            if(fileGood){
                try {
                    KeyPair kp = EnigmaFile.ReadKeyPair(kpFile,EnigmaCrypto.SHA256(UserPassword));
                    OurKeyHandler = new EnigmaKeyHandler(kp);

                } catch (IOException | InvalidKeySpecException e) {
                    System.out.println("Ran into a Error while decrypting KeyPair File");
                    e.printStackTrace();
                    System.exit(-1);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    System.exit(-1);
                }
                return;
            }
        }else {
            System.out.println("No KeyPair Has been Generated");
        }
        //Reached here means either no file or bad file or key pair not generated
        //TODO add option to use existing keypair
        System.out.println("Would You Like to generate a new Keypair?");
    }

    private static void CheckConfigFile() {
        switch (EnigmaFile.GrabConfig()){
            case "DNE":
                System.out.println("Config File Not Found");
                break;
            case "CF":
                System.out.println("Config File Corrupted");
                System.out.println("This could be cause by bad spelling or capitalization");
                break;
            case "IOE":
                System.out.println("System Experienced an IOException while Reading Config File");
                System.out.println("This could be cause by bad permissions on the File");
                break;
            case "DIR":
                System.out.println("BAD FILE config.conf is Directory");
                break;
            case "OK":
                return;
        }
        System.out.println("Would you like to Start a Fresh Config File and Registration or exit? (new/exit) ");
        String resp = scn.nextLine();

        if(!resp.toLowerCase().startsWith("new"))
            System.exit(-1);
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
