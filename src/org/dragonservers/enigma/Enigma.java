package org.dragonservers.enigma;


import javax.crypto.KeyGenerator;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ConnectException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Enigma {
    public static Scanner scn = new Scanner(System.in);

    // Interface Objects
    public static EnigmaKeyHandler OurKeyHandler;
    public static EnigmaServerConnection TuringConnection;
    public static PublicKey ServerPublicKey;

    //State Variables
    public static byte[] EncryptionPassword,LoginPassword;
    public static boolean Registered = false,KeypairGenerated= false;
    public static String Username;
    //These Variables are configuration
    public final static String ConfigFileName = "Enigma.conf",KeyPairFile = "keys/Keypair.kpr",AlgoKey = "RSA";
    public final static String ServerPublicKeyFile = "keys/Server.pbk";
    public static String ServerDomainName;
    public final static int ServerPort = 21947;
    public final static String EnigmaVersion = "1.00";
    public static SecretKey AESEncryptionKey;
    //TODO handle a quick fresh install
    public static void main(String[] args) {

        System.out.println( "Enigma " + EnigmaVersion + "\nMade By Indus, Kitten,HM");
        //Start of Enigma

        if(args.length != 0){
            //TODO handle any arguments that come up
            System.out.println("Command Line Arguments Not Yet supported ");
        }
        ServerDomainName = GetServerIP();
        CheckConfigFile();

        System.out.println("Enter Encryption Password:-");
        EncryptionPassword = GetPasswordFromUser();
        MakeSecret();
        CheckKeyPair();
        //We have a config File Password and KeyPair
        TuringConnection = new EnigmaServerConnection(ServerDomainName, ServerPort);
        CheckRegistration();
        EnigmaCLI.MainMenu();


    }

    private static String GetServerIP(){
        String dnm = "";
        try {
            if (Files.exists(Path.of("Turing_server_ip.dat"))) {
                InputStreamReader fr = new
                        InputStreamReader(Files.newInputStream(Path.of("Turing_server_ip.dat")));
                BufferedReader br = new BufferedReader(fr);
               dnm=br.readLine();
               br.close();
            } else {
                System.out.println("No Server Ip Avail");
                System.out.println("Enter Server IP:-");
                dnm = scn.nextLine();

                OutputStreamWriter osw = new
                        OutputStreamWriter(Files.newOutputStream(Path.of("Turing_server_ip.dat")));
                BufferedWriter bw = new BufferedWriter(osw);
                bw.write(dnm);
                bw.newLine();
                bw.close();
            }
        }catch (IOException e){
            System.out.println("ERROR WHILE READING SERVER IP FILE");
            e.printStackTrace();

            System.exit(-1);
        }
        return dnm;
    }

    private static void MakeSecret() {
        try{
            final KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(new SecureRandom(Enigma.EncryptionPassword));
            //TODO add salt <- NOT JOKE DO NOT REMOVE
            AESEncryptionKey = kg.generateKey();


        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR WHILE MAKING KEY");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private static void CheckRegistration(){
        //TODO clean this garbage code for server public key
        File ServerPBKFile = new File(ServerPublicKeyFile);
        if(ServerPBKFile.exists()) {

            try {
                PublicKey pbk = EnigmaFile.readPublicKey( ServerPBKFile.toPath());
                if(pbk != null){
                    ServerPublicKey = pbk;
                    PrintDataHash( "Server Public Key", ServerPublicKey.getEncoded());
                }
            }catch (GeneralSecurityException | IOException e){
                System.out.println("Error while Reading Stored Server Public Key");
                System.exit(0);
            }
        }else {
            System.out.println("No Server Public Key can be found ");
            try {
                GetServerPublicKey();
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }
        if(!Registered)
            RegisterUser();
        else{
            System.out.println("Enter Login Password:-");
            LoginPassword = GetPasswordFromUser();
        }

    }
    public static void GetServerPublicKey() throws GeneralSecurityException, IOException {
        System.out.println("Would you like to Get the Public key from the Server?(y/n)");
        String resp = scn.nextLine();
        if(!resp.toLowerCase().startsWith("y")) {
            System.out.println("Repair the Server Public Key\nQuiting...");
            System.exit(0);
        }
        PublicKey ServerPbk = null;
        try {
            ServerPbk = TuringConnection.GetPublicKey();
            byte[] hash = EnigmaCrypto.SHA256(ServerPbk.getEncoded());
            System.out.println("Got Key As :-");
            System.out.println(EnigmaCLI.toHexString(ServerPbk.getEncoded()));
            System.out.println("SHA-256:-");
            System.out.println(Base64.getEncoder().encodeToString(hash));
            System.out.println("Would you like this Save This Key?(yes/no)");
            resp = scn.nextLine();
            if(!resp.toLowerCase().startsWith("y")) {
                System.out.println("Can not run Securely without Server Public Key");
                System.out.println("quiting...");
                System.exit(0);
            }
        } catch (ConnectException e){
            System.out.println("Server Refused to Connect");
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(0);
        }
        ServerPublicKey = ServerPbk;
        EnigmaFile.savePublicKey( Path.of(ServerPublicKeyFile),ServerPublicKey,true);
    }
    private static byte[] VerifyGetPassword() throws NoSuchAlgorithmException {
        char[] hash = new char[0];
        while (true){
            char[] Password2;
            System.out.println("Enter Password:-");
            hash = EnigmaCLI.getPassword(System.console());
            System.out.println("Confirm Password:-");
            Password2 = EnigmaCLI.getPassword(System.console());
            if(Arrays.equals(hash,Password2)){
                Arrays.fill(Password2,'\0');
                break;
            }
            System.out.println("Passwords do not match, Try again");
        }
        return EnigmaCrypto.SHA256(hash);
    }
    private static void RegisterUser() {
        System.out.println("You are yet to register \n" +
                "Would you like to start a Registration Request with the server?(yes/no)");
        String resp = scn.nextLine();
        if(!resp.toLowerCase().startsWith("y")){
            System.out.println("Please Start Again When Want to Register");
            System.out.println("Quitting...");
            System.exit(0);
        }
        System.out.println("\tLogin Password");
        try {
            LoginPassword = VerifyGetPassword();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        Registered = true;
        System.out.println("Enter Registration Code:-");
        String rgCode = scn.nextLine();
        boolean redo = true;
        while(redo) {
            redo = false;
            try {
                System.out.println("Starting Registration Exception");
                TuringConnection.RegisterUser(rgCode, OurKeyHandler, LoginPassword);
            } catch (IOException | GeneralSecurityException e) {
                System.out.println("Error while communicating with server");
                e.printStackTrace();
                redo = true;
            }
            if(redo){
                System.out.println("try again?(y/n)");
                redo = scn.nextLine().toLowerCase().contains("y");
            }else {
                System.out.println("Registered Successfully");
                Registered = true;
                EnigmaFile.PushConfig();
            }
        }
        if(!Registered){
            System.out.println("Exiting..");
        }
    }
    private static byte[] GetPasswordFromUser() {
        byte[] hash = new byte[0];

        char[] pass = EnigmaCLI.getPassword(System.console());
        try {
            hash = EnigmaCrypto.SHA256(pass);
        } catch (NoSuchAlgorithmException e) {
            //highly unlikely we reach here
            e.printStackTrace();
            Arrays.fill(pass,'\0');
            System.exit(-1);
        }finally {
            Arrays.fill(pass,'\0');
        }
        return hash;
    }
    private static void PrintDataHash(String name,byte[] data){
        System.out.println("Got " + name + " As:-");
        System.out.println("SHA256(" + name + "):- " +
                Base64.getEncoder().encodeToString(data).substring(0,32));
    }
    private static void CheckKeyPair() {
        //TODO migrate this to FILES api
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
                    KeyPair kp = EnigmaFile.ReadKeyPair(kpFile.toPath(), EncryptionPassword);
                    OurKeyHandler = new EnigmaKeyHandler(kp);
                    PrintDataHash("Public Key", OurKeyHandler.GetPublicKey().getEncoded());
                    PrintDataHash("Private Key", OurKeyHandler.GetPrivateKey().getEncoded());
                } catch (IOException | InvalidKeySpecException e) {
                    //TODO handle bad password
                    System.out.println("Ran into a Error while decrypting KeyPair File\n" +
                            "File maybe Corrupted or password or username maybe wrong \n" +
                            "Since the Key verification use the username this can be cause by wrong username \n" +
                            "Quiting..\n" +
                            "Error INFO:-");
                    e.printStackTrace();
                    System.exit(-1);
                } catch (GeneralSecurityException e) {
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
        System.out.println("Would You Like to generate/load a new Keypair? (y/n)");
        String resp = scn.nextLine();
        if(!resp.toLowerCase().startsWith("y")){
            System.out.println("Correct the KeyPair File then Run Again");
            System.out.println("Quiting...");
            System.exit(-1);
        }
        try{
            CLIGenKeyPair();
        }catch (NoSuchAlgorithmException e){
            System.out.println("Error While Trying to generate a Key pair");
            System.out.println("Quiting...\nError INFO:-");
            e.printStackTrace();
        }
    }
    private static void PrintBinDataWithSha(byte[] data) throws NoSuchAlgorithmException {
        System.out.println(SoftWrap(
                Base64.getEncoder().encodeToString(data),80));
        System.out.println("SHA256:-");
        System.out.println(
                Base64.getEncoder().encodeToString(EnigmaCrypto.SHA256(data)));
    }
    private static String SoftWrap(String input,int wall){
        StringBuilder sb = new StringBuilder();
        while (input.length() > wall) {
            sb.append(input, 0, wall);
            sb.append("\n");
            input = input.substring(wall);
        }
        sb.append(input);
        return sb.toString();
    }
    private static void CLIGenKeyPair() throws NoSuchAlgorithmException {
        File kpFile = new File(KeyPairFile);
        System.out.println("Generating New KeyPair");
        KeyPair kp = null;
        try {
            kp = EnigmaKeyHandler.GenerateKeypair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-2);
        }
        if(kp == null){
            System.out.println("Failed to Generate KeyPair due to unknown reason\nQuiting");
            System.exit(-1);
        }
        System.out.println("Got KeyPair:-");
        System.out.println("Public:-");
        PrintBinDataWithSha(kp.getPublic().getEncoded());
        System.out.println("Private:-");
        PrintBinDataWithSha(kp.getPrivate().getEncoded());
        System.out.println("Please save this else where \n" +
                "in the event the encryption password is forgotten or some other IO ERROR occurs\n" +
                "Save This Key? (yes/no)");

        String resp = scn.nextLine();
        EnigmaCLI.CLS();
        System.out.println("Screen Cleared to Hide Keys");
        if(!resp.toLowerCase().startsWith("y")){
            System.out.println("Can Not Run Without KeyPair");
            System.out.println("Either Generate a KeyPair or Correct the KeyPair File");
            System.out.println("Quiting...");
            System.exit(0);
        }
        try {
            if(kpFile.exists()){
                System.out.println("KeyPair File Already Exists, Would You Like To OverWrite it? (yes/no)");
                resp = scn.nextLine();
                if(!resp.toLowerCase().startsWith("y")){
                    System.out.println("Quiting...");
                    System.exit(0   );
                }
                System.out.print("Type \"overwrite\" to Confirm Overwriting the KeyPair File:-" +
                        "\nWARNING THIS WILL DELETE THE OLD KEYPAIR FILE THE KEYS WILL BE LOST ");
                resp = scn.nextLine();
                if(!resp.equalsIgnoreCase("overwrite")){
                    System.out.println("Not Equal to overwrite");
                    System.out.println("Quiting...");
                    System.exit(0);
                }
            }
            System.out.println("Saving KeyPair...");
            EnigmaFile.SaveKeyPair(kpFile.toPath(),kp,true, EncryptionPassword);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Ran into IO Error While Saving Key Pair");
            System.out.println("Quiting...");
            System.exit(-1);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            System.out.println("Ran into GeneralSecurity While Encrypting Key Pair");
            System.out.println("Quiting...");
            System.exit(-1);
        }

        OurKeyHandler = new EnigmaKeyHandler(kp);
        KeypairGenerated = true;
        SaveConfig();
    }
    private static void CheckConfigFile() {
        switch (EnigmaFile.GrabConfig()){
            case "DNE" -> System.out.println("Config File Not Found");

            case "CF" -> {
                System.out.println("Config File Corrupted");
                System.out.println("This could also be cause by bad spelling or capitalization");
            }
            case "IOE" -> {
                System.out.println("System Experienced an IOException while Reading Config File");
                System.out.println("This could be cause by bad permissions on the File");
            }
            case "DIR" -> System.out.println("BAD FILE config.conf is Directory");

            case "NRP" -> System.out.println("No Read Privilege Config File");

            case "OK" -> {
                System.out.println("Loaded Config");
                return;
            }
        }
        //If we reach here there is either no config file or a bad config file
        System.out.println("Would you like to Start a Fresh Config File and Registration or exit? (new/exit) ");
        String resp = scn.nextLine();

        if(!resp.toLowerCase().startsWith("new")) {
            System.out.println("Can Not Run Without Config\nPlease rectify the Config File or generate a new Config File\nQuiting...");
            System.exit(-1);
        }

        System.out.println("Enter a Username For the File:-");
        Username = scn.nextLine();
        SaveConfig();
    }
    private static void SaveConfig(){
        switch (EnigmaFile.PushConfig()) {
            case "DIR" -> {
                System.out.println("[ERROR] Config File is a Directory\nEither move the folder or delete it\nQuiting...");
                System.exit(-1);
            }
            case "NWP" -> {
                System.out.println("[ERROR] No Write Privilege for Config File\nChange Read Write Privilege for Config File\nQuiting...");
                System.exit(-1);
            }
            case "IOE" -> {
                System.out.println("[ERROR] Ran Into a IO Exception While Trying to save Config File\nQuiting...");
                System.exit(-1);
            }
            case "CNC" -> {
                System.out.println("[ERROR]Can not Create Config File \nChange Read Write Privilege and try again\nQuiting..");
                System.exit(-1);
            }
            case "OK" -> System.out.println("Config Saved");
        }
    }
}
