package org.dragonservers.Aether;


import org.dragonservers.enigma.*;

import javax.crypto.KeyGenerator;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Aether {
    public static Scanner scn = new Scanner(System.in);

    // Interface Objects
    public          static EnigmaKeyHandler     OurKeyHandler;
    public          static TuringConnection     turingConnection;
    public          static PublicKey            ServerPublicKey;

    //State Variables
    public          static byte[]           EncryptionPassword;
    public          static byte[]          PrimaryHash;
    public          static byte[]           ServerHash;
    public          static boolean          Registered              = false;
    public          static boolean          KeypairGenerated        = false;
    public          static String           Username;
    //These Variables are configuration
    public final    static String           ConfigFileName          = "Enigma.conf";
    public final    static String           KeyPairFile             = "keys/Keypair.kpr";
    public final    static Path             ServerPublicKeyFile     = Path.of("keys/Server.pbk");
    public final    static int              ServerPort              = 21947;
    public final    static String           EnigmaVersion           = "Alpha1.2";
    public final    static String           ClientName              = "Aether";
    public          static String           ServerDomainName;
    public          static SecretKey        AESEncryptionKey;
    public          static boolean          New_Config_File         = false;
    //TODO handle a quick fresh install
    public static void main(String[] args) {

        System.out.println( ClientName + " " + EnigmaVersion + "\nMade By Indus, Kitten, Highground Master");
        //Start of Enigma
        /*
            TODO
            - add command line arguments for the server port
            - add upgradation/migration system
         */
        if(HandleArgs(args)){
            /*
              process for boot up
                   -load config
                        -get username
                        -ASK password login
                        -ASK password encryption

                   -get keypair
                   -get server public key
                   

             */
            LoadConfigData();
            GetLoginDetails();
            //TODO update this to run properly with the Engima FIle API
            //      currently Enigma FIle class is importing aether


            //We have a config File Password and KeyPair

            VerifyServerPublicKey();
            CheckRegistration();
            AetherCLI.MainMenu();
        }

    }

    //functions to help with handling command line arguments

    public static boolean HandleArgs(String[] args) {
        boolean runNormally = true;
        if(args.length != 0){
            //TODO handle any arguments that come up
            switch (args[0].toLowerCase()) {
                case "--encrypt", "--decrypt", "-e", "-d" -> {
                    AetherFileEncryptionCLI.Encrypt(args);
                    runNormally = false;
                }
                case "--raw-test" -> {
                    AetherCLIUtil.consoleRawInputTest();
                    runNormally = false;
                }
                case "--help", "-h" -> {
                    ArgumentHelp();
                    runNormally = false;
                }
                default -> {
                    System.out.println("Unknown Argument " + args[0]);
                    ArgumentHelp();
                    runNormally = false;
                }
            }
        }
        return runNormally;
    }
    public static void ArgumentHelp() {
        System.out.println(
                "\t==Help==\n" +
                        "-h --help              prints this help info\n" +
                        "-e --encrypt   [File]  Encrypt a certain file\n" +
                        "-d --decrypt   [File]  Decrypt a encrypted file\n"
        );
    }
    private static void GetLoginDetails() {
        System.out.print("Encryption");
        MakeSecret();
        CheckKeyPair();
    }

    private static void LoadConfigData() {
        //TODO change this to a get and set function with no return and catch
        ServerDomainName = GetServerIP();
        CheckConfigFile();

    }


    private static String GetServerIP(){
        String dnm = "";
        try{
            dnm = AetherFileHandler.ReadServerIP();
        }catch (FileNotFoundException e) {
            //TODO make this a separate function
            System.out.println("Could not Find Server IP File. \nEnter Server IP to save:- ");
            //TODO add option to use the default domain name
            dnm = scn.nextLine();
            try {
                AetherFileHandler.WriteServerIP(dnm);
            } catch (IOException ioException) {
                System.out.println("Ran into error while saving server ip");
                ioException.printStackTrace();
            }
        }catch (IOException e) {
            System.out.println("UNEXPECTED Error while Reading SERVER IP data file");
            e.printStackTrace();
            System.exit(-1);
        }

        return dnm;
    }

    private static void MakeSecret() {

        if(New_Config_File){
            EncryptionPassword = AetherCLIUtil.confirmPassword();
        }else {
            EncryptionPassword = AetherCLIUtil.singlePassword();
        }
        try{
            final KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(new SecureRandom(Aether.EncryptionPassword));
            //TODO add salt <- NOT JOKE DO NOT REMOVE
            AESEncryptionKey = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR WHILE MAKING SECRET KEY\nSHA256 ALGO not supported by this JVM");
            e.printStackTrace();
            System.exit(-1);
        }
    }
    private static void VerifyServerPublicKey(){
        try {
            turingConnection = new TuringConnection(ServerDomainName, ServerPort);
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("ERROR while Connecting to server");

            e.printStackTrace();
            System.exit(-1);
        }
        //TODO clean this garbage code for server public key
        if(Files.exists(ServerPublicKeyFile)) {
            try {
                PublicKey pbk = EnigmaFile.readSignedPublicKey(
                        ServerPublicKeyFile,OurKeyHandler.getPublic());
                if(pbk != null){
                    ServerPublicKey = pbk;
                    PrintDataHash( "Server Public Key", ServerPublicKey.getEncoded());
                }
                if(!Arrays.equals(ServerPublicKey.getEncoded(),turingConnection.serverRSAPublicKey.getEncoded())){
                    //TODO add stored and got public key hash and signatures
                    throw new IllegalArgumentException("BAD SERVER KEY, \n" +
                            "Connected Server is not having the Key stored, \nYou maybe in a man in the middle attack\n" +
                            "check your network and server public key again");
                }
            }catch (GeneralSecurityException | IOException e){
                System.out.println("Error while Reading Stored Server Public Key\n" + e.getMessage());
                e.printStackTrace();
                System.exit(0);
            }

        }else {
            System.out.println("No Server Public Key can be found ");
            GetServerPublicKey();
        }
    }
    private static void CheckRegistration(){

        if(!Registered) {
            RegisterUser();
        }
        else{
            System.out.print("Enter Login");
            PrimaryHash = AetherCLIUtil.singlePassword();
        }
        //TODO login turing and update register user function
    }
    public static void GetServerPublicKey(){
        System.out.println("Would you like to Get the Public key from the Server?(y/n)");
        String resp = scn.nextLine();
        if(!resp.toLowerCase().startsWith("y")) {
            System.out.println("Repair the Server Public Key\nQuiting...");
            System.exit(0);
        }
        PublicKey ServerPbk = null;
        try {
            ServerPbk = turingConnection.serverRSAPublicKey;
            byte[] hash = EnigmaCrypto.SHA256(ServerPbk.getEncoded());
            System.out.println("Got Key As :-");
            System.out.println(AetherCLIUtil.toHexString(ServerPbk.getEncoded()));
            System.out.println("SHA-256:-");
            System.out.println(Base64.getEncoder().encodeToString(hash));
            System.out.println("Would you like this Save This Key?(yes/no)");
            resp = scn.nextLine();
            if(!resp.toLowerCase().startsWith("y")) {
                System.out.println("Can not run Securely without Server Public Key");
                System.out.println("quiting...");
                System.exit(0);
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR ");
            e.printStackTrace();
        }
        ServerPublicKey = ServerPbk;
        try {
            EnigmaFile.saveSignedPublicKey(
                    ServerPublicKeyFile,ServerPublicKey,true,OurKeyHandler);
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("Error while saving Server Public Key");
            e.printStackTrace();
        }
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
            PrimaryHash = EnigmaUser.GeneratePrimaryHash(AetherCLIUtil.confirmPassword(),Username);
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
                System.out.println("Starting Registration ");
                byte[] ServerHash = EnigmaUser.GenerateServerHash(PrimaryHash);
                turingConnection.Register( ServerHash,rgCode);
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

        char[] pass = AetherCLIUtil.getPassword(System.console());
        try {
            hash = EnigmaCrypto.SHA256(pass);
        } catch (NoSuchAlgorithmException e) {
            //highly unlikely we reach here
            Arrays.fill(pass,'\0');
            System.out.println("ERROR SHA-256 not supported on this machine ");
            e.printStackTrace();
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
                    KeyPair kp = EnigmaFile.ReadKeyPair(kpFile.toPath(), EncryptionPassword,Username);
                    OurKeyHandler = new EnigmaKeyHandler(kp);
                    PrintDataHash("Public Key", kp.getPublic().getEncoded());
                    PrintDataHash("Private Key", kp.getPrivate().getEncoded());
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
        System.out.println(AetherCLIUtil.SoftWrap(
                Base64.getEncoder().encodeToString(data),80));
        System.out.println("SHA256:-");
        System.out.println(
                Base64.getEncoder().encodeToString(EnigmaCrypto.SHA256(data)));
    }

    private static void CLIGenKeyPair() throws NoSuchAlgorithmException {
        File kpFile = new File(KeyPairFile);
        System.out.println("Generating New KeyPair");
        KeyPair kp = null;
        try {
            kp = EnigmaKeyHandler.RSAGenerateKeypair();
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
        AetherCLIUtil.CLS();
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
            EnigmaFile.SaveKeyPair(kpFile.toPath(),kp,true, EncryptionPassword, Username);
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
                System.out.println("Loaded Configurations");
                return;
            }
        }
        //If we reach here there is either no config file or a bad config file
        System.out.println("Would you like to Start a Fresh Config File and Registration or exit? (NEW/exit) ");
        String resp = scn.nextLine();

        if(!resp.toLowerCase().startsWith("new")) {
            New_Config_File = true;
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
