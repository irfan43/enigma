package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaCrypto;
import org.dragonservers.enigma.EnigmaKeyHandler;
import org.dragonservers.enigma.EnigmaTime;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Turing {
    public static final String Version = "1.00",KeyExchangeAlgo = "DH",ShadowCodeFile = "ShadowCodes/shadows.dat";

    public static final  String UserDataFolder  = "UserData",PublicKeyMap = "PublicKey.map",UsernameMap = "Usernames.map";

    public static Logger TuringLogger;
    public static boolean Logging = true,running = true,DoSaveOP = true;
    public static Thread TPortListener,TuringCLIHandler,TuringSHThread;
    public static NetworkListener TListener;
    public static CmdLineHandler CLI_Handler;
    public static EnigmaKeyHandler TuringKH;
    public static RegistrationCodeFactory CodeFac;
    public static TuringUserFactory EUserFac;
    public static TuringInbox EnigmaInboxs;
    public static SessionHandler sesHandler;
    public static TuringSaveHandler TuringSH;
    public static final int[] CurrentVersion = {1,0};

    /**
     * Public Files
     * -ECDH Curve, Move to Set of curves
     * TODO Adding periodic Save Thread
     *
     */
    public static void main(String[] Args)  {
        String Password = "";
        if(Args.length != 0){
            switch (Args[0].toUpperCase()){
                case "--MINE" -> {
                    PublicKeyExecuter.GenerateKeyPairBruteForce(Args);
                    System.exit(0);
                }
                case "-P" ->{
                    if(Args.length >= 2){
                        Password = Args[1];
                    }else {
                        System.out.println("No Password Given");
                        System.exit(0);
                    }
                }
                default -> {
                    System.out.println("Unknown Argument " + Args[0]);
                    System.exit(0);
                }
            }
        }

        //Start of Program
        TuringLogger = Logger.getLogger("Turing");
        try {
            TuringLogger.addHandler(new FileHandler("Turing.log", 32768,64,true));
        } catch (IOException e) {
            System.out.println("IO Exception while Opening Log File");
            e.printStackTrace();
        }

        //System.exit(0);
        System.out.println("Starting Turing, Enigma Server Version " + Version + " Using " + KeyExchangeAlgo);
        System.out.println("Current Time " + EnigmaTime.GetFormattedTime());
        try {

            //Read Server RSA KeyPair File

            if(Password.equals("")){
                System.out.println("Enter Password For Keypair:-");
                Password = getPassword(System.console());
            }else {
                System.out.println("Got Password From Command Line");
            }
            TuringKH = new EnigmaKeyHandler(new File("keys/TuringKeyPair.kpr"),Password,"Turing");
            System.out.println("Running with Public Key:-");
            String HexPubKeyEnc = Base64.getEncoder().encodeToString( TuringKH.GetPublicKey().getEncoded() );
            System.out.println(HexPubKeyEnc);
            System.out.println("SHA256:-");
            System.out.println(Base64.getEncoder().encodeToString(EnigmaCrypto.SHA256(TuringKH.GetPublicKey().getEncoded())));
            //loading the code factory and data handling objects
            TuringLogger.log(Level.FINE, "Loading Factories");
            CodeFac = new RegistrationCodeFactory();
            EUserFac = new TuringUserFactory();
            EnigmaInboxs = new TuringInbox();
            sesHandler = new SessionHandler();

            TuringSH = new TuringSaveHandler();
            TuringSHThread = new Thread(TuringSH);
            TuringSHThread.start();




            //CLI Handler
            CLI_Handler = new CmdLineHandler();
            TuringCLIHandler = new Thread(CLI_Handler);
            TuringCLIHandler.start();

            //Networking Portion
            TListener = new NetworkListener();
            TPortListener = new Thread(TListener);
            TPortListener.start();

        } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
    public static String getPassword(Console con){
        String Pass;
        if(con != null) {
            char[] ch = con.readPassword();
            Pass = String.valueOf(ch);
        }else{
            Pass = (new Scanner(System.in)).nextLine();
        }
        return Pass;
    }
    //does all IO actions to prevent Race conditions
    public static void Quit(){
        System.out.println("Shutting down");
        try {
            Turing.TListener.serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        synchronized (Turing.TListener.lock) {
            Turing.TListener.shutdown = false;
        }

        Turing.running = false;
        Turing.Logging = false;
        System.out.println("Waiting for Save Handler");
        while (TuringSHThread.isAlive()){
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Closed  Save Handler");
        System.out.println("Waiting for Network Listener");
        while (TPortListener.isAlive()){
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Closed  Network Listener");
        System.out.println("Goodbye");
        TuringLogger.log(Level.INFO,"Turing Closing");
        System.exit(0);
    }
}
