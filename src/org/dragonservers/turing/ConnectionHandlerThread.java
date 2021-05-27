package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaCrypto;
import org.dragonservers.enigma.EnigmaNetworkHeader;
import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.EnigmaTime;

import javax.crypto.KeyAgreement;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;

public class ConnectionHandlerThread implements Runnable{

    //This Thread handles every user that connects to it
    private final Socket sock;
    public ConnectionHandlerThread(Socket s){
        sock = s;
    }

    public final static String GetServerPublicKeyCommand = "GET PBK";
    public final static String BadCommandResponse = "BAD CMD";
    public final static String FollowingEncrypted = "ENC";

    public final static String RegistrationCommand = "RGS";
    public final static String LoginCommand = "LOGIN"; //Equivalent to login
    public final static String GetInboxAvailCommand = "GET INBOX";
    public final static String GetPacketCommand = "GET PACKET";
    public final static String SendPacketCommand = "SEND PACKET";
    public final static String LogoutCommand = "LOGOUT";
    public final static String GetHistoryCommand = "GET HISTORY";
    public final static String GetUserPublicKeyCommand = "GET USER_PUBLIC_KEY";
    public final static String GetUsernameCommand = "GET USERNAME";

    private byte[] SharedSecret;

    //TODO globalise ENH keys

    @Override
    public void run() {
        String IP = sock.getInetAddress().toString();
        DataOutputStream dos;
        DataInputStream dis;
        //System.out.println("New Connection " + IP);
        try {
            dis = new DataInputStream(sock.getInputStream());
            dos = new DataOutputStream(sock.getOutputStream());

            //This contains the enigma \ 1.00
            //System.out.println("Reading VersionCode");
            String versionInformation = ReadBlockLine(dis);
            boolean valid = true;
            try{
                String version = GetVersion(versionInformation);
                int miner = Integer.parseInt(version.substring(1 + version.indexOf(".")));
                int major = Integer.parseInt(version.substring(0,version.indexOf(".")));
                if(major != Turing.CurrentVersion[0] || miner != Turing.CurrentVersion[1]){
                    WriteBlockLine("BAD UNSUPPORTED VERSION",dos);
                    valid = false;
                }
            }catch (IndexOutOfBoundsException e){
                WriteBlockLine("BAD Request Header",dos);
                valid = false;
            }



            if(valid) {
                WriteBlockLine("OK", dos);
                //System.out.println("Version ok " + versionInformation);
                //System.out.println("Reading Cmd ");
                String cmd = ReadBlockLine(dis);

                switch (cmd) {
                    case GetServerPublicKeyCommand -> HandleSendPublicKey(dos);
                    case FollowingEncrypted -> HandleEncryptedCommand(dos, dis);
                    default -> SendBadCommand(dos);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            //TODO log bad connection
        }finally {
            //close the Connection
           // System.out.println("Connection Closed");
            try {
                sock.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


    }

    private void SendBadCommand(DataOutputStream dos) throws IOException {
        WriteBlockLine( BadCommandResponse,dos);
    }
    private void HandleEncryptedCommand(DataOutputStream dos,DataInputStream dis) throws GeneralSecurityException, IOException {
        WriteBlockLine("OK KEYX ECDH_secp256r1_SHA256withRSA",dos);

        try {
            HandleECDHExchange(dis,dos);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return;
        } catch (InvalidKeySpecException e) {
            WriteBlockLine("BAD KEYX",dos);
            return;
        } catch (SignatureException e) {
            WriteBlockLine("BAD KEYX SERVER_SIGN_ERROR",dos);
            return;
        }


        WriteBlockLine("GOOD KEYX",dos);

        String cmd = ReadEncryptedBlockLine(dis);
        switch (cmd){
            case RegistrationCommand ->
                HandleRegistration(dos,dis);
            case LoginCommand  ->
                HandleGetSessionID(dos,dis);
            case GetInboxAvailCommand ->
                HandleGetInboxAvailCommand(dos, dis);
            case GetPacketCommand ->
                HandleGetPacketCommand(dos, dis);
            case SendPacketCommand ->
                HandleSendPacketCommand(dos, dis);
            case LogoutCommand ->
                HandleLogoutSessionIDCommand(dos, dis);
            case GetHistoryCommand ->
                HandleGetHistoryCommand(dos,dis);
            case GetUserPublicKeyCommand ->
                HandleGetUserPublicKeyCommand(dos,dis);
            case GetUsernameCommand ->
                HandleGetUsernameCommand(dos,dis);
            default -> SendBadCommand(dos);
        }

    }


    //TODO send a random number during key exchange encrypted
    //  they can send this number back to veryify the encryption
    //  later in registration and other process the can send the number and sign with the number
    //  this prevents replay attacks
    //this creates the Shared Secret
    private void HandleECDHExchange(DataInputStream dis, DataOutputStream dos)
            throws IOException, GeneralSecurityException {
        //TODO have some interface to send available curves for client to select
        byte[] ThereEncodedPub = ReadBlock(dis);

        KeyPairGenerator kpg =KeyPairGenerator.getInstance("EC");

        //we are using this curve , however later we should move to a better curve
        //testing shows it works in java 15 so don't touch it
        //IF YOU CHANGE THIS CHECK WITH ALL VERSION OF JAVA BEFORE PUSHING
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        //write Server public key
        byte[] ourPbkEnc = kp.getPublic().getEncoded();
        WriteBlock(dos,ourPbkEnc);
        //write Server public key Signature
        Signature sgn = Signature.getInstance("SHA256withRSA");
        sgn.initSign(Turing.TuringKH.GetPrivateKey());
        sgn.update(ourPbkEnc);
        WriteBlock(dos,sgn.sign());

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey ThereKey = kf.generatePublic(new X509EncodedKeySpec(ThereEncodedPub));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(ThereKey,true);
        SharedSecret = ka.generateSecret();
    }

    //command specific functions
    private void HandleRegistration(DataOutputStream dos, DataInputStream dis)
            throws IOException, GeneralSecurityException {
       //System.out.println("Requested Registration ");

        //reads the header from the request
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);
        String regCode;
        String username;
        String PassHashHex;
        String PublicKeyHex;
        try {
            regCode = enh.GetValue("registration-code");
            username = enh.GetValue("username");
            PassHashHex = enh.GetValue("password");
            PublicKeyHex = enh.GetValue("public-key");
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER",dos);
            //System.out.println("Bad Header Was received");
            return;
        }

        byte[] pbkEnc;
        try {
            pbkEnc = Base64.getDecoder().decode(PublicKeyHex);
        }catch (IllegalArgumentException  e){
            WriteEncryptedBlockLine("BAD PUBLIC_KEY INVALID_FORMAT",dos);
            return;
        }
        byte[] passHash;
        try {
            passHash = Base64.getDecoder().decode(PassHashHex);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD PASSWORD INVALID_FORMAT",dos);
            return;
        }
        //to prevent a TOCTOU bug we redeem the code well before we know if if the other
        // points are valid, we will mark it unused once we are sure

        if(!Turing.CodeFac.Redeem(regCode)){
            //System.out.println("GOT BAD CODE " + regCode);
            WriteEncryptedBlockLine("BAD CODE INVALID_OR_EXPIRED",dos);
            return;
        }
        int respCode;
        try {
            respCode = Turing.EUserFac.RegisterUser(username, pbkEnc, passHash);
        }catch (IOException e){
            respCode = -5;
        }

        //TODO add a sign check
        //  have them sign (Username+PasswordHash+UTCtime) <- to prove they own the private key
        //TODO if there is a exception in between redeem code to here
        // the code will not be renewed
        // in the try for registration add catch to last block of a exception e and a finaly block
        // mark code face unused there

        if(respCode != 0){
            Turing.CodeFac.MarkUnused(regCode);
        }
        switch (respCode){
            case 0 -> {
                WriteEncryptedBlockLine("GOOD REG", dos);
                Turing.TuringLogger.log(Level.INFO,"New Registrations from " + sock.getInetAddress() + regCode + ":" + username);
            }
            case -1 ->
                WriteEncryptedBlockLine("BAD USERNAME INVALID_NAME",dos);
            case -2 ->
                WriteEncryptedBlockLine("BAD USERNAME NAME_ALREADY_EXIST",dos);
            case -3 ->
                WriteEncryptedBlockLine("BAD PUBLIC_KEY KEY_ALREADY_EXIST",dos);
            case -4 ->
                WriteEncryptedBlockLine("BAD PUBLIC_KEY INVALID_KEY_SPEC",dos);
            case -5 ->
                WriteEncryptedBlockLine("BAD SERVER IO_ERROR",dos);
            default ->
                WriteEncryptedBlockLine("BAD SERVER ERROR",dos);
        }
    }
    private void HandleGetHistoryCommand(DataOutputStream dos, DataInputStream dis) {
    }
    private void HandleLogoutSessionIDCommand(DataOutputStream dos, DataInputStream dis) {
    }
    private void HandleSendPacketCommand(DataOutputStream dos, DataInputStream dis)
            throws IOException, GeneralSecurityException {
        //TODO make this login process into a function
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);
        String publicKey;
        String sessionID;
        try{
            publicKey = enh.GetValue("PublicKey");
            sessionID = enh.GetValue("SessionID");
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER",dos);
            return;
        }
        byte[] enigmaPacketEncoded = ReadEncryptedBlock(dis);
        byte[] publicKeyEncoded;
        try {
            publicKeyEncoded = Base64.getDecoder().decode(publicKey);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER ILLEGAL_FORMAT",dos);
            return;
        }
        if(!Turing.sesHandler.VerifySessionID(sessionID, publicKeyEncoded)){
            WriteEncryptedBlockLine("BAD SESSION_ID",dos);
            return;
        }
        EnigmaPacket ep;
        try {
            ep = new EnigmaPacket(enigmaPacketEncoded);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD PACKET_FORMAT",dos);
            return;
        }
        if(!Arrays.equals(ep.getFromAddr().getEncoded(),publicKeyEncoded) ){
            WriteEncryptedBlockLine("BAD FROM_ADDR_FORGERY",dos);
            return;
        }
        if(!Turing.EUserFac.PublicKeyExist(ep.getToAddr().getEncoded())){
            WriteEncryptedBlockLine("BAD TO_ADDR_DNE",dos);
            return;
        }
        if(Turing.EnigmaInboxs.SendPacket(ep)){
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            WriteEncryptedBlockLine("GOOD " + Base64.getEncoder().encodeToString(md.digest(enigmaPacketEncoded)),dos);
        }else {
            WriteEncryptedBlockLine("BAD INBOX_FAILED",dos);
        }

    }
    private void HandleGetPacketCommand(DataOutputStream dos, DataInputStream dis)
            throws IOException, GeneralSecurityException{
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);
        String publicKey;
        String sessionID;
        try{
            publicKey = enh.GetValue("PublicKey");
            sessionID = enh.GetValue("SessionID");
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER",dos);
            return;
        }
        byte[] publicKeyEncoded;
        try {
            publicKeyEncoded = Base64.getDecoder().decode(publicKey);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER ILLEGAL_FORMAT",dos);
            return;
        }
        if(!Turing.sesHandler.VerifySessionID(sessionID, publicKeyEncoded)){
            WriteEncryptedBlockLine("BAD SESSION_ID",dos);
            return;
        }
        EnigmaPacket ep;
        try {
            ep = Turing.EnigmaInboxs.CheckInbox(publicKeyEncoded);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD INBOX DNE SERVER_ERROR CONTACT ADMIN",dos);
            Turing.TuringLogger.log(Level.SEVERE,"Inbox dne but Session id was verified for \n" +
                    "SessionID:" + sessionID + "\nPublic key:" + publicKey);
            return;
        }
        WriteEncryptedBlockLine("GOOD",dos);
        if(ep == null){
            WriteEncryptedBlockLine("EMPTY",dos);
        }else{
            WriteEncryptedBlockLine("BLOB:",dos);
            WriteEncryptedBlock(dos,ep.EncodedBinary);
        }
    }
    private void HandleGetInboxAvailCommand(DataOutputStream dos, DataInputStream dis) {
        //TODO this forth
    }
    private void HandleGetSessionID(DataOutputStream dos, DataInputStream dis)
            throws IOException, GeneralSecurityException {
       // System.out.println("Requested Session ID ");
        //Grabed Header
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);

        String publicKeyB64;
        String passwordHashB64;
        String headerUTC;
        byte[] pbkEnc;
        byte[] hash;

        //TODO add HeaderSign, also make the header UTC the random number generated during ECDH key X
        try{
            publicKeyB64 = enh.GetValue("PublicKey");
            passwordHashB64 = enh.GetValue("password");
            headerUTC = enh.GetValue("headerUTC");
        }catch (IllegalArgumentException e){
            //header Error
            WriteEncryptedBlockLine("BAD HEADER",dos);
            return;
        }
        try {
            pbkEnc = Base64.getDecoder().decode(publicKeyB64);
            hash = Base64.getDecoder().decode(passwordHashB64);

        }catch (IllegalArgumentException  e){
            //header Error
            WriteEncryptedBlockLine("BAD BASE_65 INVALID_FORMAT",dos);
            return;
        }

        long headerTime = Long.parseLong(headerUTC);
        long ourTime = EnigmaTime.GetUnixTime();
        long deltaTime = Math.abs( headerTime - ourTime);

        //TODO globalise this GraceTime
        if(deltaTime > 120){
            WriteEncryptedBlockLine("BAD CLOCK_SYNC \nSERVER_TIME:" + ourTime,dos);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(headerTime);
        if(Turing.EUserFac.VerifyPasswordHash(pbkEnc,hash, sb.toString())){
            //Good Password
            String sesID = Turing.sesHandler.GenerateSessionID(pbkEnc);
            WriteEncryptedBlockLine("GOOD",dos);

            EnigmaNetworkHeader returnHeader = new EnigmaNetworkHeader();
            returnHeader.SetValue("SessionID",sesID);
            //todo add expiry info
            WriteEncryptedBlockLine(returnHeader.GetHeader(false),dos);
        }else {
            WriteEncryptedBlockLine("BAD CREDENTIALS",dos);

        }

    }
    private void HandleGetUsernameCommand(DataOutputStream dos, DataInputStream dis)
            throws GeneralSecurityException, IOException {
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);
        String publicKey;
        String sessionID;
        String searchPbk;
        try{
            publicKey = enh.GetValue("PublicKey");
            sessionID = enh.GetValue("SessionID");
            searchPbk = enh.GetValue("Search-PublicKey");
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER",dos);
            return;
        }
        byte[] publicKeyEncoded;
        try {
            publicKeyEncoded = Base64.getDecoder().decode(publicKey);
            Base64.getDecoder().decode(searchPbk);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER ILLEGAL_FORMAT",dos);
            return;
        }
        if(!Turing.sesHandler.VerifySessionID(sessionID, publicKeyEncoded)){
            WriteEncryptedBlockLine("BAD SESSION_ID",dos);
            return;
        }
        WriteEncryptedBlockLine("GOOD",dos);
        String foundUser;
        try {
            foundUser = Turing.EUserFac.GetUsername(searchPbk);
            WriteEncryptedBlockLine("Found-Username:" + foundUser,dos);

        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("DOES_NOT_EXIST",dos);
        }
    }

    private void HandleGetUserPublicKeyCommand(DataOutputStream dos, DataInputStream dis) throws GeneralSecurityException, IOException {
        String Header = ReadEncryptedBlockLine(dis);
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader(Header);
        String publicKey;
        String sessionID;
        String searchUsername;
        try{
            publicKey = enh.GetValue("PublicKey");
            sessionID = enh.GetValue("SessionID");
            searchUsername = enh.GetValue("Search-Username");
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER",dos);
            return;
        }
        byte[] publicKeyEncoded;
        try {
            publicKeyEncoded = Base64.getDecoder().decode(publicKey);
        }catch (IllegalArgumentException e){
            WriteEncryptedBlockLine("BAD HEADER ILLEGAL_FORMAT",dos);
            return;
        }
        if(!Turing.sesHandler.VerifySessionID(sessionID, publicKeyEncoded)){
            WriteEncryptedBlockLine("BAD SESSION_ID",dos);
            return;
        }
        WriteEncryptedBlockLine("GOOD",dos);
        String found_publicKey = Turing.EUserFac.GetPublicKeyB64(searchUsername);
        if(found_publicKey != null){

            WriteEncryptedBlockLine("PublicKey:" + found_publicKey,dos);
        }else {
            WriteEncryptedBlockLine("DOES_NOT_EXIST",dos);
        }
    }
    private void HandleSendPublicKey(DataOutputStream dos) throws IOException {
        //System.out.println("Requested Public Key ");
        byte[] PublicKeyEnc = Turing.TuringKH.GetPublicKey().getEncoded();
        WriteBlockLine("GOOD",dos);
        WriteBlock(dos,PublicKeyEnc);
    }
//TODO improve this
    private String GetVersion(String header) {
        int SlPoint  = -1;
        for (int i = 0; i < header.length(); i++) {
            if(header.charAt(i) == '\\'){
                SlPoint = i;
                break;
            }
        }
        if(SlPoint == -1)
            throw new IllegalArgumentException("Bad Header");
        return header.substring(SlPoint + 1).strip();
    }
    /*
    * Block Handling Functions
    *
    * */

    //Read and Write a Line of text
    public static String ReadBlockLine(DataInputStream dis) throws IOException {
        byte[] data = ReadBlock(dis);
        return new String(data,StandardCharsets.UTF_8);
    }
    public static void WriteBlockLine(String data,DataOutputStream dos) throws IOException {
        byte[] dataEncoded = data.getBytes(StandardCharsets.UTF_8);
        WriteBlock(dos,dataEncoded);
    }
    //Read And Writing Blocks
    public static void WriteBlock(DataOutputStream dos,byte[] data) throws IOException{
        byte[] lengthEncoded = ByteBuffer.allocate(4).putInt(data.length).array();
        dos.write(lengthEncoded);
        dos.write(data);
    }
    public static byte[] ReadBlock(DataInputStream din) throws IOException {
        byte[] lengthEncoded = new byte[4];
        int resp = din.read(lengthEncoded);
        int length = ByteBuffer.wrap(lengthEncoded).getInt();
        if(resp == -1)
            throw new IOException("EOF file Reached Prematurely");
        if(length <= 0)
            throw new IOException("BAD Block Header");

        byte[] block = new byte[length];
        resp = din.read(block);
        if(resp == -1)
            throw new IOException("EOF file Reached Prematurely");
        return block;
    }
    //Handling Encrypted Blocks
    //Read and Write Lines
    public String ReadEncryptedBlockLine(DataInputStream dataInputStream) throws IOException, GeneralSecurityException {
        byte[] Block = ReadEncryptedBlock(dataInputStream);
        return new String(Block,StandardCharsets.UTF_8);
    }
    public void WriteEncryptedBlockLine(String Data,DataOutputStream dos) throws IOException, GeneralSecurityException {
        WriteEncryptedBlock(dos,Data.getBytes(StandardCharsets.UTF_8));
    }
    //Binary Blocks
    public void WriteEncryptedBlock(DataOutputStream dos, byte[] data) throws IOException, GeneralSecurityException {
        byte[] encrypted = EnigmaCrypto.AESEncrypt(data,SharedSecret);
        WriteBlock(dos,encrypted);
    }
    public byte[] ReadEncryptedBlock(DataInputStream dis) throws IOException, GeneralSecurityException{
        byte[] block = ReadBlock(dis);
        return EnigmaCrypto.AESDecrypt(block,SharedSecret);
    }
}
