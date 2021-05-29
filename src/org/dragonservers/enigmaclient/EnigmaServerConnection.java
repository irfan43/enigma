package org.dragonservers.enigmaclient;

import org.dragonservers.enigma.*;

import javax.crypto.*;
import javax.security.auth.login.CredentialException;
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
import java.util.Base64;

public class EnigmaServerConnection {

    private final String ServerIP;
    private final int ServerPort;
    private EnigmaSession enigmaSession;

    public final static String GetPublicKeyCommand = "GET PBK";
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

    private final Object lockObject = new Object();

    public EnigmaServerConnection(String DomainName, int Port)  {
        ServerIP = DomainName;
        ServerPort = Port;
        enigmaSession = new EnigmaSession("",1);
    }
    public boolean SessionExpired(){
        boolean rtr;
        synchronized (lockObject){
            rtr = !enigmaSession.IsValid();
        }
        return rtr;
    }
    public PublicKey GetPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());

        //Request
        //Header
        SendVersion(dos,dis);
        //Command
        WriteBlockLine( "GET PBK" , dos);

        //Response code
        String ResponseCode = ReadBlockLine(dis);
        if(!ResponseCode.startsWith("GOOD")){
            throw new IOException("Bad Server Response:- \"" + ResponseCode + "\"");
        }
        byte[] publicKeyEnc = ReadBlock(dis);

        return EnigmaKeyHandler.PublicKeyFromEnc(publicKeyEnc);
    }
    public void LogIn() throws IOException, GeneralSecurityException {
        synchronized (lockObject) {
            if(!enigmaSession.IsValid()) {
                EnigmaNetworkHeader enh = new EnigmaNetworkHeader();
                enh.SetValue("PublicKey", Base64
                        .getEncoder()
                        .encodeToString(EnigmaClient.OurKeyHandler.GetPublicKey().getEncoded()));

                String headerUTC = "" + EnigmaTime.GetUnixTime();
                enh.SetValue("password", Base64.getEncoder().encodeToString(
                        EnigmaUser.HashPasswordVerification(EnigmaClient.LoginPassword, headerUTC)));
                enh.SetValue("headerUTC", headerUTC);
                String header = enh.GetHeader(true);
                Socket sock = new Socket(ServerIP, ServerPort);
                DataInputStream dis = new DataInputStream(sock.getInputStream());
                DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
                SendVersion(dos, dis);
                WriteBlockLine(FollowingEncrypted, dos);
                byte[] sharedSecret = ECDHHandshake(dos, dis);
                String keyXSuccessCode = ReadBlockLine(dis);
                if (keyXSuccessCode.contains("BAD"))
                    throw new GeneralSecurityException("Key Exchange Failed");
                WriteEncryptedLine(dos, LoginCommand, sharedSecret);
                WriteEncryptedLine(dos, header, sharedSecret);

                String resp = ReadEncryptedLine(dis, sharedSecret);
                if (resp.contains("BAD"))
                    throw new IOException("Ran Into Error Server Message:-" + resp);
                EnigmaNetworkHeader responseHeader = new EnigmaNetworkHeader(ReadEncryptedLine(dis, sharedSecret));

                String sesID = responseHeader.GetValue("SessionID");
                enigmaSession = new EnigmaSession(sesID, EnigmaTime.GetUnixTime() +  3600 - 50);
            }
        }
    }

    public String GetUsername(PublicKey publicKey) throws GeneralSecurityException, IOException {
        if(SessionExpired())
            LogIn();

        EnigmaNetworkHeader enh = new EnigmaNetworkHeader();

        enh.SetValue("SessionID", enigmaSession.SessionID );
        enh.SetValue("PublicKey", Base64.getEncoder()
                .encodeToString(EnigmaClient.OurKeyHandler.GetPublicKey().getEncoded()) );
        enh.SetValue("Search-PublicKey",Base64
                .getEncoder().encodeToString(publicKey.getEncoded()));
        String header = enh.GetHeader(true);

        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        SendVersion(dos,dis);

        WriteBlockLine( FollowingEncrypted , dos);
        byte[] sharedSecret = ECDHHandshake(dos,dis);
        String keyXSuccessCode = ReadBlockLine(dis);
        if(keyXSuccessCode.contains("BAD"))
            throw new GeneralSecurityException("Key Exchange Failed");

        //TODO figure out someway of verifying the whole thing went well
        //  maybe send the servers utc time
        WriteEncryptedLine(dos, GetUsernameCommand,sharedSecret);
        WriteEncryptedLine(dos, header, sharedSecret);
        String resp = ReadEncryptedLine(dis,sharedSecret);
        if(!resp.contains("GOOD"))
            throw new IOException("Bad Server Response GetPubkey " + resp);
        String foundUsername = null;
        resp = ReadEncryptedLine(dis,sharedSecret);
        if(resp.contains("Found")) {
            EnigmaNetworkHeader responseHeader = new EnigmaNetworkHeader(resp);
            foundUsername = responseHeader.GetValue("Found-Username");
        }
        return foundUsername;
    }
    public PublicKey GetUserPublicKey(String username) throws GeneralSecurityException, IOException {
        if(SessionExpired()){
            LogIn();
        }

        EnigmaNetworkHeader enh = new EnigmaNetworkHeader();


        enh.SetValue("SessionID", enigmaSession.SessionID );
        enh.SetValue("PublicKey", Base64.getEncoder()
                .encodeToString(EnigmaClient.OurKeyHandler.GetPublicKey().getEncoded()) );
        enh.SetValue("Search-Username",username);
        String header = enh.GetHeader(true);

        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        SendVersion(dos,dis);

        WriteBlockLine( FollowingEncrypted , dos);
        byte[] sharedSecret = ECDHHandshake(dos,dis);
        String keyXSuccessCode = ReadBlockLine(dis);
        if(keyXSuccessCode.contains("BAD"))
            throw new GeneralSecurityException("Key Exchange Failed");

        //TODO figure out someway of verifying the whole thing went well
        //  maybe send the servers utc time
        WriteEncryptedLine(dos, GetUserPublicKeyCommand,sharedSecret);
        WriteEncryptedLine(dos, header, sharedSecret);
        String resp = ReadEncryptedLine(dis,sharedSecret);
        if(!resp.contains("GOOD"))
            throw new IOException("Bad Server Response for GetPublicKey " + resp);
        resp = ReadEncryptedLine(dis,sharedSecret);
        PublicKey pbk = null;
        if(!resp.contains("DOES_NOT_EXIST")){
            EnigmaNetworkHeader responseHeader = new EnigmaNetworkHeader(resp);
            pbk = EnigmaKeyHandler.PublicKeyFromEnc(Base64
                    .getDecoder().decode(responseHeader.GetValue("PublicKey")));
        }
        return pbk;
    }
    public EnigmaPacket GetPacket() throws IOException, GeneralSecurityException {
        if(SessionExpired()){
            LogIn();
        }
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader();


        enh.SetValue("SessionID", enigmaSession.SessionID );
        enh.SetValue("PublicKey", Base64.getEncoder()
                .encodeToString(EnigmaClient.OurKeyHandler.GetPublicKey().getEncoded()) );
        String header = enh.GetHeader(true);

        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        SendVersion(dos,dis);

        WriteBlockLine( FollowingEncrypted , dos);
        byte[] sharedSecret = ECDHHandshake(dos,dis);
        String keyXSuccessCode = ReadBlockLine(dis);
        if(keyXSuccessCode.contains("BAD"))
            throw new GeneralSecurityException("Key Exchange Failed");

        //TODO figure out someway of verifying the whole thing went well
        //  maybe send the servers utc time
        WriteEncryptedLine(dos, GetPacketCommand,sharedSecret);
        WriteEncryptedLine(dos, header, sharedSecret);
        String resp = ReadEncryptedLine(dis,sharedSecret);
        EnigmaPacket ep = null;
        if(resp.contains("GOOD")){
            resp = ReadEncryptedLine(dis,sharedSecret);
            if(resp.contains("BLOB:")){
                ep = new EnigmaPacket(ReadEncryptedBlock(dis,sharedSecret));
            }
        }else {
            System.out.println("Failed to get Inbox");
            throw new IOException("");
        }
        return ep;
    }
    public void SendPacket(EnigmaPacket ep) throws IOException, GeneralSecurityException {
        if(SessionExpired()){
            LogIn();
        }
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader();


        enh.SetValue("SessionID", enigmaSession.SessionID );
        enh.SetValue("PublicKey", Base64.getEncoder()
                .encodeToString(EnigmaClient.OurKeyHandler.GetPublicKey().getEncoded()) );
        String header = enh.GetHeader(true);

        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        SendVersion(dos,dis);

        WriteBlockLine( FollowingEncrypted , dos);
        byte[] sharedSecret = ECDHHandshake(dos,dis);
        String keyXSuccessCode = ReadBlockLine(dis);
        if(keyXSuccessCode.contains("BAD"))
            throw new GeneralSecurityException("Key Exchange Failed");

        //TODO figure out someway of verifying the whole thing went well
        //  maybe send the servers utc time
        WriteEncryptedLine(dos, SendPacketCommand,sharedSecret);
        WriteEncryptedLine(dos, header, sharedSecret);
        WriteEncryptedBlock(dos,ep.GetBinary(EnigmaClient.OurKeyHandler.GetPrivateKey()),sharedSecret);
        String resp = ReadEncryptedLine(dis,sharedSecret);
        if(!resp.contains("GOOD"))
            System.out.println("Failed to Send Packet :- " + resp);
    }
    public void RegisterUser(String registrationCode, EnigmaKeyHandler enigmaKeyHandler,byte[] passwordHash)
            throws IOException, GeneralSecurityException {
        EnigmaNetworkHeader enh = new EnigmaNetworkHeader();
        enh.SetValue("registration-code",registrationCode);
        enh.SetValue("username", EnigmaClient.Username);
        enh.SetValue("password",  Base64.getEncoder().encodeToString(passwordHash) );
        enh.SetValue("public-key", Base64.getEncoder().encodeToString(enigmaKeyHandler.GetPublicKey().getEncoded()) );
        String header = enh.GetHeader(true);
        Socket sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
        SendVersion(dos,dis);

        WriteBlockLine( FollowingEncrypted , dos);
        byte[] sharedSecret = ECDHHandshake(dos,dis);
        String keyXSuccessCode = ReadBlockLine(dis);
        if(keyXSuccessCode.contains("BAD"))
            throw new GeneralSecurityException("Key Exchange Failed");




        //TODO figure out someway of verifying the whole thing went well
        //  maybe send the servers utc time
        WriteEncryptedLine(dos, RegistrationCommand,sharedSecret);
        WriteEncryptedLine(dos, header, sharedSecret);
        String respMsg = ReadEncryptedLine(dis,sharedSecret);
        sock.close();
        if(!respMsg.contains("GOOD")){
            throw new IOException("Registration Failed, Server Message:-" + respMsg);
        }
        System.out.println("Registered");
    }
    private void SendVersion(DataOutputStream dos,DataInputStream dis) throws IOException {
        WriteBlockLine( "enigma \\ " + EnigmaClient.EnigmaVersion , dos);
        String resp = ReadBlockLine(dis);
        if(resp.contains("BAD"))
            throw new IOException("Got Bad Response from server, Message:-"  +ReadBlockLine(dis));
    }
    private byte[] ECDHHandshake(DataOutputStream dos,DataInputStream dis) throws GeneralSecurityException, IOException {
        String AlgoInfo = ReadBlockLine(dis);
        //lets generate the Key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        //we are using this curve , however later we should move to a better curve
        //testing shows it works in java 15 so don't touch it
        //IF YOU CHANGE THIS CHECK WITH ALL VERSION OF JAVA BEFORE PUSHING
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        WriteBlock(dos, kp.getPublic().getEncoded());

        byte[] serverDHPubKey = ReadBlock(dis);
        byte[] pbkSgn = ReadBlock(dis);

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey serverPdk = kf.generatePublic(new X509EncodedKeySpec(serverDHPubKey));

        Signature sgn = Signature.getInstance("SHA256withRSA");
        sgn.initVerify(EnigmaClient.ServerPublicKey);
        sgn.update(serverDHPubKey);

        if(!sgn.verify(pbkSgn)){
            throw new CredentialException("Signature Failed");
        }

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(serverPdk,true);
        return ka.generateSecret();
    }


    private void WriteEncryptedLine(DataOutputStream dos, String data,byte[] key) throws GeneralSecurityException, IOException {
        WriteEncryptedBlock(dos,data.getBytes(StandardCharsets.UTF_8),key);
    }
    private String ReadEncryptedLine(DataInputStream dis,byte[] key) throws GeneralSecurityException, IOException {
        return new String(ReadEncryptedBlock(dis,key),StandardCharsets.UTF_8);
    }
    private void WriteEncryptedBlock(DataOutputStream dos, byte[] data,byte[] key) throws GeneralSecurityException, IOException {
        WriteBlock(dos,EnigmaCrypto.AESEncrypt(data,key));
    }
    private byte[] ReadEncryptedBlock(DataInputStream dis,byte[] key) throws GeneralSecurityException, IOException {
        byte[] data = ReadBlock(dis);
        return EnigmaCrypto.AESDecrypt(data,key);
    }
    private static String ReadBlockLine(DataInputStream dis) throws IOException {
        byte[] data = ReadBlock(dis);
        return new String(data,StandardCharsets.UTF_8);
    }
    private static void WriteBlockLine(String data,DataOutputStream dos) throws IOException {
        byte[] dataEncoded = data.getBytes(StandardCharsets.UTF_8);
        WriteBlock(dos,dataEncoded);
    }
    //Read And Writing Blocks
    private static void WriteBlock(DataOutputStream dos,byte[] data) throws IOException{
        byte[] lengthEncoded = ByteBuffer.allocate(4).putInt(data.length).array();
        dos.write(lengthEncoded);
        dos.write(data);
    }
    private static byte[] ReadBlock(DataInputStream din) throws IOException {
        byte[] lengthEncoded = new byte[4];
        int resp = din.read(lengthEncoded);
        int length =ByteBuffer.wrap(lengthEncoded).getInt();
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



    //Reading And Writing Encrypted Blocks

}