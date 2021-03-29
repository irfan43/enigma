package org.dragonservers.enigma;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class EnigmaServer {

    private Socket sock;
    private final String ServerIP;
    private final int ServerPort;
    public EnigmaServer(String DomainName,int Port)  {
        ServerIP = DomainName;
        ServerPort = Port;
    }
    public PublicKey GetPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        sock = new Socket(ServerIP,ServerPort);
        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());

        //Request
        //Header
        WriteBlockLine( "enigma \\ " + Enigma.EnigmaVersion , dos);
        //Command
        WriteBlockLine( "GET PBK" , dos);

        //Response code
        String ResponseCode = ReadBlockLine(dis);
        if(!ResponseCode.equals("GOOD")){
            throw new IOException("Bad Server Response:- \"" + ResponseCode + "\"");
        }

        byte[] publicKeyEnc = ReadBlock(dis);

        return EnigmaKeyHandler.PublicKeyFromEnc(publicKeyEnc);
    }
    public void RegisterUser(String RegistrationCode, EnigmaKeyHandler enigmaKeyHandler,String Password) throws IOException {
        sock = new Socket(ServerIP,ServerPort);

        DataInputStream dis = new DataInputStream( sock.getInputStream() );
        DataOutputStream dos = new DataOutputStream(sock.getOutputStream());

        SendBlock("RGS".getBytes(StandardCharsets.UTF_8),dos,null);


        sock.close();
    }



    private void SendBlock(byte[] bin, DataOutputStream dos,byte[] key) throws IOException {
        int pos = 0;
        byte[] IntEnc = ByteBuffer.allocate(4).putInt(bin.length).array();

        if(key != null)IntEnc = EnigmaCrypto.Encrypt(IntEnc,key,pos);
        pos += 4;
        dos.write(IntEnc);
        if(key != null)bin = EnigmaCrypto.Encrypt(bin,key,pos);
        dos.write(bin);

    }
    private byte[] GrabBlock(DataInputStream dis,byte[] key) throws IOException {
        byte[] lenEnc = new byte[4];
        if(dis.read(lenEnc) == -1)
            throw new IOException("End OF Data Input Stream Reached Unexpectedly");
        int len = ByteBuffer.wrap(lenEnc).getInt();
        if(len <= 0)
            throw new IOException("Bad Block Length");
        byte[] block = new byte[len];
        if(dis.read(block) == -1)
            throw new IOException("End OF Data Input Stream Reached Unexpectedly");
        return block;
    }
    public static String ReadBlockLine(DataInputStream dis) throws IOException {
        byte[] data = ReadBlock(dis);
        return new String(data,StandardCharsets.UTF_8);
    }
    public static void WriteBlockLine(String data,DataOutputStream dos) throws IOException {
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
    private static void WriteEncryptedBlock(DataOutputStream dos, byte[] data, PublicKey publicKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(data);
        byte[] encrypted = cipher.doFinal();

        WriteBlock(dos,encrypted);
    }
    private static byte[] ReadEncryptedBlock(DataInputStream dis) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] block = ReadBlock(dis);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,Enigma.OurKeyHandler.GetPrivateKey());
        return cipher.doFinal(block);
    }
}
