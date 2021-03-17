package org.dragonservers.enigma;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class EnigmaServer {

    private Socket sock;
    private byte[] Secret;
    private String ServerIP;
    private int ServerPort;
    public EnigmaServer(String DomainName,int Port) throws IOException {
        ServerIP = DomainName;
        ServerPort = Port;
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
}
