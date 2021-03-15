package org.dragonservers.enigma;

import org.jetbrains.annotations.Nullable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;

public class EnigmaServer {


    public EnigmaServer(String DomainName,int Port){

    }
    public void RegisterUser(String RegistrationCode, EnigmaKeyHandler enigmaKeyHandler,String Password){

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
        dis.read(lenEnc);
        int len = ByteBuffer.wrap(lenEnc).getInt();
        if(len <= 0)
            throw new IOException("Bad Block Length");


        byte[] block = new byte[len];
        dis.read(block); //TODO handle returning -1

        return block;
    }
}
