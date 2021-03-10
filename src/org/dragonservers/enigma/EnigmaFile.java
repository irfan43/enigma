package org.dragonservers.enigma;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EnigmaFile {

    public static KeyPair ReadKeyPair(String Filename,byte[] key) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bin = EnigmaCrypto.Encrypt(Files.readAllBytes(Paths.get(Filename)),key);
        return GetKeyPairFromBin(bin);
    }

    public static KeyPair ReadKeyPair(String Filename) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        return GetKeyPairFromBin(Files.readAllBytes(Paths.get(Filename)));
    }

    private static KeyPair GetKeyPairFromBin(byte[] bin) throws InvalidKeySpecException, NoSuchAlgorithmException {
        List<byte[]> KeyEnc = SplitBlocks(bin);

        PublicKey pbk = EnigmaKeyHandler.PublicKeyFromEnc(KeyEnc.get(0));
        PrivateKey pvk = EnigmaKeyHandler.PrivateKeyFromEnc(KeyEnc.get(1));

        return new KeyPair(pbk,pvk);
    }

    private static byte[] GetBinFromKeypair(KeyPair keyPair){
        byte[] pubBlock = GetBlock(keyPair.getPublic().getEncoded());
        byte[] prvBlock = GetBlock(keyPair.getPrivate().getEncoded());

        byte[] bin = new byte[prvBlock.length + pubBlock.length];

        System.arraycopy(pubBlock,0,bin,0,pubBlock.length);
        System.arraycopy(prvBlock,0,bin,pubBlock.length,prvBlock.length);

        return bin;
    }

    public static void SaveKeyPair(String Filename,KeyPair keyPair,byte[] key) throws IOException {
        byte[] bin = GetBinFromKeypair(keyPair);
        Files.write(Paths.get(Filename),EnigmaCrypto.Encrypt(bin,key));
    }

    public static byte[] GetBlock(byte[] bin){
        //throw exception for blocks larger then 1mb
        if(bin.length > 1048576)throw new IllegalArgumentException("unbuffered Block Size Exceeded Maximum size");

        byte[] block = new byte[bin.length + 4];
        //Encodes the length into the first 4 bytes of the block
        byte[] intenc = ByteBuffer.allocate(4).putInt(bin.length).array();

        System.arraycopy(intenc,0,block,0,4);
        System.arraycopy(bin, 4,block,4,bin.length);

        return block;
    }


    public static List<byte[]> SplitBlocks(byte[] bin){
        List<byte[]> out = new ArrayList<>();
        int pos = 0;
        while(pos < bin.length){
            int len = ByteBuffer.wrap(Arrays.copyOfRange(bin,pos,pos + 4)).getInt();
            byte[] block = Arrays.copyOfRange(bin,pos + 4,pos + 4 + len);
            out.add(block);
        }
        return out;
    }

}
