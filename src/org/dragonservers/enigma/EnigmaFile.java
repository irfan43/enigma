package org.dragonservers.enigma;

import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EnigmaFile {

    //Constants
    public static byte[] EncryptionSignature = new byte[]{ (byte)0x1d,(byte)0x08,(byte)0x14,(byte)0x17,(byte)0x06,(byte)0x13,(byte)0x36};
    public static byte[] VersionCode = new byte[]{ (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};


    // Reading and Writing to KeyPair
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

    public static void SaveKeyPair(String Filename,KeyPair keyPair,byte[] key) throws IOException {
        byte[] bin = GetBinFromKeypair(keyPair);
        Files.write(Paths.get(Filename),EnigmaCrypto.Encrypt(bin,key));
    }
    public static void SaveKeyPair(String Filename,KeyPair keyPair) throws IOException {
        byte[] bin = GetBinFromKeypair(keyPair);
        Files.write(Paths.get(Filename),bin);
    }
    private static byte[] GetBinFromKeypair(KeyPair keyPair){
        byte[] pubBlock = GetBlock(keyPair.getPublic().getEncoded());
        byte[] prvBlock = GetBlock(keyPair.getPrivate().getEncoded());

        byte[] bin = new byte[prvBlock.length + pubBlock.length];

        System.arraycopy(pubBlock,0,bin,0,pubBlock.length);
        System.arraycopy(prvBlock,0,bin,pubBlock.length,prvBlock.length);

        return bin;
    }


    //Reading and Writing a list of keys
    public static List<PublicKey> GetKeyList(String Filename,byte[] key) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        return getKeyList(EnigmaCrypto.Encrypt(Files.readAllBytes(Paths.get(Filename)),key));
    }
    public static List<PublicKey> GetKeyList(String Filename) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        return getKeyList(Files.readAllBytes(Paths.get(Filename)));
    }
    private static List<PublicKey> getKeyList(byte[] bin) throws InvalidKeySpecException, NoSuchAlgorithmException {
        List<PublicKey> listPBK = new ArrayList<>();
        List<byte[]> lstBlck = SplitBlocks(bin);
        for(byte[] block:lstBlck)
            listPBK.add(EnigmaKeyHandler.PublicKeyFromEnc(block));
        return listPBK;
    }
    private static byte[] getBinFromKeyList(PublicKey[] PBK_Array){
        byte[] bin;
        List<byte[]> blocks = new ArrayList<>();
        int len = 0;
        for (PublicKey pb: PBK_Array) {
            byte[] blck = GetBlock(pb.getEncoded());
            len += blck.length;
            blocks.add(blck);
        }
        bin = new byte[len];
        int pos = 0;
        for( byte[] blck:blocks){
            System.arraycopy(blck,0,bin,pos,blck.length);
            pos += blck.length;
        }
        return bin;
    }


    //block splitting
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
            pos += 4 + len;
        }
        return out;
    }


    //TODO later add multithreading to create new threads to encrypt a file and then return the encrypted
    public static void EncryptFile(String[] SourceFiles, byte[] key,String FileName) throws IOException, NoSuchAlgorithmException {
        File[] files = new File[SourceFiles.length];
        for (int i = 0;i < SourceFiles.length;i++) {
            files[i] = (new File(SourceFiles[i]));
        }
        EncryptFile(files,key,FileName);
    }
    public static void EncryptFile(File[] SourceFiles, byte[] key,String FileName) throws IOException, NoSuchAlgorithmException {

        int pos = 0;

        FileOutputStream fos = new FileOutputStream(FileName);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //write the signature
        bos.write(EncryptionSignature);
        bos.write(VersionCode);

        //  == Encryption starts from here  ==  SHA256 hash starts from here == \\

        //writes the number of files present
        byte[] intenc = ByteBuffer.allocate(4).putInt(SourceFiles.length).array();

        md.update(intenc);
        intenc = EnigmaCrypto.Encrypt(intenc,key,pos);
        pos +=4;
        bos.write(intenc);

        //TODO improve it so to do recursively for directories
        for (File file : SourceFiles)
            pos = GetLongBlockBuffered(bos, file, key,pos, md);

        // == SHA 256 hash stops from here == \\

        // calculate the hash
        byte[] sha256 = md.digest();
        sha256 = EnigmaCrypto.Encrypt(sha256,key,pos);
        pos += sha256.length;
        bos.write(GetBlock(sha256));
        bos.flush();
        bos.close();

    }
    private static int GetLongBlockBuffered(BufferedOutputStream bos,File ToEncrypt,byte[] key,int pos,MessageDigest md) throws IOException {

        //File Reading Streams
        FileInputStream fis = new FileInputStream(ToEncrypt);
        BufferedInputStream bis = new BufferedInputStream(fis);

        //Write the name

        byte[] NameEnc = GetBlock(ToEncrypt.getName().getBytes(StandardCharsets.UTF_8));
        pos = DigestEncryptWrite(NameEnc,md,key,pos,bos);

        //Write the Length
        byte[] longLenEnc =  ByteBuffer.allocate(8).putLong(ToEncrypt.length()).array();
        pos = DigestEncryptWrite(longLenEnc,md,key,pos,bos);

        while (bis.available() > 0){
            byte[] buffer;
            if(bis.available() >=1024){
                buffer = new byte[1024];
            }else{
                buffer = new byte[bis.available()];
            }
            bis.read(buffer);
            md.update(buffer);
            buffer = EnigmaCrypto.Encrypt(buffer,key,pos);
            pos += buffer.length;
            bos.write(buffer);

            //trim pos to stop overflowing
            if(pos >= (key.length*10))pos -= key.length*(pos/ key.length);
        }
        bos.close();
        return pos;
    }
    private static int DigestEncryptWrite(byte[] block,MessageDigest md, byte[] key, int pos,BufferedOutputStream bos) throws IOException {
        md.update(block);
        byte[] Encrypted = EnigmaCrypto.Encrypt(block,key,pos);
        pos += block.length;
        bos.write(Encrypted);
        return  pos;
    }

    public static void DecryptFile(File Filename,String Destination,byte[] key) throws IOException, NoSuchAlgorithmException {
        int pos = 0;

        FileInputStream fis = new FileInputStream(Filename);
        BufferedInputStream bis = new BufferedInputStream(fis);

        File destination = new File(Destination);
        if(destination.exists()) {
            if (!destination.isDirectory())
                throw new FileNotFoundException("Destination is not a directory");
        }else{
             //create directory
             if(!destination.mkdirs())
                 throw new FileNotFoundException("Could not create Directory");
        }

        byte[] Signature = new byte[8];
        bis.read(Signature);

        byte[] versionCode = new byte[4];
        bis.read(versionCode);

        if(!Arrays.equals(Signature,EncryptionSignature) )
            throw new IOException("Invalid Signature, This is not a Encryption file or has a bad header ");
        //TODO handle version stuff currently 1 version so not needed



        MessageDigest md = MessageDigest.getInstance("SHA-256");

        //  == Decryption starts from here  ==  SHA256 hash starts from here == \\

        //get the number of files Present
        byte[] nFilesEnc = ReadDecryptDigest(4,bis,key,pos,md);
        int nFiles = ByteBuffer.wrap(nFilesEnc).getInt();
        pos += nFilesEnc.length;

        for(int i = 0;i < nFiles;i++){
            pos = SaveDecryptedFile(bis,key,pos,md,destination);
        }
        byte[] calculateHash = md.digest();
        byte[] hash = (byte[]) GrabEncryptedBlock(bis,key,pos,md)[0];
        if(!Arrays.equals(hash,calculateHash))
            throw new IOException("Bad HASH ");

        bis.close();
    }
    //TODO verify this
    public static boolean IsParentDirectory(File ToCheck, File Parent) throws IOException {
        String parentPath = Parent.getCanonicalPath();
        File checkParent = ToCheck.getParentFile();
        while(checkParent != null) {
            if( checkParent.getCanonicalPath().equals(parentPath) ) return true;
            checkParent = checkParent.getParentFile();
        }
        return false;
    }
    private static int SaveDecryptedFile(BufferedInputStream bis, byte[] key, int pos, MessageDigest md,File TopDirectory) throws IOException{
        //grab name and generate file
        Object[] rtr = GrabEncryptedBlock(bis,key,pos,md);
        byte[] fileNameEnc = (byte[])rtr[0];
        pos = (int) rtr[1];

        String outputFilename = new String(fileNameEnc,StandardCharsets.UTF_8);
        File output = new File(outputFilename);
        if(output.exists())
            throw new IOException( output.getName() + " already exists");
        //TODO add overWright flag

        if(!IsParentDirectory(output,TopDirectory))
            throw new IOException("BAD FILE Directory, trying to escape TopDirectory ");

        if(!output.getParentFile().mkdirs())
            throw new IOException("Failed To Make Parent Directories");

        FileOutputStream fos = new FileOutputStream(output);
        BufferedOutputStream bos = new BufferedOutputStream(fos);


        byte[] lengthLongEnc = new byte[8];
        bis.read(lengthLongEnc);
        lengthLongEnc = EnigmaCrypto.Encrypt(lengthLongEnc,key,pos);
        md.update(lengthLongEnc);
        pos += lengthLongEnc.length;
        long length = ByteBuffer.wrap(lengthLongEnc).getLong();

        int blockPos = 0;
        while ( (length - (long)blockPos) > 0){
            byte[] buffer;
            if((length - (long)blockPos) > 1024){
                buffer = new byte[1024];
            }else {
                buffer = new byte[(int)(length - (long)blockPos)];
            }
            bis.read(buffer);
            buffer = EnigmaCrypto.Encrypt(buffer,key,pos);

            blockPos += buffer.length;
            pos += buffer.length;
            md.update(buffer);
            bos.write(buffer);
        }
        bos.flush();
        bos.close();
        return pos;
    }
    private static Object[] GrabEncryptedBlock(BufferedInputStream bis, byte[] key,int pos, MessageDigest md) throws IOException {
        byte[] blockLengthEnc = new byte[4];
        bis.read(blockLengthEnc);
        blockLengthEnc = EnigmaCrypto.Encrypt(blockLengthEnc,key,pos);

        md.update(blockLengthEnc);
        pos += blockLengthEnc.length;
        int blockLength = ByteBuffer.wrap(blockLengthEnc).getInt();

        byte[] data = new byte[blockLength];

        bis.read(data);
        data = EnigmaCrypto.Encrypt(data,key,pos);
        md.update(data);
        pos += data.length;
        return new Object[]{data,pos};
    }
    private static byte[] ReadDecryptDigest(int len, BufferedInputStream bis, byte[] key,int pos, MessageDigest md) throws IOException {
        byte[] bin = new byte[len];
        bis.read(bin);
        EnigmaCrypto.Encrypt(bin,key,pos);
        md.update(bin);
        return bin;
    }

}
