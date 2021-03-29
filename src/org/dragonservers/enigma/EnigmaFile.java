package org.dragonservers.enigma;

import org.jetbrains.annotations.Nullable;
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

    //Constants                             //(byte) 78,(byte) e6,(byte) 42,(byte) 06,(byte) d8,(byte) 00,(byte) 0f,(byte) eb
    final static byte[] KeyPairSignature =
            new byte[]{ (byte)0x78,(byte)0xe6,(byte)0x42,(byte)0x06,(byte)0xd8,(byte)0x00,(byte)0x0f,(byte)0xeb};
    final static byte[] KeyListSignature =
            new byte[]{ (byte)0x41,(byte)0x4D,(byte)0x54,(byte)0x75,(byte)0x72,(byte)0x69,(byte)0x6e,(byte)0x67};
    final static byte[] EncryptionSignature =
            new byte[]{ (byte)0x1d,(byte)0x08,(byte)0x14,(byte)0x0e,(byte)0x17,(byte)0x06,(byte)0x13,(byte)0x36};
    public static byte[] VersionCode =
            new byte[]{ (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
    private static final String[] configFileValues = {"Username","Registered","Keypair"};

    public static void MKDIR(String file) throws IOException {
        MKDIR(new File(file));
    }
    public static void MKDIR(File file) throws IOException {
        if(file.exists()){
            if(!file.isDirectory())
                throw new FileNotFoundException("Given File is not a Directory");
        }else {
            if (!file.mkdirs())
                throw new IOException("Could not create the Directory or parent directory for " + file.getCanonicalPath());
        }
    }
    public static void readBytes(BufferedInputStream bis,byte[] block) throws IOException {
        int eof = bis.read(block);
        if(eof == -1)
            throw new IOException("Reached End Of File Prematurely");
    }
    // Reading and Writing to KeyPair
    //Reading
    public static KeyPair ReadKeyPair(File Filename,byte[] key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(Filename);
        BufferedInputStream bis = new BufferedInputStream(fis);

        byte[] signature = new byte[8];
        readBytes(bis,signature);
        if(!Arrays.equals(KeyPairSignature,signature))
            throw new IOException("Bad Signature");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int pos = 0;
        List<byte[]> keysEnc = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            Object[] rtr = GrabEncryptedBlock(bis,key,pos,md);
            keysEnc.add( (byte[])rtr[0] );
            pos = (int)rtr[1];
        }

        byte[] hash = new byte[32];
        readBytes(bis,hash);

        byte[] CalculatedHash = md.digest();
        if(!Arrays.equals(CalculatedHash,hash))
            throw new IOException("BAD HASH");
        bis.close();
        return EnigmaKeyHandler.KeyPairFromEnc(keysEnc.get(0),keysEnc.get(1));
    }
    //Writing
    //Master Function
    public static void SaveKeyPair(String Filename,KeyPair keyPair,boolean OverWrite, byte[] key) throws IOException, NoSuchAlgorithmException {
        SaveKeyPair(new File(Filename),keyPair,OverWrite,key);
    }
    public static void SaveKeyPair(File Filename,KeyPair keyPair,boolean OverWrite, byte[] key) throws IOException, NoSuchAlgorithmException {
        byte[] bin = GetBinFromKeypair(keyPair);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bin);
        if(key != null) bin = EnigmaCrypto.Encrypt(bin,key);

        if(Filename.exists() && !OverWrite)
            throw new FileNotFoundException("File Already Exists");
        MKDIR(Filename.getParentFile());

        FileOutputStream fos = new FileOutputStream(Filename);
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        bos.write(KeyPairSignature);
        bos.write(bin);
        bos.write(md.digest());
        bos.close();
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

    public static List<PublicKey> ReadKeyList(String Filename) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        return ReadKeyList(new File(Filename));
    }
    public static List<PublicKey> ReadKeyList(File file) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        if(!file.exists())
            throw new FileNotFoundException("Key List File Not Found");
        if(file.isDirectory())
            throw new FileNotFoundException("Key List File is Directory");

        byte[] signiture = new byte[8];

        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);

        //Read the first 8 bytes and check the signiture
        readBytes(bis,signiture);
        if(Arrays.equals(signiture,KeyListSignature))
            throw new IOException("BAD Key List Exceptions");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //Grab the number of keys present in this file
        int nKeys = GetBufferedInt(bis,md);

        //Grab the public key
        List<PublicKey> listPBK = new ArrayList<>();
        for (int i = 0; i < nKeys; i++)
            listPBK.add(GrabKey(bis,md));

        byte[] hash = new byte[32];
        readBytes(bis,hash);

        if(!Arrays.equals(hash,md.digest()))
            throw new IOException("BAD HASH");

        return listPBK;
    }
    private static PublicKey GrabKey(BufferedInputStream bis,MessageDigest md) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        int len = GetBufferedInt(bis, md);
        if(len <= 0)
            throw new IOException("BAD BLOCK Length");

        byte[] bin = new byte[len];
        readBytes(bis,bin);
        return EnigmaKeyHandler.PublicKeyFromEnc(bin);
    }
    private static int GetBufferedInt(BufferedInputStream bis,MessageDigest md) throws IOException {
        byte[] lenEnc = new byte[4];
        readBytes(bis,lenEnc);
        if(md != null)md.update(lenEnc);
        return ByteBuffer.wrap(lenEnc).getInt();
    }
    public static void SaveKeyList(File Filename,List<PublicKey> publicKeys) throws IOException, NoSuchAlgorithmException {

        if(Filename.isDirectory())
            throw new FileNotFoundException("Given File is a Directory");

        MKDIR(Filename.getParentFile());

        PublicKey[] ToSave = (PublicKey[]) publicKeys.toArray();
        FileOutputStream fos = new FileOutputStream(Filename);
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        bos.write(KeyListSignature);

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] LenEnc = ByteBuffer.allocate(4).putInt(ToSave.length).array();
        bos.write(LenEnc);
        md.update(LenEnc);

        for(PublicKey pbk: ToSave) {
            byte[] block = GetBlock(pbk.getEncoded());
            bos.write(block);
            md.update(block);
        }

        //Write the sha256 hash
        bos.write(md.digest());

        bos.close();
    }
    public static byte[] GetBlock(byte[] bin){
        //throw exception for blocks larger then 1mb
        if(bin.length > 1048576)throw new IllegalArgumentException("unbuffered Block Size Exceeded Maximum size");

        byte[] block = new byte[bin.length + 4];
        //Encodes the length into the first 4 bytes of the block
        byte[] intEncoded = ByteBuffer.allocate(4).putInt(bin.length).array();

        System.arraycopy(intEncoded,0,block,0,4);
        System.arraycopy(bin, 0,block,4,bin.length);

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
        byte[] intEncoded = ByteBuffer.allocate(4).putInt(SourceFiles.length).array();

        md.update(intEncoded);
        intEncoded = EnigmaCrypto.Encrypt(intEncoded,key,pos);
        pos +=4;
        bos.write(intEncoded);

        //TODO improve it so to do recursively for directories
        for (File file : SourceFiles)
            pos = GetLongBlockBuffered(bos, file, key,pos, md);

        // == SHA 256 hash stops from here == \\

        // calculate the hash
        byte[] sha256 = md.digest();
        bos.write(sha256);
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
            readBytes(bis,buffer);
            md.update(buffer);
            buffer = EnigmaCrypto.Encrypt(buffer,key,pos);
            pos += buffer.length;
            bos.write(buffer);

            //trim pos to stop overflowing
            if(pos >= (key.length*10))pos -= key.length*(pos/ key.length);
        }
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
        readBytes(bis,Signature);

        byte[] versionCode = new byte[4];
        readBytes(bis,versionCode);

        if(!Arrays.equals(Signature,EncryptionSignature) )
            throw new IOException("Invalid Signature, This is not a Encryption file or has a bad header ");
        //TODO handle version stuff currently 1 version so not needed



        MessageDigest md = MessageDigest.getInstance("SHA-256");

        //  == Decryption starts from here  ==  SHA256 hash starts from here == \\

        //get the number of files Present
        byte[] nFilesEnc = ReadDecryptDigest(4,bis,key,pos,md);
        int nFiles = ByteBuffer.wrap(nFilesEnc).getInt();
        pos += nFilesEnc.length;
        if(nFiles <= 0 )
            throw new IOException("BAD FILE ARGUMENTS 'nFile'");
        for(int i = 0;i < nFiles;i++){
            pos = SaveDecryptedFile(bis,key,pos,md,destination);
        }
        byte[] calculateHash = md.digest();
        byte[] hash = new byte[32];
        int EOF = bis.read(hash);

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
        File output = new File(TopDirectory,outputFilename);
        if(output.exists())
            throw new IOException( output.getName() + " already exists");
        //TODO add overWright flag

        if(!IsParentDirectory(output,TopDirectory))
            throw new IOException("BAD FILE Directory, trying to escape TopDirectory ");

        if(!TopDirectory.exists())if(!TopDirectory.mkdirs())
            throw new IOException("Failed To Make Parent Directories");

        FileOutputStream fos = new FileOutputStream(output);
        BufferedOutputStream bos = new BufferedOutputStream(fos);


        byte[] lengthLongEnc = new byte[8];
        readBytes(bis,lengthLongEnc);
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
            readBytes(bis,buffer);
            buffer = EnigmaCrypto.Encrypt(buffer,key,pos);

            blockPos += buffer.length;
            pos += buffer.length;
            md.update(buffer);
            bos.write(buffer);
            if(pos > key.length*10)pos -= (pos/key.length)*key.length;
        }
        bos.flush();
        bos.close();
        return pos;
    }
    private static Object[] GrabEncryptedBlock(BufferedInputStream bis, byte[] key,int pos,@Nullable MessageDigest md) throws IOException {
        byte[] blockLengthEnc = ReadDecryptDigest(4,bis,key,pos,md);
        pos += blockLengthEnc.length;
        int blockLength = ByteBuffer.wrap(blockLengthEnc).getInt();

        byte[] data = new byte[blockLength];

        int eof = bis.read(data);
        if(eof == -1)
            throw new IOException("End Of File Reached");
        if(key != null)data = EnigmaCrypto.Encrypt(data,key,pos);
        if(md != null)md.update(data);
        pos += data.length;
        return new Object[]{data,pos};
    }
    private static byte[] ReadDecryptDigest(int len, BufferedInputStream bis, byte[] key,int pos,@Nullable MessageDigest md) throws IOException {
        byte[] bin = new byte[len];
        readBytes(bis,bin);
        if(key != null)bin = EnigmaCrypto.Encrypt(bin,key,pos);
        if(md != null)md.update(bin);
        return bin;
    }

    //Functions for handling Config Files
    public static String GrabConfig() {

        File configFile = new File(Enigma.ConfigFileName);

        if(!configFile.exists())
            return "DNE";
        if(configFile.isDirectory())
            return "DIR";
        if(!configFile.canRead())
            return "NRP";//No Read Privilege

        //all good try Reading the file
        String[] Ans =  new String[configFileValues.length];
        boolean[] AnsPresent =  new boolean[configFileValues.length];

        Arrays.fill(AnsPresent, false);

        try {
            //TODO improve this algo
            List<String> lines = Files.readAllLines(Paths.get(Enigma.ConfigFileName));
            for (String line:lines) {
                if(line.startsWith("#"))
                    continue;
                for (int i = 0; i < configFileValues.length; i++)
                    if(line.startsWith(configFileValues[i])) {
                        Ans[i] = GetValue(line, ':');
                        AnsPresent[i] = true;
                    }
            }


        }catch (FileNotFoundException e){
            return "FNF";
        } catch (IOException e) {
            e.printStackTrace();
            return "IOE";
        }


        if(!AnsPresent[0])
            return "CF";
        else
            Enigma.Username = Ans[0];

        if(AnsPresent[1])
            Enigma.Registered = Ans[1].equalsIgnoreCase("true");
        if(AnsPresent[2])
            Enigma.KeypairGenerated = Ans[2].equalsIgnoreCase("true");

        return "OK";
    }
    private static String GetValue(String line, char separator) {
        int sepLoc = -1;
        for (int i = 0; i < line.length(); i++) {
            if(line.charAt(i) == separator ) {
                sepLoc = i;
                break;
            }
        }
        if(sepLoc == -1)return null;
        return line.substring(sepLoc + 1); //Magic:Check gives 5
    }
    public static String PushConfig(){
        File config = new File(Enigma.ConfigFileName);

        if(!config.exists()){
            try {
                if(!config.createNewFile()){
                    return "CNC";
                }
            } catch (IOException e) {
                return "IOE";
            }
        }

        if(config.isDirectory())
            return "DIR";
        if(!config.canWrite())
            return "NWP"; //No Write Privilege
        String[] Ans = new String[configFileValues.length];

        Ans[0] = Enigma.Username;
        Ans[1] = (Enigma.Registered) ? "true" : "false";
        Ans[2] = (Enigma.KeypairGenerated) ? "true" : "false";

        try {
            FileWriter fw = new FileWriter(config);
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write( "#" + "Enigma Version " + Enigma.EnigmaVersion + "\n");
            bw.write("# NOT INTENDED FOR USER EDITING, TO Change Settings Go Through Software Interface" + "\n");
            bw.write("# Updated on " + EnigmaTime.GetFormattedTime() + "\n");
            for (int i = 0; i < configFileValues.length; i++) {
                bw.write(configFileValues[i] + ":" + Ans[i] + "\n");
            }
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
            return "IOE";
        }
        return "OK";
    }
}
