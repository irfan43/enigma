package org.dragonservers.enigma;

import javax.crypto.BadPaddingException;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
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

    //TODO Add AES file Encryption
    //TODO Add file partitioning (cut a large file into smaller files and later recombine them)
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


    public static KeyPair ReadKeyPair(File Filename,byte[] key) throws IOException, GeneralSecurityException {
        System.out.println(" Decrypting with key = " + Base64.getEncoder().encodeToString(key));
        FileInputStream fis = new FileInputStream(Filename);
        BufferedInputStream bis = new BufferedInputStream(fis);

        // verify the signature
        byte[] signature = new byte[8];
        readBytes(bis,signature);
        if(!Arrays.equals(KeyPairSignature,signature))
            throw new IOException("Bad Signature");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] checkBlock = new byte[48];
        readBytes(bis,checkBlock);
        try{
            byte[] calCheck = getVerificationBlock(Enigma.Username);
            byte[] Decrypted = EnigmaCrypto.AESDecrypt(checkBlock,key);
            if(!Arrays.equals(calCheck,
                    Decrypted)) {
                throw new IOException();
            }
        }catch (BadPaddingException | IOException e){
            throw new IOException("BAD HASH KEY");
        }


        byte[] PubEnc = EnigmaCrypto.AESDecrypt( readBlock(bis),key );
        byte[] PrvEnc = EnigmaCrypto.AESDecrypt( readBlock(bis),key );
        md.update(PubEnc);
        md.update(PrvEnc);
        byte[] hash   = readBlock(bis);
        byte[] CalculatedHash = md.digest();
        if(!Arrays.equals(CalculatedHash,hash))
            throw new IOException("BAD HASH");

        bis.close();
        return EnigmaKeyHandler.KeyPairFromEnc(PubEnc,PrvEnc);
    }



    //Writing
    //Master Function
    public static void SaveKeyPair(File Filename,KeyPair keyPair,boolean OverWrite, byte[] key) throws IOException, GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        System.out.println(" Encrypting with key = " + Base64.getEncoder().encodeToString(key));
        if(Filename.exists() && !OverWrite)
            throw new FileNotFoundException("File Already Exists");
        MKDIR(Filename.getParentFile());

        byte[] publicKeyEnc = keyPair.getPublic().getEncoded();
        byte[] privateKeyEnc = keyPair.getPrivate().getEncoded();

        md.update(publicKeyEnc);
        md.update(privateKeyEnc);

        FileOutputStream fos = new FileOutputStream(Filename);
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        bos.write(KeyPairSignature);
        byte[] checkBlock = EnigmaCrypto.AESEncrypt( getVerificationBlock(Enigma.Username), key);
        assert checkBlock.length == 48;
        bos.write( checkBlock);
        //end of header
        //now all blocks
        writeBlock(bos,  EnigmaCrypto.AESEncrypt(publicKeyEnc,key) );
        writeBlock(bos,  EnigmaCrypto.AESEncrypt(privateKeyEnc,key) );
        writeBlock(bos, md.digest());
        bos.close();
    }

    private static byte[] getVerificationBlock(String username) throws GeneralSecurityException {
        String paddingUsername = (username + "EnigmaPaddingFalseEchoEcho").substring(0,16);
        return paddingUsername.getBytes(StandardCharsets.UTF_8);
    }
    public static byte[] readBlock(BufferedInputStream bis) throws IOException {
        byte[] intLenEnc = new byte[4];
        readBytes(bis,intLenEnc);
        int len = ByteBuffer.wrap(intLenEnc).getInt();
        if(len <= 0){
            throw new IOException("Bad Block Header");
        }
        byte[] block = new byte[len];
        readBytes(bis,block);
        return block;
    }
    public static void  writeBlock(BufferedOutputStream bos, byte[] data) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(data.length);
        bos.write(bb.array());
        bos.write(data);
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
