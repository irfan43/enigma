package org.dragonservers.Aether.FileEncryption;


import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class AetherFileEncryption implements Runnable{

    public static final String AETHER_ENC_FILE_HEADER = "AETHER ENC FILE";

    private List<Path> listOfPaths;
    private byte[] SALT;
    private byte[] IV;
    private SecretKey KEY;
    private boolean encrypt;
    private Path outputFile;
    private BufferedInputStream bis;
    private BufferedOutputStream bos;
    private Cipher cipher;

    /*
    Progress in bytes
    total bytes
    number of files encrypted
    total number of files
    speed of encryption
    estimated time of completion
    */


    public AetherFileEncryption(List<Path> paths,Path output, boolean encryption) throws IOException {
        listOfPaths     = walkDirectories(paths);
        encrypt         = encryption;
        outputFile      = output;

        SALT = new byte[32];
        IV = new byte[32];

        if(encryption) {
            if(Files.isDirectory(outputFile)) {
                throw new FileNotFoundException("Given output File is a Directory");
            }

            (new SecureRandom()).nextBytes(SALT);
            (new SecureRandom()).nextBytes(IV);

        }else{
            if(!Files.isDirectory(outputFile))
                throw new FileNotFoundException("Given output File is not a Directory");
            if(listOfPaths.size() != 1)
                throw new IllegalArgumentException("More than one file given for Decryption");
            bis = new BufferedInputStream(Files.newInputStream( listOfPaths.get(0) ));
            if(!readHeaders())
                throw new IOException("Bad Header");
        }
    }

    public void setKey(SecretKey key){
        KEY = key;
    }

    /**
     * Walks throught the input list and returns all the files present in them
     * @param list input list of paths
     * @return a list of paths after walking
     * @throws IOException if a IOException
     */
    public List<Path> walkDirectories(List<Path> list) throws IOException {
        List<Path> rtr = new ArrayList<>();
        for (Path p: list)
            rtr.addAll(Files.walk(p).collect(Collectors.toList()));
        return rtr;
    }
    @Override
    public void run() {
        if(encrypt){
            try {
                encryptionThread();
            } catch (IOException | GeneralSecurityException e) {
                e.printStackTrace();
            }
        }else {
            try {
                decryptionThread();
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void decryptionThread() throws GeneralSecurityException, IOException {
        buildDecryptionCipher();
        CipherInputStream cis = new CipherInputStream(bis,cipher);
        InputStreamReader isr = new InputStreamReader(cis);
        BufferedReader br = new BufferedReader(isr);
        String s = br.readLine();
        if(!s.equals("FOLDERS"))
            throw new IOException("FILE CORRUPTED OR KEY WRONG");
        int n_folders = Integer.parseInt(br.readLine());

        for (int i = 0; i < n_folders; i++) {
            System.out.println(br.readLine());
        }
        System.out.println(br.readLine());
        byte[] gmac = cipher.doFinal();
        byte[] readGmac = bis.readNBytes(gmac.length);

        if(Arrays.equals(readGmac,gmac))
            System.out.println("GMAC OK");
        else
            System.out.println("GMAC not OK");

    }

    private void encryptionThread() throws IOException, GeneralSecurityException {
        bos = new BufferedOutputStream(Files.newOutputStream(outputFile));
        writeHeaders();
        //from now all is encrypted
        buildEncryptionCipher();
        CipherOutputStream cos = new CipherOutputStream(bos,cipher);
        OutputStreamWriter osw = new OutputStreamWriter(cos);
        BufferedWriter bw = new BufferedWriter(osw);
        List<Path> listOfFiles = new ArrayList<>();
        List<Path> listOfDir = new ArrayList<>();

        for (Path p: listOfPaths) {
            if(Files.isDirectory(p))
                listOfDir.add(p);
            else if(Files.isRegularFile(p))
                listOfFiles.add(p);
        }

        bw.write("FOLDERS\n" + listOfDir.size());
        bw.newLine();

        if(listOfDir.size() != 0)
            for (Path p:listOfDir) {
                bw.write( p.toString() );
                bw.newLine();
            }

        bw.flush();
        osw.flush();
        bw.write("Done");
        bw.newLine();
        bos.write(cipher.doFinal());
        bos.close();

    }

    private void buildEncryptionCipher() throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("AES/GCM/NOPADDING");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128,IV);
        cipher.init(Cipher.ENCRYPT_MODE,KEY,parameterSpec);
    }
    private void buildDecryptionCipher() throws GeneralSecurityException{
        cipher = Cipher.getInstance("AES/GCM/NOPADDING");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128,IV);
        cipher.init(Cipher.DECRYPT_MODE,KEY,parameterSpec);
    }


    private void writeHeaders() throws IOException {
        bos.write(AETHER_ENC_FILE_HEADER.getBytes(StandardCharsets.UTF_8));
        bos.write(SALT);
        bos.write(IV);
    }
    private boolean readHeaders() throws IOException {
        byte[] header = bis.readNBytes(AETHER_ENC_FILE_HEADER.getBytes(StandardCharsets.UTF_8).length);

        SALT = bis.readNBytes(SALT.length);
        IV = bis.readNBytes(IV.length);
        return Arrays.equals(header,AETHER_ENC_FILE_HEADER.getBytes(StandardCharsets.UTF_8));
    }



    public byte[] getSALT() {
        return SALT;
    }
}
