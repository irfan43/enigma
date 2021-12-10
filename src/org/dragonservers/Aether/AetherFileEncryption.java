package org.dragonservers.Aether;

import org.dragonservers.enigma.EnigmaBlock;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public class AetherFileEncryption {


    public static final byte[] EncryptedFileSignature = "AETHER ENC FILE\n".getBytes(StandardCharsets.UTF_8);

    public static void HandleCmdARGS(String[] args){
        List<Path> targets = new ArrayList<>();
        Path output = Path.of(".");
        boolean overwrite = false;
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if(arg.charAt(0) == '-'){
                switch (arg.toLowerCase()){
                    case "-o","--output" -> {
                        if(args.length >= (i + 1)){
                            i++;
                            output = Path.of(args[i]);
                        }
                    }
                    default -> {
                        System.out.println("invalid option " + arg);
                        System.out.println("Please read help and try again");
                    }
                }
            }else{
                targets.add(Path.of(arg));
            }
        }
        switch(args[0].toLowerCase()){
            case "--encrypt","-e" -> {
                if(targets.size() > 1){
                    EncryptCLI(targets,output,overwrite);
                }else{
                    System.out.println("");
                }
            }
            case "--decrypt","-d" -> {

            }
        }
    }


    public static void Decrypt(Path target,Path output, boolean overwrite) throws IOException{
        if(!Files.exists(target))
            throw new FileNotFoundException("Input File Not Found");
        BufferedInputStream is = new BufferedInputStream( Files.newInputStream(target));
        verifyHeader(is);
        String algo = new String(EnigmaBlock.ReadBlock(is),StandardCharsets.UTF_8);
        readAlgorithmParameters(is);
        String key_verif = new String(EnigmaBlock.ReadBlock(is),StandardCharsets.UTF_8);
        int n = ByteBuffer.wrap(EnigmaBlock.ReadBlock(is)).getInt();
        for (int i = 0; i < n; i++) {
            readFileBlock(is,output,overwrite);
        }
    }
    public static void EncryptCLI(List<Path> target,Path output, boolean overwrite){
        if(target.size() < 1){
            System.out.println("no Target Specified\nPlease Specify a target");
        }
        System.out.println("Encryption Password:-");
        Encrypt(target,output,overwrite,);
    }
    public static void Encrypt(List<Path> target,Path output, boolean overwrite, SecretKey secretKey) throws IOException {
        for (Path p: target) {
            if (!Files.exists(p))
                throw new FileNotFoundException("Input File Not Found");
        }
        if((!overwrite) && Files.exists(output))
            throw new FileNotFoundException("Output already Exists");

        List<Path> filesList =  new ArrayList<>();
        for (Path p: target)
            filesList.addAll(walkDirectory(p));

        int n = filesList.size();

        BufferedOutputStream os = new BufferedOutputStream( Files.newOutputStream(output) );

        EnigmaBlock.WriteBlock(os, EncryptedFileSignature);
        EnigmaBlock.WriteBlock(os, "AES/GCM".getBytes(StandardCharsets.UTF_8));
        writeAlgorithmParameters(os,"IV".getBytes(StandardCharsets.UTF_8),"SALT".getBytes(StandardCharsets.UTF_8));
        //From Now Encrypted
        EnigmaBlock.WriteBlock(os, "CORRECT_KEY".getBytes(StandardCharsets.UTF_8));
        EnigmaBlock.WriteBlock(os, ByteBuffer.allocate(4).putInt(n).array());

        for (Path file : filesList) {
            writeFileBlock(file,os);
        }
        os.close();
    }

    private static void verifyHeader(BufferedInputStream is) throws IOException {
        if (!Arrays.equals(EncryptedFileSignature,EnigmaBlock.ReadBlock(is)))
            throw new IOException("Invalid File Header");
    }
    private static void writeFileBlock(Path file, OutputStream os) throws IOException {
        EnigmaBlock.WriteBlock(os,file.toString().getBytes(StandardCharsets.UTF_8));
        EnigmaBlock.WriteBlock(os,ByteBuffer.allocate(8).putLong(Files.size(file)).array());
        CopyStreams(Files.newInputStream(file),os,Files.size(file));
    }
    private static void readFileBlock(InputStream is, Path output, boolean overwrite) throws IOException {
        Path currentFile = Path.of(new String(EnigmaBlock.ReadBlock(is),StandardCharsets.UTF_8));
        long fileSize = ByteBuffer.wrap(EnigmaBlock.ReadBlock(is)).getLong();

        Path out = output.resolve(currentFile);
        if((!overwrite)&&(Files.exists(out)))
            throw new IOException("File Already Exists");
        Files.createDirectories(out.getParent());
        System.out.println("Echo" + out.toString());
        CopyStreams(is,Files.newOutputStream(out),fileSize);
    }
    private static byte[] readAlgorithmParameters(InputStream is){
        return null;
    }
    private static void writeAlgorithmParameters(OutputStream os,byte[] IV,byte[] salt) {
    }
    private static List<Path> walkDirectory(Path target) throws IOException {
        if(Files.isDirectory(target)){
            return Files.walk(target).collect(Collectors.toList());
        }else{
            List<Path> out = new ArrayList<>();
            out.add(target);
            return out;
        }
    }

    private static void CopyStreams(InputStream is, OutputStream os,long l) throws IOException {
        long pos = 0;
        while (pos < l){
            int bufSize = (int)(l - pos);
            if( (bufSize) > 16328 )
                bufSize = 16328;
            byte[] buffer = new byte[bufSize];
            int readSize = is.read(buffer);
            pos += readSize;
            if(readSize != buffer.length)
                buffer = Arrays.copyOf(buffer,readSize);
            os.write(buffer);
        }
    }
}
