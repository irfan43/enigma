package org.dragonservers.Aether.FileEncryption;

import org.dragonservers.Aether.AetherCLIUtil;

import javax.crypto.SecretKey;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class FileEncryptionInterface {


    public FileEncryptionInterface(List<Path> paths, Path output, boolean encryption) throws GeneralSecurityException {
        System.out.println("Aether File Encryption:-");
        if(encryption){
            Encryption(paths,output);
        }else{
            if(paths.size() != 1)
                System.out.println("More than 1 input file for decryption not allowed");
            else
                Decryption(paths.get(0),output);

        }
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        SecretKey secret1 = AetherCLIUtil.getSecretKeyFromConsole(System.console(),true,salt);
        SecretKey secret2 = AetherCLIUtil.getSecretKeyFromConsole(System.console(),false,salt);

        System.out.println(" s1 " + Base64.getEncoder().encodeToString(secret1.getEncoded()));
        System.out.println(" s2 " + Base64.getEncoder().encodeToString(secret2.getEncoded()));
        System.out.println(" equal " + Arrays.equals(secret1.getEncoded(),secret2.getEncoded()));

    }

    private void Decryption(Path path, Path output) {

    }

    public void Encryption(List<Path> paths, Path output){

        System.out.println("Performing Encryption");
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        try{

            AetherFileEncryption afe = new AetherFileEncryption(paths,output,true);
            SecretKey key = AetherCLIUtil.getSecretKeyFromConsole(System.console(), true, afe.getSALT());
            afe.setKey(key);
            Thread afeThread = new Thread(afe);
            afeThread.start();
            try {
                afeThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            List<Path> dl = new ArrayList<>();
            dl.add(output);

            AetherFileEncryption dafe = new AetherFileEncryption(dl,Path.of("."),false);
            dafe.setKey(key);
            Thread dafeThread = new Thread(dafe);
            dafeThread.start();
            try {
                dafeThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }catch (IOException | GeneralSecurityException e){
            e.printStackTrace();
        }
    }


}
