package org.dragonservers.Aether;

import org.dragonservers.enigma.EnigmaBlock;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class AetherFileEncryptionCLI {
	/**
	 * TODO add signing option
	 * TODO add method to print out help info
	 * TODO add options for folders
	 * TODO add options for different AES modes
	 * TODO add options for multiple files
	 * TODO add options for zip
	 * TODO add output option
	 * TODO Add file partitioning (cut a large file into smaller files and later recombine them)
	 * TODO clean code
	 */
	public static final byte[] EncryptedFileSignature = "AETHER ENC FILE\n".getBytes(StandardCharsets.UTF_8);


	public static void Encrypt(String[] args) {
		if (args.length < 2){
			System.out.println("Not Specified File name");
			Aether.ArgumentHelp();
		}else{

			Path target = Path.of(args[1]);
			VerifyTarget(target);
			switch(args[0].toLowerCase()){
				case "--encrypt","-e" -> {
					Path output = Path.of(GetFileName(target) + ".crypt");
					EncryptDirectory(target,output);
				}
				case "--decrypt","-d" ->
					decryptFile(target);

			}
		}
	}

	private static String GetFileName(Path path){
		return path.toFile().getName();
	}
	private static void VerifyTarget(Path target) {
		if(!Files.exists(target)){
			System.out.println("File " + target.toUri() + " does not exist");
			System.exit(0);
		}
		if(Files.isDirectory(target)){
			System.out.println("Directory Encryption is not yet supported by Aether");
			System.exit(0);
		}
	}

	private static void decryptFile(Path target) {
		SecretKeySpec secretKey = GetSecretKey(false);

		BufferedInputStream 	is = null;
		BufferedOutputStream 	os = null;
		try {
			is = new BufferedInputStream(Files.newInputStream(target));

			Cipher dCipher = GetCipher(secretKey, readHeader(is));
			CipherInputStream cis = new CipherInputStream(is,dCipher);

			String outputFile = new String( EnigmaBlock.ReadBlock(cis),StandardCharsets.UTF_8 );

			verifyFileName(outputFile);

			Path outputPath = Path.of(outputFile);
			os = new BufferedOutputStream(Files.newOutputStream(outputPath));

			long fileSize = ByteBuffer
					.wrap(EnigmaBlock.ReadBlock(cis))
					.getLong();

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			CopyStream(cis,os,md,fileSize);
			verifySHA(md,cis);
		}
		catch (IOException e){
			System.out.println("IO Exception while Decrypting File");
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e){
			System.out.println("SHA 256 Algo Not Supported in this JVM");
			e.printStackTrace();
		}
		catch (IllegalArgumentException e){
			System.out.println("Illegal State :- " + e.getLocalizedMessage());
			e.printStackTrace();
		}
		finally {
			try {
				if(is != null)
					is.close();
				if(os != null)
					os.close();
			}catch (Exception e){
				System.out.println("Exception while Closing File Handler");
			}
		}
	}
	private static byte[] readNBytes(InputStream is, int n) throws IOException {
		int pos = 0;
		int left = n;
		byte[] output = new byte[n];
		while(left > 0) {
			byte[] tmp = new byte[left];
			int len = is.read(tmp);
			if(len == -1)throw new IOException();
			System.arraycopy(tmp,0,output,pos,len);
			pos += len;
			left -= len;
		}
		return output;
	}
	private static void verifySHA(MessageDigest md,InputStream is) throws IOException {
		byte[] sha = md.digest();
		byte[] readSha = readNBytes(is,32);

		if(Arrays.equals(sha,readSha)){
			System.out.println("Good SHA256 hash\n" +
					"got   " + Base64.getEncoder().encodeToString(sha) + 		"\n" );
		}else{
			System.out.println("BAD SHA256 hash\n" +
					"got   " + Base64.getEncoder().encodeToString(sha) + 		"\n" +
					"given " + Base64.getEncoder().encodeToString(readSha) +	"\n"
			);
		}
	}
	private static void verifyFileName(String outputFile) {
		if(
				outputFile.contains("\\") ||
				outputFile.contains("/")
		)
			throw new IllegalArgumentException("BAD FILE NAME escaping directory Attack detected");

	}
	// input target should be array

	public static void EncryptDirectory(Path target, Path output) {
		SecretKeySpec secretKey = GetSecretKey(true);
		Cipher eCipher = GetCipher(secretKey);

		BufferedInputStream 	is = null;
		BufferedOutputStream 	os = null;

		try {
			is = new BufferedInputStream(	Files.newInputStream(target)	);
			os = new BufferedOutputStream(	Files.newOutputStream(output)	);

			WriteHeader(os, eCipher);

			CipherOutputStream cipherOS = new CipherOutputStream(os, eCipher);
			WriteFileInfo(target,cipherOS);

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			CopyStream(is,cipherOS,md, Files.size(target));

			byte[] sha = md.digest();
			System.out.println("SHA256:-" + Base64.getEncoder().encodeToString(sha));
			cipherOS.write(sha);
			cipherOS.close();
		}catch (IOException e){
			System.out.println("IO Exception while encrypting File");
			e.printStackTrace();
		}catch (NoSuchAlgorithmException e){
			System.out.println("SHA 256 Algo Not Supported in this JVM");
			e.printStackTrace();
		}finally {
			try {

				if(is != null)
					is.close();
				if(os != null) {
					os.flush();
					os.close();
				}
			}catch (Exception e){
				System.out.println("Exception while Closing Files");
			}
		}
	}

	private static AlgorithmParameters readHeader(InputStream is)
			throws IOException, NoSuchAlgorithmException {
		byte[] signature = EnigmaBlock.ReadBlock(is);
		if(!Arrays.equals(signature,EncryptedFileSignature))
			throw new IllegalArgumentException("BAD FILE SIGNATURE");

		AlgorithmParameters algoParam = AlgorithmParameters.getInstance("AES");
		algoParam.init(EnigmaBlock.ReadBlock(is));
		return algoParam;
	}
	private static void WriteFileInfo(Path path, OutputStream os)throws IOException {
		EnigmaBlock.WriteBlock(os,GetFileName(path).getBytes(StandardCharsets.UTF_8));
		long fileSize = Files.size(path);
		byte[] sizeEncoded = ByteBuffer
				.allocate(8)
				.putLong(fileSize)
				.array();
		EnigmaBlock.WriteBlock(os,sizeEncoded);
	}
	private static void WriteHeader(OutputStream os, Cipher eCipher) throws IOException {
		EnigmaBlock.WriteBlock(os,EncryptedFileSignature);
		EnigmaBlock.WriteBlock(os,eCipher.getParameters().getEncoded());
	}
	private static SecretKeySpec GetSecretKey(boolean confirmPassword){
		byte[] hash;
		if(confirmPassword){
			hash = AetherCLIUtil.confirmPassword();
		} else {
			System.out.println("Password:-");
			hash = AetherCLIUtil.getPasswordHash();
		}
		return new SecretKeySpec(hash, 0, 32, "AES");
	}

	private static Cipher GetCipher(SecretKeySpec secretKey) {
		Cipher cipher = CipherInstance();
		try {
			cipher.init(Cipher.ENCRYPT_MODE,secretKey);
		} catch (InvalidKeyException e) {
			System.out.println("ERROR Initializing Cipher");
			e.printStackTrace();


			System.exit(0);
		}
		return cipher;
	}
	private static Cipher GetCipher(
			SecretKeySpec secretKey, AlgorithmParameters algorithmParameters){
		Cipher cipher = CipherInstance();
		try {
			cipher.init(Cipher.DECRYPT_MODE,secretKey,algorithmParameters);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			System.out.println("ERROR Initializing Cipher");
			e.printStackTrace();
			System.exit(0);
		};
		return cipher;
	}

	private static Cipher CipherInstance(){
		Cipher cipher = null;
		try {
			//cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Your JVM does not Support AES/CBC Encryption");
			e.printStackTrace();
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			System.out.println("Your JVM does not Support PKCS5 Padding");
			e.printStackTrace();
			System.exit(0);
		}
		return cipher;
	}

	private static void CopyStream(InputStream is,
								   OutputStream os,
								   MessageDigest md,
								   long fileSize) throws IOException {
		System.out.println("Copying Streams");
		long pos = 0;
		long part = fileSize/100L;
		int percentage = 0;
		int updateInterval = 150;
		long nextUpdate = System.currentTimeMillis();
		String humanFileSize =  " of " + GetHumanSize(fileSize);


		while (pos < fileSize){
			int bufSize = (int)(fileSize - pos);
			if( (bufSize) > 16328 )
				bufSize = 16328;

			byte[] buffer = new byte[bufSize];
			int readSize = is.read(buffer);
			pos += readSize;
			if(readSize != buffer.length)
				buffer = Arrays.copyOf(buffer,readSize);

			os.write(buffer);
			md.update(buffer);
			if( nextUpdate < System.currentTimeMillis()){
				nextUpdate = System.currentTimeMillis() + updateInterval;
				percentage = (int)(pos/part);
				int parts = (int) ((50*pos)/fileSize);
				StringBuilder progressbar = new StringBuilder("[");
				for (int i = 0; i < 50; i++) {
					progressbar.append((i < parts)? '#' : ' ');
				}
				progressbar.append(']');
				AetherCLIUtil.CLS();
				System.out.println("%" + percentage + "\t" + GetHumanSize(pos) + humanFileSize );
				System.out.println(progressbar);
				//TODO add speed and progress bar
			}
		}
	}

	//Human readable file size. DOES NOT RETURN SIZE OF HUMAN
	public static String GetHumanSize(long fileSize) {
		String[] units = {"kb","mb","gb","tb","pb"};
		double radix = 1024;
		double size = ((double)fileSize)/radix ;
		int i;
		for (i = 1; i < units.length; i++) {
			if(size > radix){
				size = size/(long)radix;
			}else{
				break;
			}
		}
		i--;
		return String.format("%.2f",size) + units[i];

	}

}
