package org.dragonservers.enigma;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EnigmaEncryptionCLI {

	public static void Take(String[] args){
		while(true) {
			System.out.println("Menu");
			System.out.println("E - Encrypt File");
			System.out.println("D - Decrypt File");
			System.out.println("Q - Quit");

			String Response = Enigma.scn.nextLine();
			switch (Response) {
				case "Q":
				case "q":
					return;
				case "d":
				case "D":
					Decrypt();
					break;
				case "E":
				case "e":
					Encrypted();
					break;
			}
		}
	}

	private static void Encrypted()  {


		String FileName = "y";
		List<File> ToEncrypt = new ArrayList<>();
		while(FileName.toLowerCase().startsWith("y")){
			System.out.println("Enter File name to be encrypted:");
			FileName = Enigma.scn.nextLine();

			File tmp = new File(FileName);
			ToEncrypt.add(tmp);
			System.out.println("Add Another File? (yes/no)");
			FileName = Enigma.scn.nextLine();
		}

		//asks for password
		char[] Password;
		while (true){
			char[] Password2;
			System.out.println("Enter Password:-");
			Password = EnigmaCLI.getPassword(System.console());
			System.out.println("Confirm Password:-");
			Password2 = EnigmaCLI.getPassword(System.console());
			if(Arrays.equals(Password,Password2)){
				Arrays.fill(Password2,'\0');
				break;
			}
			System.out.println("Passwords do not match, Try again");
		}
		//generate the hash so we can get rid of the password as fast as possible
		byte[] hash;
		try {
			hash = EnigmaCrypto.SHA256(Password);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("HASH OF PASSWORD FAILED");
			e.printStackTrace();
			return;
		}
		Arrays.fill(Password,'\0');

		System.out.println("Enter File Name to save your Encrypted Package:-");
		String OutFileName = Enigma.scn.nextLine() + ".crypt";

		File[] Set = new File[ToEncrypt.size()];
		for (int i = 0; i < ToEncrypt.size(); i++) {
			Set[i] = ToEncrypt.get(i);
		}
		System.out.println("Encryption Running with \n Key  = " + EnigmaCLI.toHexString(hash));
		try {
			EnigmaFile.EncryptFile( Set,hash,OutFileName);
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}


	}

	private static void Decrypt() {
		String DestFileName,CryptFileName;
		char[] Password;

		System.out.println(" Destination Directory:-");
		DestFileName = Enigma.scn.nextLine();
		System.out.println(" Package FileName:-");
		CryptFileName = Enigma.scn.nextLine();
		System.out.println( "Password");
		//char[] pass = System.console().readPassword();
		Password = EnigmaCLI.getPassword(System.console());
		try {
			byte[] hash = EnigmaCrypto.SHA256(Password);
			Arrays.fill(Password,'\0');
			System.out.println("Running Decryption...\n Key = " + EnigmaCLI.toHexString(hash));
			EnigmaFile.DecryptFile(new File(CryptFileName),DestFileName,hash);
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}


}
