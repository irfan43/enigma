package org.dragonservers.Aether;

import org.dragonservers.enigma.EnigmaCrypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.Console;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class AetherCLIUtil {
	public static final boolean IsWindows = System.getProperty("os.name").contains("Windows");

	public static void CLS(){
		//System.out.println("Cleared");
		if(IsWindows){
			try {
				new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
			} catch (InterruptedException | IOException e) {
				e.printStackTrace();
				System.out.println("Error While Trying to Clear Console");
			}
		}else {
			System.out.print("\033[H\033[2J");
			System.out.flush();
		}
	}

	@Deprecated
	public static String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();
		int len = block.length;
		for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len-1) {
				buf.append(":");
			}
			if(i%32 == 31)buf.append("\n");
		}
		return buf.toString();
	}

	private static void byte2hex(byte b, StringBuffer buf) {
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		int high = ((b & 0xf0) >> 4);
		int low = (b & 0x0f);
		buf.append(hexChars[high]);
		buf.append(hexChars[low]);
	}

	static void consoleRawInputTest(){
		System.out.println("DEBUG TOOL RAW CHAR INPUT" +
				"\n CTRL + C to Exit ie resp code 3\n");
		int resp= -1;
		while (resp != 3){
			try {
				resp = RawConsoleInput.read(false);
			} catch (IOException e) {
				System.out.println("Error while reading from raw");
				e.printStackTrace();
			}
			if(resp >= 0){
				System.out.println("code:-" +  resp);
			}
		}
		try {
			RawConsoleInput.resetConsoleMode();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Deprecated because does not use a PBKDF
	 * @return
	 */
	@Deprecated
	public static byte[] getPasswordHash(){
		char[] pass = getPassword(System.console());
		byte[] hash = new byte[0];
		try {
			hash = EnigmaCrypto.SHA256(pass);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("your JVM does not support SHA256 Algo");
			e.printStackTrace();
			System.exit(0);
		}
		Arrays.fill(pass,'\0');
		return hash;
	}


	public static byte[] singlePassword(){
		System.out.print("Password :-");
		return getPasswordHash();
	}
	public static byte[] confirmPassword(){
		byte[] hash;
		byte[] confirmHash;
		boolean wrong = false;
		do {
			CLS();
			if(wrong)
				System.out.println("Passwords did not Match");

			hash 		= singlePassword();
			System.out.print("Confirm");
			confirmHash = singlePassword();

			wrong = true;
		}while (!Arrays.equals(hash,confirmHash));

		Arrays.fill(confirmHash,(byte)0x00);
		return hash;
	}

	public static SecretKey getSecretKeyFromChar(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// use the "PKCS#5" or "PBE" SecretKeyFactory to convert the password
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec specs = new PBEKeySpec(
				password,
				salt,
				1024,
				256
		);
		return kf.generateSecret(specs);
	}
	public static SecretKey getSecretKeyFromConsole(Console con,boolean confirm,byte[] salt) throws GeneralSecurityException {
		char[] password;
		char[] passwordConfirm = {};

		do{
			System.out.println("Password:-");
			password = getPassword(con);
			if(confirm){
				System.out.println("Confirmation \nPassword:-");
				passwordConfirm = getPassword(con);
			}
		}while (confirm && !Arrays.equals(passwordConfirm,password));

		Arrays.fill(passwordConfirm, '\0');

		return getSecretKeyFromChar(password,salt);
	}

	public static String SoftWrap(String input, int wall){
		StringBuilder sb = new StringBuilder();
		while (input.length() > wall) {
			sb.append(input, 0, wall);
			sb.append("\n");
			input = input.substring(wall);
		}
		sb.append(input);
		return sb.toString();
	}

	public static char[] getPassword(Console con){
		char[] Pass;
		if(con != null) {
			Pass = con.readPassword();
		}else{
			String s = Aether.scn.nextLine();
			Pass = s.toCharArray();
		}
		return Pass;
	}
}
