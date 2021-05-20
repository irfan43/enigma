package org.dragonservers.enigma;

import java.io.Console;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class EnigmaCLI {
	public static final String ANSI_CLS = "\u001b[2J";
	public static final String ANSI_HOME = "\u001b[H";
	public static final String ANSI_BOLD = "\u001b[1m";
	public static final String ANSI_AT55 = "\u001b[10;10H";
	public static final String ANSI_REVERSEON = "\u001b[7m";
	public static final String ANSI_NORMAL = "\u001b[0m";
	public static final String ANSI_WHITEONBLUE = "\u001b[37;44m";
	public static final boolean IsWindows = System.getProperty("os.name").contains("Windows");


	public static void MainMenu(){
		try{
			LogIn();
		}catch (IOException | GeneralSecurityException e){
			//TODO fix this
			e.printStackTrace();
			System.out.println("Error While logging in");
			System.exit(-1);
		}
		while (true){
			CLS();
			System.out.println("\t== Enigma ==");
			System.out.println("\tQ - Quit");
			String resp = Enigma.scn.nextLine();
			if(resp.contains("quit") || resp.startsWith("q"))
				break;

		}
		//TODO any Save operation if needed
		CLS();
		System.out.println("=GOODBYE=");
	}

	private static void LogIn() throws IOException, GeneralSecurityException {
		System.out.println("Logging in....");
		Enigma.TuringConnection.LogIn();
	}

	public static void CLS(){
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
	public static char[] getPassword(Console con){
		char[] Pass;
		if(con != null) {
			Pass = con.readPassword();
		}else{
			String s = Enigma.scn.nextLine();
			Pass = s.toCharArray();
		}
		return Pass;
	}
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
}
