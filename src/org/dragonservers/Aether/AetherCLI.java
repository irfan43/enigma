package org.dragonservers.Aether;



import org.dragonservers.enigma.*;


import java.io.Console;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;

public class AetherCLI {
	public static final String ANSI_CLS = "\u001b[2J";
	public static final String ANSI_HOME = "\u001b[H";
	public static final String ANSI_BOLD = "\u001b[1m";
	public static final String ANSI_AT55 = "\u001b[10;10H";
	public static final String ANSI_REVERSEON = "\u001b[7m";
	public static final String ANSI_NORMAL = "\u001b[0m";
	public static final String ANSI_WHITEONBLUE = "\u001b[37;44m";
	public static final boolean IsWindows = System.getProperty("os.name").contains("Windows");

	public static Thread backgroundThread,EIHThread ;
	public static AetherBackground engimaBackgroundProcess;
	public static AetherInboxHandler aetherInboxHandler;

	public static void MainMenu(){
		try{
			LogIn();
			LoadFriendList();
			//TODO Check Inbox
		}catch (IOException | GeneralSecurityException | ClassNotFoundException e){
			//TODO fix this
			e.printStackTrace();
			System.out.println("Error While Starting Up");
			System.exit(-1);
		}

		StartBackgroundThread();
		try {
			while (true) {
				CLS();
				System.out.println("\t== Enigma ==");
				System.out.println("\tF - Friends");
				System.out.println("\tI - Inbound Request");
				System.out.println("\tS - Send a Request");

				System.out.println("\tQ - Quit");
				String resp = Aether.scn.nextLine().toLowerCase();
				if (resp.startsWith("q"))
					break;
				if(resp.length() > 0) {
					switch (resp.substring(0, 1)) {
						case "f" -> {
							DisplayFriends();
						}
						case "i" -> {
							DisplayInboundRequest();
						}
						case "s" -> {
							DisplayOutboundRequest();
						}
						default -> {
							System.out.println("Unknown Command " + resp);
						}
					}
				}
			}
		}catch (Exception e){
			System.out.println("We ran into a unexpected Exception ");
			e.getMessage();
			e.printStackTrace();
			Aether.scn.nextLine();
		}finally {
			//TODO any Save operation if needed
			engimaBackgroundProcess.keep_Running = false;
			aetherInboxHandler.keep_Running = false;
			EIHThread.interrupt();
			backgroundThread.interrupt();
		}
		try {
			System.out.println("Saving");
			AetherFriendManager.Save();
		} catch (GeneralSecurityException | IOException e) {
			System.out.println("Ran INTO error while Saving");
			e.printStackTrace();
			Aether.scn.nextLine();
		}
		CLS();
		System.out.println("=GOODBYE=");
	}

	private static void DisplayOutboundRequest() {
		CLS();
		System.out.println("Send a new introduction request? (y/n)");
		String resp = Aether.scn.nextLine().toLowerCase();
		while(resp.startsWith("y")){
			System.out.println("Enter Username:-");
			String username = Aether.scn.nextLine().toLowerCase(Locale.ROOT);
			PublicKey publicKey = null;
			try {
				publicKey = Aether.turingConnection.GetUserPublicKey(username);
			}catch (Exception e){
				System.out.println("Error While Trying to get Public Key From the Server");
				e.getMessage();
				e.printStackTrace();
			}
			if(publicKey == null){
				System.out.println("Error Username \"" + username + "\" Does not Exist" );
			}else {
				try {
					System.out.println("Public Key Got As:-" +
							Base64
								.getEncoder()
								.encodeToString(EnigmaCrypto.SHA256(publicKey.getEncoded())));
					System.out.println("Continue? (y/n)");
					String rep = Aether.scn.nextLine();
					if(rep.toLowerCase(Locale.ROOT).startsWith("y")){
						AetherPacketFactory.SendIntroductionToken(username,publicKey);
						System.out.println("Sent token to " + username );
					}else {
						System.out.println("Canceling..");
					}
				} catch (GeneralSecurityException | IOException e) {
					System.out.println("Error While Queue IntroToken ");
					e.printStackTrace();
				}
			}
			System.out.println("Send another?(y/n)");
			resp = Aether.scn.nextLine().toLowerCase();
		}

	}

	private static void DisplayInboundRequest() {
		boolean sentRequest = false;
		String sentUsername = "";
		Exception sendException = null;
		while (true) {
			CLS();
			if(sentRequest){
				System.out.println("Sent response to " + sentUsername);
				sentRequest = false;

			}
			if( sendException != null){
				System.out.println("Ran into Error While responding to " + sentUsername);
				System.out.println("Error:-" + sendException.getMessage());
				sendException.printStackTrace();
				sendException = null;
			}
			System.out.println("\t==Inbound Requests==");
			System.out.println("\tEnter A Number To reply to the request");
			System.out.println("\tThis will Start a Key X");
			String[] requestList = AetherFriendManager.GetRequestsList();
			PrintList(requestList);
			System.out.println("Q - Quit");
			String resp = Aether.scn.nextLine().toLowerCase();
			if(resp.contains("q"))
				break;
			int responseID = -1;
			try {
				responseID = Integer.parseInt(resp.trim());
			}catch (NumberFormatException e){
				System.out.println("Invalid input");
			}
			if(responseID > 0 && responseID <= requestList.length) {
				sentUsername = requestList[responseID - 1];
				System.out.println( "Confirm Send Request to " + sentUsername + "?" );
				System.out.print( "Type \"SEND\" to confirm:-" );
				String Confirmation = Aether.scn.nextLine();

				if(Confirmation.equals("SEND")){
					System.out.println("Responding to Request of " + sentUsername);
					try {
						AetherPacketFactory.SendIntroductionToken(sentUsername);
						System.out.println("Sent");
						sentRequest = true;
					} catch (GeneralSecurityException | IOException e) {
						sendException = e;
						System.out.println("Ran into ERROR Sending Token");
					}
				}
			}
		}
	}

	private static void DisplayFriends() {
		String header = "";
		while (true) {
			CLS();
			System.out.println(
					"\t==Friends List==\n" +
					"\tEnter A Number To Enter A chat with them\n" +
					"\tThis Excludes people yet to accept request\n" +
					"\tSelect a friend to message\n" +
					"\tNote:- After Opening a Chat window \n" +
					"\tUse !quit to exit that chat window\n" +
					"\tUse !help to see a list of commands\n" +
					"\tWe suggest You expand your terminal to display at least 40 lines\n"
			);
			List<String> friendsSet = AetherFriendManager.GetLatestFriendsList();
			String[] friends = new String[friendsSet.size()];
			friendsSet.toArray(friends);
			PrintList(friends);

			System.out.println("Q - Quit");
			System.out.print(header);
			System.out.print(":-");
			String resp = Aether.scn.nextLine().toLowerCase();
			if(resp.contains("q"))
				break;
			int responseID;
			try {
				responseID = Integer.parseInt(resp.trim());
			}catch (NumberFormatException e){
				responseID = -2;
			}
			if(responseID > 0 && responseID <= friends.length){
				try {
					AetherFriendManager.OpenMessageWindow(friends[responseID - 1]);
				} catch (GeneralSecurityException | IOException | ClassNotFoundException e) {
					header = "Error Occurred While Opening Message Window\nERROR:-";
					header += e.getMessage();
					header += e.getStackTrace();
				}
			}else {
				header = "Invalid Input\n";
			}

		}
	}

	private static void PrintList(String[] usernames){
		for (int i = 0; i < usernames.length; i++) {
			try {
				System.out.println( (i + 1) + ":" +
						AetherFriendManager.RenderName(usernames[i]) );
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Security Error SHA256 not supported");
				e.printStackTrace();
			}
		}
		if(usernames.length == 0){
			System.out.println("WOW you have 0 request");
			System.out.println("You must be lonely");
		}
	}

	private static void StartBackgroundThread() {
		engimaBackgroundProcess = new AetherBackground();
		backgroundThread = new Thread(engimaBackgroundProcess);
		backgroundThread.start();
		aetherInboxHandler = new AetherInboxHandler();
		 EIHThread = new Thread(aetherInboxHandler);
		EIHThread.start();
	}

	private static void LogIn() throws IOException, GeneralSecurityException {
		System.out.println("Logging in....");
		Aether.turingConnection.LogIn();
		System.out.println("Logged IN");


	}
	private static void LoadFriendList() throws GeneralSecurityException, IOException, ClassNotFoundException {
		System.out.println("Loading Friend List...");

		if(AetherFriendManager.IsFileMissing()){
			System.out.println("NO Friend List Found");
			System.out.println("Create New Friend List?(Y/N)");
			String resp = Aether.scn.nextLine();
			if(!resp.toLowerCase().startsWith("y")){
				System.out.println("Please Replace the Friend List File to continue\n");
				System.exit(0);
			}
			System.out.println("Creating New empty Friend list");
			AetherFriendManager.InitialiseNewFile();
		}else {
			AetherFriendManager.Load();
		}
	}

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
