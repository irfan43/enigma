package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaCrypto;
import org.dragonservers.enigma.EnigmaFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PublicKeyExecuter {

	public static List<KeyPair> goodKeyPairs = new ArrayList<>();
	public static long hashes;
	public static int currentHighestScore = 1;
	public static ExecutorService HashingPool;
	public static final Object lockHashes = new Object(),
			lockKeyPairs = new Object(),lockHS = new Object();
	public static boolean threadsDoHash = true;

	public static int GetStringScore(String testingString,String toFind,int hs){
		//calculate once, don't keep calculating the len and slow code down
		int len = toFind.length();
		int i;
		for (i = hs; i < len; i++) {
			String subSearch = toFind.substring(0,i);
			if(!testingString.contains(subSearch))
				break;
		}
		if(i == hs)
			return -1;
		else
			return i - 1;
	}
	//TODO redo this buggy mess
	public static void GenerateKeyPairBruteForce(String[] args)  {
		Scanner scn = new Scanner(System.in);
		System.out.println("Enter Password:-");
		String password = scn.nextLine();
		System.out.println("Running with Password \"" + password + "\"");
		byte[] hash = new byte[0];
		try{
			Files.createDirectories(Path.of("GoodPublicKeys"));
			hash = EnigmaCrypto.SHA256(password);
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
			System.exit(0);
		}

		int gotN = 0;
		int BestPos = 1000;
		int pos;
		long LastReport = System.currentTimeMillis()/1000L;
		long numberAttempts = 0;

		System.out.println("Enter the String to Find");
		String searchString  = scn.nextLine().toUpperCase();
		System.out.println("Number of threads:-");
		int threadCount = Integer.parseInt(scn.nextLine());
		System.out.println("Finding " + searchString + " using " + threadCount + " Threads");

		long start_time = System.currentTimeMillis()/1000L;

		synchronized (lockHS){
			currentHighestScore = 1;
		}

		HashingPool = Executors.newFixedThreadPool(threadCount);
		for (int i = 0; i < threadCount; i++) {
			PublicKeyMiner pkm = new PublicKeyMiner(searchString,i);
			HashingPool.execute(pkm);
		}
		int lhs = 1;

		while (true){
			KeyPair kp = null;
			synchronized (lockKeyPairs){
				if(!goodKeyPairs.isEmpty()){
					kp = goodKeyPairs.remove(0);
				}
			}
			if(kp != null) {
				try {
					gotN++;
					String b64 = Base64.getEncoder()
							.encodeToString(
									EnigmaCrypto.SHA256(kp.getPublic().getEncoded()))
							.toUpperCase();
					int score = GetStringScore( b64,searchString ,1 );



					String curSS =  searchString.substring(0,score);
					pos = b64.indexOf( curSS );
					if (pos != -1) {
						System.out.println("Saving " + curSS + " " + b64 + " score " + score);
						Files.createDirectories(Path.of("GoodPublicKeys", curSS));
						EnigmaFile.SaveKeyPair(
								Path.of("GoodPublicKeys/" + curSS,
										curSS + "-Key" + gotN + "p" + pos + ".kpr"),
								kp, false, hash,"SERVER");
					}else {
						System.out.println("Got -1");
					}

				} catch (IOException | GeneralSecurityException e) {
					e.printStackTrace();
				}
			}

			if((LastReport + 5) < System.currentTimeMillis()/1000L  ){
				long CurrentNHashes;
				synchronized (lockHashes) {
					CurrentNHashes = hashes;
					hashes = 0;
				}
				numberAttempts += CurrentNHashes;
				System.out.println("\t== Progress Report ==");
				System.out.print("Attempts        = ");
				if(numberAttempts > 1000000){
					System.out.println((numberAttempts / 1000000F) + "Mhs");
				}else {
					System.out.println((numberAttempts / 1000) + "Khs");
				}
				System.out.println("Hash Rate       = " + ( CurrentNHashes)/5 + "H/s");
				System.out.println("Best Position   = " + BestPos );
				System.out.println("GotN            = " +  gotN);

				LastReport = System.currentTimeMillis()/1000L;
				int hs;
				synchronized (lockHS){
					hs = currentHighestScore;
				}
				if(hs == searchString.length())
					break;
			}

		}
		threadsDoHash =false;
		long Time_Taken = (System.currentTimeMillis()/1000L - start_time);
		System.out.println("Found in " + Time_Taken + "seconds");
		System.exit(0);
	}
}
