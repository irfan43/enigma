package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaCrypto;
import org.dragonservers.enigma.EnigmaKeyHandler;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class PublicKeyMiner implements Runnable {

	private String searchString;
	private String currentSearch;
	int HighestScore = 0;//how many chars in the search string has been found
	private int thrdID;

	public PublicKeyMiner(String findString,int id){
		searchString = findString;
		thrdID = id;
	}

	private void updateCheckString(){
		synchronized (PublicKeyExecuter.lockHS){
			HighestScore = PublicKeyExecuter.currentHighestScore;
		}
		currentSearch = searchString.substring(0,HighestScore);
	}
	private boolean checkIfB64Valid(String testingString){
		updateCheckString();
		int score = PublicKeyExecuter.GetStringScore(
				testingString,searchString,HighestScore);
		if(score > HighestScore){
			synchronized (PublicKeyExecuter.lockHS){
				if(PublicKeyExecuter.currentHighestScore < score){
					PublicKeyExecuter.currentHighestScore = score ;
				}
			}
		}
		return score == -1;
	}

	@Override
	public void run() {
		int hashCount = 0;
		currentSearch = searchString.substring(0,1);
		while(PublicKeyExecuter.threadsDoHash) {
			try {
				KeyPair kp = EnigmaKeyHandler.RSAGenerateKeypair();
				String b64 = Base64.getEncoder().encodeToString(
						EnigmaCrypto.SHA256(kp.getPublic().getEncoded()));
				hashCount++;
				if (b64.toUpperCase().contains(currentSearch)) {
					if(checkIfB64Valid(b64.toUpperCase())) {
						System.out.println("[Thread" + thrdID + "]Found " + currentSearch + "  " + b64 + " score " +
								PublicKeyExecuter.GetStringScore(b64.toUpperCase(),searchString.toUpperCase(),1));
						synchronized (PublicKeyExecuter.lockKeyPairs) {
							PublicKeyExecuter.goodKeyPairs.add(kp);
						}
					}
				}
				if (hashCount > 100) {
					synchronized (PublicKeyExecuter.lockHashes) {
						PublicKeyExecuter.hashes += hashCount;
					}
					hashCount = 0;
					updateCheckString();
				}

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
	}
}
