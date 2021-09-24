package org.dragonservers.turing;



public class TuringSQL {

	public static void AddRegistrationCode(RegistrationCode registrationCode){

	}
	public static boolean redeemRegistrationCode(String Code){
		return false;
	}

	public static void resetRegistrationCode(String Code){

	}


	public static void AddNewUser(String username, byte[] PublicKey, byte[] passwordHash){

	}

	public static String GetUsername(byte[] PublicKey){
		return null;
	}

	public static byte[] GetPublicKey(String username){
		return null;

	}

	public static void QueuePacket(byte[] packet,byte[] publicKey){

	}

}
