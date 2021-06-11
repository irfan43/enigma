package org.dragonservers.enigma.NetworkProtocol;

public class Commands {


	public final static String RegistrationCommand = "RGS";
	public final static String LoginCommand = "LOGIN"; //Equivalent to login
	public final static String GetPacketCommand = "GET PACKET";
	public final static String SendPacketCommand = "SEND PACKET";
	public final static String LogoutCommand = "LOGOUT";
	public final static String GetHistoryCommand = "GET HISTORY";
	public final static String GetUserPublicKeyCommand = "GET PUBLICKEY";
	public final static String GetUsernameCommand = "GET USERNAME";

	public static final String UsernameKey			= "username";
	public static final String PasswordKey 			= "password";
	public static final String PublicKeyKey 		= "publicKey";
	public static final String RegCodeKey 			= "regCode";
	public static final String SignatureKey 		= "sign";
	public static final String SearchUsernameKey 	= "searchUsername";
	public static final String SearchPublicKeyKey 	= "searchPublicKey";


}
