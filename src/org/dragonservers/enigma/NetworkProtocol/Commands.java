package org.dragonservers.enigma.NetworkProtocol;

public class Commands {


	public final static String RegistrationCommand 			= "RGS";
	public final static String LoginCommand 				= "LOGIN";
	public final static String GetPacketCommand 			= "GET PACKET";
	public final static String SendPacketCommand 			= "PUT PACKET";
	public final static String LogoutCommand 				= "LOGOUT";
	public final static String GetHistoryCommand 			= "GET HISTORY";
	public final static String GetUserPublicKeyCommand 		= "GET KEY";
	public final static String GetUsernameCommand 			= "GET USERNAME";

	public static final String UsernameKey					= "username";
	public static final String PasswordKey 					= "password";
	public static final String PublicKeyKey 				= "public-key";
	public static final String RegCodeKey 					= "reg-code";
	public static final String SignatureKey 				= "sign";
	public static final String SearchUsernameKey 			= "search-name";
	public static final String SearchPublicKeyKey 			= "search-key";

	public static final String ObjectNotFound 				= "NOT_FOUND";



}
