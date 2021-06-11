package org.dragonservers.enigma.NetworkProtocol;

import java.nio.charset.StandardCharsets;

public class EnigmaBaseRequest {

	public static byte[] Sandwich(String body,String header){
		return Sandwich(body,header,header);
	}
	public static byte[] Sandwich(String body,String header,String footer){
		return (header + body + footer).getBytes(StandardCharsets.UTF_8);
	}
}
