package org.dragonservers.enigma;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class EnigmaBlock {
	public static String ReadBlockLine(InputStream dis) throws IOException {
		byte[] data = ReadBlock(dis);
		return new String(data, StandardCharsets.UTF_8);
	}
	public static void WriteBlockLine(String data, OutputStream dos) throws IOException {
		byte[] dataEncoded = data.getBytes(StandardCharsets.UTF_8);
		WriteBlock(dos,dataEncoded);
	}
	public static void WriteBlock(OutputStream dos, byte[] data) throws IOException{
		byte[] lengthEncoded = ByteBuffer.allocate(4).putInt(data.length).array();
		dos.write(lengthEncoded);
		dos.write(data);
	}
	public static byte[] ReadBlock(InputStream din) throws IOException {
		byte[] lengthEncoded = new byte[4];
		int resp = din.read(lengthEncoded);
		int length = ByteBuffer.wrap(lengthEncoded).getInt();
		if(resp == -1)
			throw new IOException("EOF file Reached Prematurely");
		if(length <= 0)
			throw new IOException("BAD Block Header");
		byte[] block = new byte[length];
		resp = din.read(block);
		if(resp == -1)
			throw new IOException("EOF file Reached Prematurely");
		return block;
	}

}
