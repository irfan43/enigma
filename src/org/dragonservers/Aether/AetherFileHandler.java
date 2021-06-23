package org.dragonservers.Aether;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class AetherFileHandler {
	public final static Path server_ip_file = Path.of("Turing_server_ip.dat");
	public static String ReadServerIP() throws IOException {
		String rtr;
		if (!Files.exists(server_ip_file))
			throw new FileNotFoundException(" SERVER IP FILE NOT FOUND ");
		InputStreamReader fr = new
				InputStreamReader(Files.newInputStream(Path.of("Turing_server_ip.dat")));
		try(BufferedReader br = new BufferedReader(fr)){
			rtr = br.readLine();
		}
		return rtr;
	}
	public static void WriteServerIP(String ip) throws IOException {
		try(
			BufferedWriter bw = new BufferedWriter(
				new OutputStreamWriter(Files.newOutputStream(server_ip_file)))
		){
			bw.write(ip);
			bw.newLine();
		}

	}
}
