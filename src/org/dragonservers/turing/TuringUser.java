package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.enigma.NetworkProtocol.EnigmaRegistrationRequest;

import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class TuringUser extends EnigmaUser implements Serializable{

	public final transient 	Object 				lockObject = new Object();
	private transient 		Socket 				sock;
	private transient 		InputStream 		is;
	private transient 		OutputStream 		os;
	private transient 		BufferedWriter  	bw;
	private transient 		BufferedReader  	br;

	public TuringUser(String username, PublicKey pbk, byte[] passwordHash) {
		super(username, pbk, passwordHash);
	}

	public TuringUser(EnigmaRegistrationRequest registrationRequest) throws NoSuchAlgorithmException {
		super(registrationRequest.uname, registrationRequest.publicKey, GenerateServerHash(registrationRequest.passwordHash) );
	}

	public void hookPacketListener(Socket socket, InputStream inputStream, OutputStream outputStream) throws IOException {
		synchronized (lockObject) {
			closeSocket();
			sock 	= socket;
			is 		= inputStream;
			os 		= outputStream;
			br		= new BufferedReader(new InputStreamReader(is));
			bw 		= new BufferedWriter(new OutputStreamWriter(os));

			bw.write("GOOD HOOK\n\n");
		}

		if(pullInbox())sock.close();
	}

	private boolean pullInbox() {
		EnigmaPacket enigmaPacket;
		boolean failed;
		do{
			enigmaPacket = Turing.EnigmaInboxs.CheckInbox(getPublicKey().getEncoded());
			failed = pushPacketToStream(enigmaPacket);
		}while (enigmaPacket != null && !failed);
		return failed;
	}

	public boolean SendPacket(EnigmaPacket enigmaPacket) throws IOException {
		boolean success;
		verifyPacket(enigmaPacket);
		synchronized (lockObject) {
			if(pushPacketToStream(enigmaPacket)) {
				sock.close();
				success = Turing.EnigmaInboxs.queuePacket(enigmaPacket);
			}else{
				success = true;
			}
		}
		return success;
	}


	private boolean pushPacketToStream(EnigmaPacket enigmaPacket) {
		boolean failed = false;
		if(IsOnline()){
			try {
				bw.write("NEW\n\n");
				EnigmaBlock.WriteBlock(os,enigmaPacket.EncodedBinary);

				failed = br.readLine().equals("OK");
			}catch (Exception e){
				failed = true;
			}
		}
		return failed;
	}

	public boolean IsOnline(){
		return !(sock == null || sock.isClosed());
	}

	private void closeSocket(){
		if(IsOnline()) {
			try {
				sock.close();
			} catch (IOException e) {
				//TODO add logger log
			}
			sock = null;
		}
	}
	private void verifyPacket(EnigmaPacket enigmaPacket){
		if (!Arrays.equals(
				enigmaPacket
						.getToAddr()
						.getEncoded(),
				PubKey.getEncoded())
		)
			throw new IllegalArgumentException();
	}
}
