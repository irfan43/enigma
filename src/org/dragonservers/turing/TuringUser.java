package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaBlock;
import org.dragonservers.enigma.EnigmaPacket;
import org.dragonservers.enigma.EnigmaUser;
import org.dragonservers.enigma.NetworkProtocol.EnigmaRegistrationRequest;

import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

public class TuringUser extends EnigmaUser implements Serializable{

	public transient boolean online = false;
	public final transient Object lockObject = new Object();
	private transient InputStream is;
	private transient OutputStream os;
	private transient BufferedWriter bw;
	public TuringUser(String username, PublicKey pbk, byte[] passwordHash) {
		super(username, pbk, passwordHash);
	}

	public TuringUser(EnigmaRegistrationRequest registrationRequest) {
		super(registrationRequest.uname, registrationRequest.publicKey, registrationRequest.passwordHash);
	}

	public void ListenPacket(OutputStream outputStream,InputStream inputStream){
		synchronized (lockObject) {
			if (!online) {
				is = inputStream;
				os = outputStream;
				bw = new BufferedWriter(new OutputStreamWriter(os));
				online = true;
			} else
				throw new IllegalArgumentException("Already Logged In");
		}
	}
	public void SendPacket(EnigmaPacket enigmaPacket){
		if (!Arrays.equals(
				enigmaPacket.getToAddr().getEncoded()
				, PubKey.getEncoded())) {
			throw new IllegalArgumentException();
		}
		synchronized (lockObject) {
			if (online) {
				try {
					bw.write("NEW");
					EnigmaBlock.WriteBlock(os,enigmaPacket.EncodedBinary);
				} catch (IOException e) {
					online = false;
					try {
						bw.close();
					} catch (IOException ioException) {
						ioException.printStackTrace();
					}
				}
			}
			if(!online){
				Turing.EnigmaInboxs.SendPacket(enigmaPacket);
			}
		}
	}

}
