package org.dragonservers.Aether;

import org.dragonservers.enigma.*;

import java.io.IOException;
import java.net.ConnectException;
import java.security.GeneralSecurityException;

public class AetherInboxHandler implements Runnable{

	public boolean keep_Running = true;

	@Override
	public void run() {
		int errors = 0;
		while (keep_Running){
			EnigmaPacket ep = null;
			do {
				try {
					ep = Aether.turingConnection.GetPacket();
					//TODO handle loss of internet better
					errors = 0;
				} catch (ConnectException e){
					System.out.println("Connection Refused");
				}catch (IOException | GeneralSecurityException e) {
					e.printStackTrace();
					System.out.println("Failed to get Packets");
					errors++;
					if(errors > 5){
						keep_Running = false;
						System.out.println("Critical unrecoverable ERROR");
						break;
					}

				}
				if(ep != null)
					AetherPacketFactory.QueueIncomingPacket(ep);
			}while (ep != null);
			boolean rtr = true;
			while (rtr){
				try {
					rtr = AetherPacketFactory.HandleOutboundPackets();
					errors = 0;

				} catch (GeneralSecurityException | IOException e) {
					e.printStackTrace();
					System.out.println("Error While Sending Packet");
					errors++;
					if(errors > 5){
						keep_Running = false;
						System.out.println("Critical unrecoverable ERROR");
						break;
					}

				}
			}
			try {
				Thread.sleep(500);
			}catch (InterruptedException ignored){}
		}
		if(errors > 5)
			System.exit(-1);
	}
}