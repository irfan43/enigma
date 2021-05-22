package org.dragonservers.enigma;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class EnigmaInboxHandler implements Runnable{

	public boolean keep_Running = true;

	@Override
	public void run() {

		while (keep_Running){
			EnigmaPacket ep = null;
			do {
				try {
					ep = Enigma.TuringConnection.GetPacket();
				} catch (IOException | GeneralSecurityException e) {
					e.printStackTrace();
					System.out.println("Failed to get Packets");
				}
				if(ep != null)
					EnigmaPacketFactory.QueueIncomingPacket(ep);
			}while (ep != null);
			boolean rtr = true;
			while (rtr){
				try {
					rtr = EnigmaPacketFactory.HandleOutboundPackets();
				} catch (GeneralSecurityException | IOException e) {
					e.printStackTrace();
					System.out.println("Error While Sending Packet");
				}
			}
			try {
				Thread.sleep(800);
			}catch (InterruptedException ignored){}
		}
	}
}