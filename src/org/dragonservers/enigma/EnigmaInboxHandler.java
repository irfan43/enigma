package org.dragonservers.enigma;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class EnigmaInboxHandler implements Runnable{

	public boolean keep_Running = true;

	@Override
	public void run() {
		int errors = 0;
		while (keep_Running){
			EnigmaPacket ep = null;
			do {
				try {
					ep = Enigma.TuringConnection.GetPacket();
					//TODO handle loss of internet

				} catch (IOException | GeneralSecurityException e) {
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
					EnigmaPacketFactory.QueueIncomingPacket(ep);
			}while (ep != null);
			boolean rtr = true;
			while (rtr){
				try {
					rtr = EnigmaPacketFactory.HandleOutboundPackets();
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
				Thread.sleep(800);
			}catch (InterruptedException ignored){}
		}
		if(errors > 5)
			System.exit(-1);
	}
}