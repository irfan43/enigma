package org.dragonservers.enigma;

public class EngimaBackground implements Runnable{

	public  boolean keep_Running = true;

	@Override
	public void run() {

		while (keep_Running){

			//check EnigmaPackets
			EnigmaPacketFactory.HandleInboundPackets();
			try {
				Thread.sleep(500);
			}catch (InterruptedException ignored){}

		}
	}
}
