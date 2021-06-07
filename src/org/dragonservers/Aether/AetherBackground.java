package org.dragonservers.Aether;

public class AetherBackground implements Runnable{

	public  boolean keep_Running = true;

	@Override
	public void run() {

		while (keep_Running){

			//check EnigmaPackets
			AetherPacketFactory.HandleInboundPackets();
			try {
				Thread.sleep(500);
			}catch (InterruptedException ignored){}

		}
	}
}
