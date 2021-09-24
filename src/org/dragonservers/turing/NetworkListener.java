package org.dragonservers.turing;


import java.net.ServerSocket;

public class NetworkListener implements Runnable{


	public ServerSocket serverSocket;
	public boolean shutdown;
	public final Object lock = new Object();

	@Override
	public void run() {
		
	}
}
