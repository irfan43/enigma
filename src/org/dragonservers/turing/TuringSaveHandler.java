package org.dragonservers.turing;

import java.io.IOException;
import java.util.logging.Level;

public class TuringSaveHandler implements Runnable {

	public static long previousSavesTime,timeBetweenSaves = 5*60;
	public final Object lockObject = new Object();
	public boolean saveNow = false;
	//replace with TimerTask with sechedule Fixed Rate
	@Override
	public void run() {
		previousSavesTime = System.currentTimeMillis()/1000L;
		while (Turing.DoSaveOP&&Turing.running){

			while (( (previousSavesTime + timeBetweenSaves) > (System.currentTimeMillis()/1000L) )&& (Turing.DoSaveOP&&Turing.running) ){
				//System.out.println(" Time " + System.currentTimeMillis() );
				//System.out.println(" Time to save " + (previousSavesTime + timeBetweenSaves) );
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				synchronized (lockObject){
					if(saveNow) {
						saveNow = false;
						break;
					}
				}
			}

			Save();
		}

	}
	public void Save()  {
		synchronized (lockObject) {

			previousSavesTime = System.currentTimeMillis()/1000L;
			Turing.TuringLogger.log(Level.INFO,"Saving Data Started");
			if (Turing.EUserFac.IO_Flag) {
				try {
					Turing.EUserFac.SaveData();
					Turing.EUserFac.IO_Flag = false;
				} catch (IOException e) {
					System.out.println("User Factory IO Error");
					e.printStackTrace();
				}
			}
			if (Turing.EnigmaInboxs.IO_Flag) {
				try {
					Turing.EnigmaInboxs.SaveData();
				} catch (IOException e) {
					System.out.println("User Inbox IO Error");
					e.printStackTrace();
				}
			}
			if (Turing.CodeFac.IO_Flag) {
				try {
					Turing.CodeFac.SaveData();
				} catch (IOException e) {
					System.out.println("Code Factory IO Error");
					e.printStackTrace();
				}
			}
			Turing.sesHandler.PurgeSessions();
			Turing.TuringLogger.log(Level.INFO,"Saving Data finished");
		}
	}
}
