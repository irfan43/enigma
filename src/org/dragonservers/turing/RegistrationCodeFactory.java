package org.dragonservers.turing;

import org.dragonservers.enigma.EnigmaTime;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;

public class RegistrationCodeFactory {



	public final int ExpireOneHour = 60*60, ExpireOneDay = 24*ExpireOneHour,ExpireOneWeek = 7*ExpireOneDay;
	private HashMap<String,RegistrationCode> CodeMap;
	//TODO move this to a hashmap instead of binary search
	//TODO add IO_Flag and Save data calls
	private final Object lockObject = new Object();
	public boolean IO_Flag = false;
	public RegistrationCodeFactory() throws IOException, ClassNotFoundException {
		if( Files.isRegularFile(Path.of(Turing.ShadowCodeFile)) ){
			LoadData();
		}else {
			CodeMap = new HashMap<>();
			if(!Files.exists(Path.of(Turing.ShadowCodeFile).getParent()))
				Files.createDirectories(Path.of(Turing.ShadowCodeFile).getParent());
			SaveData();
		}
	}

	/**
	 * @param code The code you want to mark as unused
	 *
	 * @return true if Code exist in this Code Factory, returns false if the code is not valid or does not exist
	 *
	 */
	public boolean MarkUnused(String code) {
		boolean result = false;
		String clean_code = RegistrationCode.GetCleanString(code);
		if (clean_code != null) {
			synchronized (lockObject) {
				RegistrationCode rc = CodeMap.get(clean_code);
				result = rc != null;
				if (result) {
					rc.MarkUnused();
					IO_Flag = true;
				}
			}
		}
		return result;
	}
	public boolean Redeem(String code){
		String clean_code = RegistrationCode.GetCleanString(code);
		boolean Success = false;

		if(clean_code != null) {
			synchronized (lockObject) {
				RegistrationCode rc = CodeMap.get(clean_code);
				if (rc != null) {
					Success = rc.redeem();
					IO_Flag = true;
				}
			}
		}
		return Success;
	}
	//function generates a Shadow Code adds it to the list and then returns that object
	public RegistrationCode GenerateCode() throws IOException {
		// defaults to a 1 day Expiry
		return GenerateCode(ExpireOneDay);
	}
	public RegistrationCode GenerateCode(int expiry) throws IOException {
		if( expiry > ExpireOneWeek )
			throw new IllegalArgumentException("Bad Expiry Value, Expiry Can not be greater the 1 week or 604800 seconds");
		if( expiry < 0)
			throw new IllegalArgumentException("Bad Expiry Value, Expiry can not be less then 0");
		//Expiry states the number of seconds till the code is considered expired
		long nowTime = EnigmaTime.GetUnixTime();

		RegistrationCode rtr = new RegistrationCode( nowTime + (long)expiry);
		synchronized (lockObject) {
			IO_Flag = true;
			CodeMap.put(rtr.GetCleanCode(), rtr);
		}
		return rtr;
	}
	public void SaveData() throws IOException {
		HashMap<String,RegistrationCode> copy_CodeMap;
		synchronized (lockObject){
			copy_CodeMap = CodeMap;
			IO_Flag = false;
		}
		FileOutputStream fos = new FileOutputStream(Turing.ShadowCodeFile);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(copy_CodeMap);
		oos.close();
		fos.close();
	}
	public void LoadData() throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(Turing.ShadowCodeFile);
		ObjectInputStream ois = new ObjectInputStream(fis);
		synchronized (lockObject){
			CodeMap = (HashMap<String, RegistrationCode>) ois.readObject();
		}
		ois.close();
		fis.close();
	}

	//TODO function to purge codes 1 month expired
}
