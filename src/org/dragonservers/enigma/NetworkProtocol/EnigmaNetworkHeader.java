package org.dragonservers.enigma.NetworkProtocol;

import java.util.*;

public class EnigmaNetworkHeader {
	private String header = "";
	private String[] Keys = new String[]{};
	private String[] Values = new String[]{};

	private static final char Separator = ':';

	//TODO rewrite this

	public EnigmaNetworkHeader(String Text){
		UpdateHeader(Text);
	}
	public EnigmaNetworkHeader(){
	}


	private void ParseHeader(){
		List<String> keys = new ArrayList<>();
		List<String> vals = new ArrayList<>();

		String[] lines = header.split("\n");
		for(String line: lines){
			String[] s;
			if((s = SplitOnSeparator(line)) != null) {
				keys.add(s[0]);
				vals.add(s[1]);
			}
		}
		keys.addAll(Arrays.asList(Keys));
		vals.addAll(Arrays.asList(Values));

		Keys = keys.toArray(Keys);
		Values = vals.toArray(Values);

	}

	private void SortList(){
		String[] SortedKeys = Keys.clone();
		String[] SortedValues = new String[Values.length];
		Arrays.sort(SortedKeys);
		for (int i = 0; i < Keys.length; i++) {
			int idx = Arrays.binarySearch(SortedKeys, Keys[i]);
			SortedValues[idx] = Values[i];
		}
		Keys = SortedKeys;
		Values = SortedValues;
	}

	public String GetHeader(boolean Random){
		StringBuilder Header = new StringBuilder();
		String[] myKeys = Keys.clone();
		String[] myValues = Values.clone();
		if(Random){
			RandomiseKeys(myKeys,myValues);
		}
		for (int i = 0; i < Keys.length; i++) {
			Header.append(myKeys[i]);
			Header.append(Separator);
			Header.append(myValues[i]);
			Header.append("\n");
		}

		return Header.toString();
	}

	private void RandomiseKeys(String[] keys, String[] vals) {
		Random random = new Random();
		for (int i = 0; i < keys.length; i++) {
			int swap = random.nextInt(keys.length);
			ArraySwap(keys,i,swap);
			ArraySwap(vals,i,swap);
		}
	}

	private void ArraySwap(String[] Array,int index1,int index2){
		String tmp = Array[index1];
		Array[index1] = Array[index2];
		Array[index2] = tmp;
	}
	public void UpdateHeader(String Text){
		header += Text;
		ParseHeader();
		header = "";
		SortList();
	}

	public String GetValue(String key){
		if(Keys == null)
			throw new NullPointerException();
		int idx = Arrays.binarySearch(Keys,key);
		if(idx < 0)
			throw new IllegalArgumentException("Bad Key");

		return Values[idx];
	}
	public String[] getKeys(){
		return Keys;
	}
	public void SetValue(String key,String value){
		int idx = Arrays.binarySearch(Keys,key);
		if(idx < 0){
			UpdateHeader( key + Separator + value);
		}else{
			Values[idx] = value;
		}
	}

	//Util
	public static String[] SplitOnSeparator(String Combined){
		String[] rtr = null;
		int sep = FindSeparator( Combined);
		if(sep != -1){
			rtr = new String[2];
			rtr[0] = Combined.substring(0,sep);
			rtr[1] = Combined.substring(sep + 1);
		}
		return rtr;
	}
	public static int FindSeparator(String txt){
		for (int i = 0; i < txt.length(); i++)
			if(Separator == txt.charAt(i))return i;
		return  -1;
	}

}
