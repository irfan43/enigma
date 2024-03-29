server


Encrypting a file,
	a .crypt file holds the list of files present with in it self
		[] <- denotes a block of which the first 4 bytes tells the length of the block

	encryption starts half way through the header, this prevents reveal the first 12 bytes of the key while masking the number of files present
	HEADER-> 8byte signiture, 4 byte version, /\ Encryption starts here /\  4 bytes number of files present  // Signiture decimal 29 8 20 14 23 6 19 54 hex 1d 08 14 0E 17 06 13 36

	[location of file + name example Folder1/folder2/Image.png]
	[Binary of that file] // note first 8 bytes not 4 denote long for length (to allow for files larger then 2gb)
	2 block pairs denote a single file. name then Binary
	multiple files can be listed as well as full directories

	[sha256 hash]
	terminated with sha256 hash

	note every single bit including the sha256 hash is XOR Encrypted with the given key

function/commands
	register username
		username, Public Key, sign-up-invite-code, sha256(invite-code) only-signature
		return
			aknowledment , Public Keys
		#if bad invite code
			403, bad-invite-code;
		send
			Encrypted(sha256("%En!gm@" + password + "%En!gm@"))

	login request
		username, public key
		return
			UTC time signed by the server (server time - our time < 60s )
		send
			username,password(double terminated double hash with utc time),
		return
			a random 1kb bin
		send
			signiture of prevatious bin
	request server time
		return UTC time with signature
	send_packet
		send packet  [bin] to public key [your signiture]
		returns AKN sha hash  with server signature
	return_inbox





Feature

Encrypt File's to be sent to someone over Pendrive or other medium
sign the file as well

server-Structure
	List of user objects (later make this a hashmap with the public key as a key)




//old code
/*
    private static void TestTyping(){
        //tests the typing notification
        String[] messages = new String[]{
                "Hey " ,
                "Enigma Messaging Services" ,
                "this is a demo of the typing notification on the CLI interface on" ,
                "Let me know if there are any problems u have with the interface or improvements u can make " ,
                "Thanks Indus" };
        String User = "indus";

        for (int i = 0; i < messages.length; i++) {
            String Msg = PrintBlock(Arrays.copyOfRange(messages,0,i),User);
            for (int j = 0; j < 5; j++) {
                TypingAnimation(Msg,User);
            }
        }
    }

    private static void TypingAnimation(String msg,String User) {
            EnigmaCLI.CLS();
            System.out.print(msg);
            System.out.print("[" + User + "]" + "Typing");
            for (int j = 0; j < 3; j++) {
                System.out.print(".");
                try {
                    Thread.sleep(70);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

    }
    private static String PrintBlock(String[] messages, String user) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < messages.length; i++)
            sb.append(PrintMessage(user,messages[i] ));
        return sb.toString();
    }
    private static String PrintMessage(String username,String msg){
       return ("[" + username + "]" + msg + "\n");
    }
*/
/*
	  private static void EncryptFileCLI() {
		  System.out.println("Decrypt or Encrypt? (D/E)");
		  String s = scn.nextLine();
		  if(s.equalsIgnoreCase("d")){
			  System.out.println("enter the name of the file to decrypt?");
			  String Filename = scn.nextLine() + ".crypt";
			  try {
				  DecryptFile(Filename,SharedSct);
			  } catch (IOException e) {
				  e.printStackTrace();
			  }
		  }else if(s.equalsIgnoreCase("e")){
			  System.out.println("enter the name of the file to encrypt?");
			  String Filename = scn.nextLine() ;
			  try {
				  EncryptFile(Filename,SharedSct);
			  } catch (IOException e) {
				  e.printStackTrace();
			  }
		  }else{
			  System.out.println("invalid option");
		  }
	  }

	  private static void EncryptFile(String filename, byte[] hash) throws IOException {
		  File f = new File(filename);
		  if(!f.exists()){
			  System.out.println("File does not exit");
			  return;
		  }
		  if(f.isDirectory()){
			  System.out.println("Directory not supported at this time");
			  return;
		  }
		  byte[] StringEnc = filename.getBytes(StandardCharsets.UTF_8);
		  ByteBuffer bb = ByteBuffer.allocate(4);
		  bb.putInt(StringEnc.length);
		  byte[] StrEncLenEnc = bb.array();


		  String outFilename = filename + ".crypt";

		  FileInputStream fis = new FileInputStream(filename);
		  BufferedInputStream bis = new BufferedInputStream(fis);

		  FileOutputStream fos = new FileOutputStream(outFilename);
		  BufferedOutputStream bos = new BufferedOutputStream(fos);

		  bos.write(StrEncLenEnc);
		  bos.write(StringEnc);
		  byte[] buf = new byte[1024];
		  long pos = 0;
		  boolean EOF = false;
		  while(!EOF){
			  if(bis.available() >= 1024){
				  EOF = bis.read(buf) == -1;
				  for(int i = 0;i < 1024;i++){
					  buf[i] ^= hash[(int) (pos%hash.length)];
					  pos++;
				  }
				  bos.write(buf);
			  }else{
				  byte[] b = new byte[1];
				  EOF = (bis.read(b) == -1);
				  b[0] ^= hash[(int) (pos%hash.length)];
				  pos++;
				  bos.write(b);
			  }
		  }


		  bis.close();
		  bos.flush();
		  bos.close();

	  }

	  private static void DecryptFile(String filename, byte[] hash) throws IOException {
		  FileInputStream fis = new FileInputStream(filename);
		  BufferedInputStream bis = new BufferedInputStream(fis);

		  byte[] StringLenEnc = new byte[4];

		  bis.read(StringLenEnc);
		  ByteBuffer bb = ByteBuffer.allocate(4);
		  int Stringlen = bb.wrap(StringLenEnc).getInt();
		  byte[] outfilenameEnc = new byte[Stringlen];

		  bis.read(outfilenameEnc);
		  String outFileName = new String(outfilenameEnc,StandardCharsets.UTF_8 );

		  FileOutputStream fos = new FileOutputStream(outFileName);
		  BufferedOutputStream bos = new BufferedOutputStream(fos);

		  boolean EOF = false;
		  byte[] buf = new byte[1024];
		  long pos = 0;
		  while (!EOF){
			  if(bis.available() >= 1024){
				  EOF = bis.read(buf) == -1;
				  for (int i = 0; i < 1024; i++) {
					  buf[i] ^= hash[(int) (pos%hash.length)];
					  pos++;
				  }
				  bos.write(buf);
			  }else{
				  byte[] b = new byte[1];
				  EOF = bis.read(b) == -1;
				  b[0] ^= hash[(int) (pos%hash.length)];
				  pos++;
				  bos.write(b);
			  }
		  }


		  bos.flush();
		  bos.close();
		  bis.close();
	  }

	  private static void SaveOurPubKey() {
		  if(Kpair == null){
			  System.out.println("KeyPair not generated or loaded \nPlease Load or Generate to save");
			  return;
		  }
		  System.out.println("Enter The Filename:-");
		  SaveKey(Kpair.getPublic().getEncoded(),scn.nextLine() + ".pbk");
	  }

	  private static void DisplayKey() {
		  if(Kpair != null){
			  System.out.println("Our Public Key     :-\n" + toHexString(Kpair.getPublic().getEncoded()));
			  System.out.println("Our Private Key    :-\n" + toHexString(Kpair.getPrivate().getEncoded()));
		  }
		  if(TherePubKey != null)
			  System.out.println("There Public Key   :-\n" + toHexString(TherePubKey.getEncoded()));
		  if(SharedSct != null)
			  System.out.println("Shared Secret      :-\n" + toHexString(SharedSct) );
	  }

	  private static void GenerateSecret() {
		  if((Kpair == null)||(TherePubKey == null)) {
			  if(Kpair == null)
				  System.out.println("Keypair null");
			  if(TherePubKey == null)
				  System.out.println("There Public key is null");
			  return;
		  }
		  try {
			  GenerateSharedSecret();
			  System.out.println("Generated Secret");
		  } catch (NoSuchAlgorithmException | InvalidKeyException e) {
			  e.printStackTrace();
		  }

	  }
	  private static void GenerateSharedSecret() throws InvalidKeyException, NoSuchAlgorithmException {
		  KeyAgreement KeyAgr = KeyAgreement.getInstance("DH");
		  KeyAgr.init(Kpair.getPrivate());
		  KeyAgr.doPhase(TherePubKey, true);
		  SharedSct = KeyAgr.generateSecret();
	  }
	  private static void InitialiseThem() {
		  System.out.println("Enter there Key FileName:-");
		  String resp = scn.nextLine() + ".pbk";
		  byte[] PubEnc = readkey(resp);
		  KeyFactory PubKF;
		  try {
			  PubKF = KeyFactory.getInstance("DH");
			  TherePubKey = PubKF.generatePublic(new X509EncodedKeySpec(PubEnc));;
		  } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			  e.printStackTrace();
		  }
	  }

	  private static void InitialiseKeys() {
		  String resp;
		  try {
			  System.out.println("(G)enerate Keys or Open From (F)ile? (G/F) [any to return to main menu]");
			  resp = scn.nextLine();
			  if(resp.equalsIgnoreCase("f")){
				  //load the Key pair from a file
				  System.out.println("Enter the FileName:-");
				  String FileName = scn.nextLine();
				  Kpair = getKeyPair(FileName + ".kpr");
			  }else if(resp.equalsIgnoreCase("g")) {
				  //Generate new keys
				  KeyPairGenerator KPgen = KeyPairGenerator.getInstance("DH");
				  KPgen.initialize(2048);
				  Kpair = KPgen.generateKeyPair();
				  System.out.println("Enter File Name to save the KeyPair:-");
				  SaveKeyPair(scn.nextLine() + ".kpr",Kpair);
			  }
		  } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			  e.printStackTrace();
		  }
	  }

	  private static void SaveKeyPair(String Filename,KeyPair kp) {
		  byte[] Pubenc = kp.getPublic().getEncoded(), Prvenc = kp.getPrivate().getEncoded();
		  byte[] FileBin = new byte[Pubenc.length + Prvenc.length + 8];

		  ByteBuffer PubBB = ByteBuffer.allocate(4);
		  PubBB.putInt(Pubenc.length);
		  byte[] PubLenIntEnc = PubBB.array();

		  ByteBuffer PrvBB = ByteBuffer.allocate(4);
		  PrvBB.putInt(Prvenc.length);
		  byte[] PrvLenIntEnc = PrvBB.array();

		  System.arraycopy(PubLenIntEnc, 0,FileBin,0,4);
		  System.arraycopy(Pubenc, 0, FileBin, 4,Pubenc.length);
		  System.arraycopy(PrvLenIntEnc, 0,FileBin,Pubenc.length + 4,4);
		  System.arraycopy(Prvenc,0, FileBin,Pubenc.length + 8,Prvenc.length);

		  //System.out.println(" Public Len = " + Pubenc.length + "private len = " + Prvenc.length );
		  SaveKey(FileBin,Filename);

	  }

	  private static KeyPair getKeyPair(String FileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		  KeyPair kp;
		  byte[] PublicKeyEnc,PrivateKeyEnc;
		  byte[] FileBin = readkey(FileName);
		  int PubLen,PrvLen;

		  byte[] PubLenEnc = Arrays.copyOfRange(FileBin,0,4);
		  ByteBuffer PubBB = ByteBuffer.wrap(PubLenEnc);
		  PubLen = PubBB.getInt();
		  PublicKeyEnc = Arrays.copyOfRange(FileBin,4,PubLen + 4);

		  byte[] PrvLenEnc = Arrays.copyOfRange(FileBin,PubLen + 4,PubLen + 8);
		  ByteBuffer PrvBB = ByteBuffer.wrap(PrvLenEnc);
		  PrvLen = PrvBB.getInt();
		  PrivateKeyEnc = Arrays.copyOfRange(FileBin, PubLen + 8,PubLen + 8 + PrvLen);

		  KeyFactory PubKF = KeyFactory.getInstance("DH");
		  PublicKey pubk = PubKF.generatePublic(new X509EncodedKeySpec(PublicKeyEnc));

		  KeyFactory PrvKF = KeyFactory.getInstance("DH");
		  PrivateKey prvk = PrvKF.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyEnc));

		  kp = new KeyPair(pubk,prvk);
		  return kp;
	  }
	  private static byte[] readkey(String Filename, byte[] hash){
		  byte[] b = readkey(Filename);
		  for(int i = 0; i < b.length;i++)b[i] ^= hash[i%hash.length];
		  return b;
	  }
	  private static byte[] readkey(String FileName) {
		  byte[] KeyEnc = null;
		  try {
			  KeyEnc = Files.readAllBytes(Paths.get(FileName));
		  } catch (IOException e) {
			  e.printStackTrace();
		  }
		  return KeyEnc;
	  }

	  private static void SaveKey(byte[] pubKeyEnc, String Filename, byte[] hash) {
		  for (int i = 0; i < pubKeyEnc.length; i++)
			  pubKeyEnc[i] ^= hash[i%hash.length];
		  SaveKey(pubKeyEnc,Filename,hash);
	  }
	  private static void SaveKey(byte[] pubKeyEnc, String Filename) {
		  try {
			  Files.write(Paths.get(Filename),pubKeyEnc);
		  } catch (IOException e) {
			  e.printStackTrace();
		  }
	  }

  */
/*
try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            KeyPair kp = EnigmaKeyHandler.GenerateKeypair();
            sign.initSign(kp.getPrivate());
            sign.update(EnigmaCrypto.SHA256("Magicaly"));
            byte[] sgn = sign.sign();

            Signature verSign = Signature.getInstance("SHA256withRSA");
            verSign.initVerify(kp.getPublic());
            verSign.update(EnigmaCrypto.SHA256("Magicaly"));
            boolean good = verSign.verify(sgn);
            if(good){
                System.out.println("Good Sign");
            }else {
                System.out.println("Bad Sign");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
*/
