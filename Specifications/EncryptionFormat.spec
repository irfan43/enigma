Encrypting a file,
	a .crypt file holds the list of files present with in it self
		[] <- denotes a block of which the first 4 bytes tells the length of the block

	encryption starts half way through the header, this prevents reveal the first 12 bytes of the key while masking the number of files present
	HEADER-> 8byte signiture, 4 byte version, /\ Encryption starts here /\  4 bytes number of files present  // Signiture decimal 29 8 20 14 23 6 19 54 hex 1d 08 14 0E 17 06 13 36

	[location of file + name example Folder1/folder2/Image.png]
	[Binary of that file] // note first 8 bytes not 4 denote long for length (to allow for files larger then 2gb)
	2 block pairs denote a single file. name then Binary
	multiple files can be listed as well as full directories

	sha256 hash
	terminated with sha256 hash

	note every single bit excluding the sha256 hash is XOR Encrypted with the given key
