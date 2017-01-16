#!/usr/bin/python

# FRANKEN CIPHER
# WRITTEN FOR ACADEMIC PURPOSES
#
# AUTHORED BY: Dan C and james@forscience.xyz
#
# THIS SCRIPT IS WRITTEN TO DEMONSTRATE A UNIQUE ENCRYPTION ALGORITHM THAT IS INSPIRED BY A NUMBER
# OF EXISTING ALGORITHMS.
# THE SCRIPT IS WRITTEN ENTIRELY FOR ACADEMIC PURPOSES. NO WARRANTY OR GUARANTEES ARE
# OFFERED BY THE AUTHORS IN RELATION TO THE USE OF THIS SCRIPT.
#
# Usage: franken.py <"-v" (verbose)> <"-d" (decrypt)> <"-k" (key phrase)> <"-m" (string to encrypt/decrypt)>
#
# indentation: TABS!

import sys
import getopt
import collections
import binascii
import hashlib
import itertools

# GLOBALS
# define -v and -d as false (-d defaults to encrypt mode)
verbose_opt = False
decrypt_opt = False
key_phrase = '' 		# clear text key phrase
key_hashed = '' 		# hashed key phrase
clear_text = '' 		# starting message input
pigpen_message = '' 	# message after pigpen stage
encrypted_message = '' 	# the encrypted message
decrypted_message = '' 	# the decrypted message

# GLOBALS
# pigpen dictionaries
pigpen_A = {'A':'ETL', 'B':'ETM', 'C':'ETR', 'D':'EML', 'E':'EMM', 'F':'EMR', 'G':'EBL', 'H':'EBM', 'I':'EBR', 'J':'DTL',
'K':'DTM', 'L':'DTR', 'M':'DML', 'N':'DMM', 'O':'DMR', 'P':'DBL', 'Q':'DBM', 'R':'DBR', 'S':'EXT', 'T':'EXL', 'U':'EXR',
'V':'EXB', 'W':'DXT', 'X':'DXL', 'Y':'DXR', 'Z':'DXB', ' ':'EPS', '.':'EPF', ',':'EPC', '!':'EPE', '?':'EPQ', '"':'EPD',
'@':'EPA','0':'NTL', '1':'NTM', '2':'NTR', '3':'NML', '4':'NMM', '5':'NMR', '6':'NBL', '7':'NBM', '8':'NBR','9':'NXT'}

pigpen_B = {'C':'ETL', 'D':'ETM', 'A':'ETR', 'B':'EML', 'G':'EMM', 'H':'EMR', 'E':'EBL', 'F':'EBM', 'K':'EBR', 'L':'DTL',
'I':'DTM', 'J':'DTR', 'O':'DML', 'P':'DMM', 'M':'DMR', 'N':'DBL', 'S':'DBM', 'T':'DBR', 'Q':'EXT', 'R':'EXL', 'W':'EXR',
'X':'EXB', 'U':'DXT', 'V':'DXL', ' ':'DXR', ',':'DXB', 'Y':'EPS', '!':'EPF', 'Z':'EPC', '.':'EPE', '@':'EPQ', '0':'EPD',
'?':'EPA','"':'NTL', '3':'NTM', '4':'NTR', '1':'NML', '2':'NMM', '7':'NMR', '8':'NBL', '9':'NBM', '5':'NBR', '6':'NXT'}

pigpen_C = {'K':'ETL', 'L':'ETM', 'M':'ETR', 'N':'EML', 'O':'EMM', 'P':'EMR', 'Q':'EBL', 'R':'EBM', 'S':'EBR', 'U':'DTL',
'V':'DTM', 'W':'DTR', 'X':'DML', 'Y':'DMM', 'Z':'DMR', ' ':'DBL', '.':'DBM', ',':'DBR', '!':'EXT', '"':'EXL', '?':'EXR',
'@':'EXB', '0':'DXT', '1':'DXL', '2':'DXR', '3':'DXB', '4':'EPS', '5':'EPF', '6':'EPC', '7':'EPE', '8':'EPQ', '9':'EPD',
'A':'EPA','B':'NTL', 'C':'NTM', 'D':'NTR', 'E':'NML', 'F':'NMM', 'G':'NMR', 'H':'NBL', 'I':'NBM', 'J':'NBR','T':'NXT'}


# creates hashes of the key phrase inputted by the user 
# in order for it to be used as a key
# the clear text key phrase string is retained
def keyGenerate():
	global key_hashed

	# create the hashes of the key phrase string
	md5_hash = hashlib.md5(key_phrase.encode())
	sha256_hash = hashlib.sha256(key_phrase.encode())
	sha512_hash = hashlib.sha512(key_phrase.encode())

	# concatenate the hash digests into one key
	key_hashed = md5_hash.hexdigest() + sha256_hash.hexdigest() + sha512_hash.hexdigest()

	# hash the entire key (so far) one more time and concatenate to make 1024bit key
	key_hashed_hash = hashlib.md5(key_hashed.encode())
	key_hashed += key_hashed_hash.hexdigest()

	# vebose mode if verbose option is set
	if verbose_opt:
		print("[KEY GENERATION]: The key phrase is: \"" + key_phrase + "\"")
		print("[KEY GENERATION]: \"" + key_phrase + "\" is independantly hashed 3 times using MD5, SHA256 and SHA512")
		print("[KEY GENERATION]: The 3 hashes are concatenated with 1 more md5 hash, resulting in the 1024bit key:")
		print("[KEY GENERATION]: \"" + key_hashed + "\"\n")

	return


# selects the appropriate pigpen dictionary based on summing all of the ascii
# values in the key phrase and modulating the sum of the integers by 3 in order to retrieve
# one of 3 values. Returns the appropriate dictionary
def selectDict():
	# sum ASCII value of each character in the clear text key phrase 
	ascii_total = 0
	for x in key_phrase:
		ascii_total += ord(x)

	# modulo 3 ascii_total to find 0-3 result to select pigpen dict
	if ascii_total % 3 == 0:
		pigpen_dict = pigpen_A

	elif ascii_total % 3 == 1:
		pigpen_dict = pigpen_B

	elif ascii_total % 3 == 2:
		pigpen_dict = pigpen_C

	# return the dictionary	
	return pigpen_dict


# convert message into pigpen alphabet. compare each letter to dict key.
# first makes all chars uppercase and ignores some punctuation.
# itterates through pigpen dict to find value based on clear message char as key
def pigpenForward():
	global pigpen_message

	# convert clear message to uppercase
	message = clear_text.upper()

	# itterate through dict looking for chars
	for letter in message:
		if letter in selectDict():
			pigpen_message += selectDict().get(letter)

	# verbose mode if verbose option is set
	if verbose_opt:
		print("[ENCRYPTION - Phase 1]: The clear text is:")
		print("[ENCRYPTION - Phase 1]: \"" + clear_text + "\"")
		print("[ENCRYPTION - Phase 1]: 1 of 3 dictionaries is derived from the sum of the pre-hashed key ASCII values (mod 3)")
		print("[ENCRYPTION - Phase 1]: The clear text is converted into pigpen cipher text using the selected dictionary:")
		print("[ENCRYPTION - Phase 1]: \"" + pigpen_message + "\"\n")

	return


# reverses the pigpen process. takes a pigpen string and converts it back to clear text
# first creates a list of each 3 values from the inputted string (each element has 3 chars)
# then compares those elements to the pigpen dictionary to create the decrypted string
def pigpenBackward():
	global decrypted_message

	# convert encrypted message (int array) back to a single ascii string
	message = ''
	try:
		for i in decrypted_message:
			message += chr(i)
	except:
		print("[ERROR]: Incorrect key. Cannot decrypt.")
		usageText()

	# retrieve each 3 chars (one pigpen value) and form a list
	message_list = [message[i:i+3] for i in range(0, len(message), 3)]

	# zero out decrypted message string in order to store pigpen deciphered characters
	decrypted_message = ''

	# itterate through list elements and compare against pigpen dict
	# to find correct key (clear text letter) and create decrypted string
	for element in message_list:
		for key, value in selectDict().iteritems():
			if value == element:
				decrypted_message += key

	# verbose mode if verbose option is set
	if verbose_opt:
		print("[DECRYPTION - Phase 3]: 1 of 3 dictionaries is derived from the sum of the pre-hashed key ASCII values (mod 3)")
		print("[DECRYPTION - Phase 3]: The values of the pigpen cipher text are looked up in the selected dictionary")
		print("[DECRYPTION - Phase 3]: The pigpen cipher text is converted back into clear text:\n")
		print("[DECRYPTION - COMPLETE]: \"" + decrypted_message + "\"\n")

	return


# XORs an int value derived from the hashed key to each ascii int value of the message.
# The key value is looked up by using the value stored in that key array position to reference
# the array position that value points to. That value is then XOR'ed with the corresponding value of the message
# this occurs three times. Inspired by DES key sub key generation and RC4   
def keyConfusion(message):
	# create array of base10 ints from ascii values of chars in hashed key
	key = []
	for x in key_hashed:
		key.append(ord(x))

	# create a variable for cycling through the key array (in case the message is longer than key)
	key_cycle = itertools.cycle(key)

	# loop through the key and XOR the resultant value with the corresponding value in the message
	for i in range(len(message)): 

		# find the value pointed to by the value of each element of the key (for each value in the message array)
		key_pointer = key_cycle.next() % 128 # get the next key byte. mod 128 because 128 bytes in 1024bits
		key_byte = key[key_pointer]

		# XOR message byte with current key_byte
		message[i] = message[i] ^ key_byte

		# XOR message byte with the key byte pointed to by previous key byte value
		key_byte = key[(key_byte % 128)]
		message[i] = message[i] ^ key_byte

		# once again XOR message byte with the next key byte pointed to by previous key byte value
		key_byte = key[(key_byte % 128)]
		message[i] = message[i] ^ key_byte

	# verbose mode if verbose option is set
	if verbose_opt:
		# are we decrypting or encrypting?
		if decrypt_opt:
			en_or_de = "[DECRYPTION - Phase 2]: "
			en_or_de_text = " pigpen cipher text:"

		else:
			en_or_de = "[ENCRYPTION - Phase 2]: "
			en_or_de_text = " partially encrypted string:"
		
		# print the appropriate output for encrypting or decrypting
		print(en_or_de + "Each byte of the pigpen cipher is then XOR'ed against 3 bytes of the key")
		print(en_or_de + "The key byte is XOR'ed against the byte of the message and then used to select the")
		print(en_or_de + "position in the key array of the next key byte value. This occurs three times.")
		print(en_or_de + "Resulting in the" + en_or_de_text)
		print(en_or_de + "\"" + message + "\"\n")

	return message


# xors the hashed key against the pigpenned message
# each character in the message is xor'ed against each character
# in the hashed key, resulting in the encrypted message
def xorForward():
	global encrypted_message

	# convert key and message into ints for xoring
	message = bytearray(pigpen_message)
	key = bytearray(key_hashed)

	# send pigpen message off for permution
	message = keyConfusion(message)

	# iterate over message and xor each character against each value in the key
	for x in range(len(message)):
		for y in range(len(key)):
			xored = key[y] ^ message[x]
			message[x] = xored

	# store hex value of encrypted string in global variable
	encrypted_message = binascii.hexlify(bytearray(message))

	# verbose mode is verbose option is set
	if verbose_opt:
		print("[ENCRYPTION - Phase 3]: The partially encrypted cipher text and key are converted into a byte arrays")
		print("[ENCRYPTION - Phase 3]: Each byte of the message is XOR'ed against each byte of the key")
		print("[ENCRYPTION - Phase 3]: Resulting in the cipher text hex string:\n")
		print("[ENCRYPTION - COMPLETE]: \"" + encrypted_message + "\"\n")

	return


# the reverse of the encrypt function, whereby the supplied key is reversed
# and xored against the encrypted message. The message is first unhexlified
# to facilitate xoring
def xorBackward():
	global decrypted_message

	# create byte array for key and to store decrypted message
	reverse_key = key_hashed[::-1]
	key = bytearray(reverse_key)

	# try to convert the encrypted message from hex to int, error if incorrect string
	try:
		message = bytearray(binascii.unhexlify(clear_text))
	except:
		print("[ERROR]: Incorrect string. Cannot decrypt.")
		usageText()

	# iterate over the encrypted message and xor each value against each value in the key
	for x in range(len(message)):
		for y in range(len(key)):
			xored = key[y] ^ message[x]
			message[x] = xored

	# verbose mode is verbose option is set
	if verbose_opt:
		print("[DECRYPTION - Phase 1]: The cipher text is:")
		print("[DECRYPTION - Phase 1]: \"" + clear_text + "\"")
		print("[DECRYPTION - Phase 1]: The cipher text and key are converted into a byte arrays")
		print("[DECRYPTION - Phase 1]: The key is reversed in order to reverse this stage of XOR'ing")
		print("[DECRYPTION - Phase 1]: Each byte of the cipher text is XOR'ed against each byte of the key")
		print("[DECRYPTION - Phase 1]: Resulting in the partially decrypted string:")
		print("[DECRYPTION - Phase 1]: \"" + message + "\"\n")

	# send decrypted array off for permutation (reverse encrypted XOR'ing)
	decrypted_message = keyConfusion(message)

	return


# text to be displayed on incorrect user input
def usageText():
	print("\n[USAGE]: franken.py -v (verbose) -d (decrypt) --keyphrase (-k) <phrase> --message (-m) <message to encrypt>")
	print("[USAGE]: -v and -d arguments are optional. --keyphrase(-k) and --message(-m) are required")
	print("\n[EXAMPLE]: python franken.py -v --keyphrase \"super secret\" --message \"This is a super secret message\"\n")
	print("[!] As with any cipher, your message is only as secure as your key phrase.")
	print("[!] REMEMBER: The more complicated your key phrase, the stronger your encrypted message will be!\n")
	sys.exit(2)


# USER INPUT HANDLING
# check that arguments have been supplied
if len(sys.argv) < 2:
	usageText()

# define the arguments and necessity.
try:
	opts, args = getopt.getopt(sys.argv[1:], 'vdk:m:', ["verbose", "decrypt", "keyphrase=", "message="])
except getopt.GetoptError:
	usageText()

# check for presence of args and assign values
for opt, arg in opts:
	if opt == '-v': 
		verbose_opt = True
	if opt == '-d':
		decrypt_opt = True
	if opt in ('-k', '--keyphrase'):
		key_phrase = arg
	if opt in ('-m', '--message'):
		clear_text = arg

# Check that a keyphrase and message has been set
if not key_phrase or not clear_text:
	usageText()

print(
'''
   __                 _              
  / _|               | |             
 | |_ _ __ __ _ _ __ | | _____ _ __  
 |  _| '__/ _` | '_ \| |/ / _ \ '_ \ 
 | | | | | (_| | | | |   <  __/ | | |
 |_| |_|  \__,_|_| |_|_|\_\___|_| |_|                                     
			     _      _            
			  __(_)_ __| |_  ___ _ _ 
			 / _| | '_ \ ' \/ -_) '_|
			 \__|_| .__/_||_\___|_|  
			      |_|                
 
 [!] franken.py
 An encryption algorithm inspired by a number of existing ciphers.
 Created for CC6004 Course Work 1. 2016/17

 [@] Dan C and james@forscience.xyz
__________________________________________________
'''
)
# are we decrypting or encrypting? defaults to encrypting
# decrypt
if decrypt_opt:
	keyGenerate()
	xorBackward()
	pigpenBackward()
	if not verbose_opt:
		print("[DECRYPTED]: " + decrypted_message + "\n")
# encrypt
else:
	keyGenerate()
	pigpenForward()
	xorForward()
	if not verbose_opt:
		print("[ENCRYPTED]: " + encrypted_message + "\n")
