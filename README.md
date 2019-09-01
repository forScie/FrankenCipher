
FRANKEN CIPHER (franken.py)

WRITTEN FOR ACADEMIC PURPOSES 
AUTHORED BY: Dan C and james@forscience.xyz

THIS SCRIPT IS WRITTEN TO DEMONSTRATE A UNIQUE ENCRYPTION ALGORITHM THAT IS INSPIRED BY A NUMBER
OF EXISTING ALGORITHMS.
THE SCRIPT IS WRITTEN ENTIRELY FOR ACADEMIC PURPOSES. NO WARRANTY OR GUARANTEES ARE
OFFERED BY THE AUTHORS IN RELATION TO THE USE OF THIS SCRIPT.
------------------------------------------------------------------------------------------------

USAGE
$> python franken.py <"-v" (verbose)> <"-d" (decrypt)> <"-k" (key phrase)> <"-m" (string to encrypt/decrypt)>

EXAMPLE
$> python franken.py -k "super secret" -m "hello world"

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

[ENCRYPTED]: 7f783620247c716e79216f7c74287d7f68647e3c3c7f7c7a206e7c223a7c21627b


PURPOSE
This script has been written to provide proof of concept for a proposed cryptographic algorithm.

FUNCTIONALITY
franken.py is a command line python script designed to take a key phrase of any length which can be used to encrypt/decrypt a string of any length.
In order for the script to function it requries two arguments at minimum: -k and -m (--key, --message) - the key phrase (k) and the message (m).
