# vigenere
Vigenere Cipher , ARM Assembly Raspberry PI 4.

The program uses command line arguments to determine what to do. It accepts two argument values. 
The first is the word encrypt or decrypt to specify the operation. 
The second is a string of lowercase letters representing the key for the  algorithm. 
If I do not get exactly two arguments of the correct form I print an error message and quit the program.

The program implements The substitution cipher known as the Autokey cipher (you can read about it here: 
https://crypto.interactive-maths.com/autokey-cipher.html). 
A 2D lookup table is used to perform the substitution for each letter, where the letters of the key are used in 
the beginning for one dimension of the table, then being followed by the plain text. 
The plain text letters are used for the other dimension of the table. Each letter
pairing picks a replacement character from the corresponding entry in the table. This process is
basically reversed for decryption. Rather than simply hard-coding this table in the data area, 
I wrote a function that automatically fills in an appropriate sized memory area with the letters.

This technique is known as a stream cipher, 
I  continue applying it to consecutive characters for however many there are. 
For this program, I read from stdin and redirect the contents of a file as input on the command line. 
Similarly, rather than opening a file for output, 
I write to stdout and redirect this output to a file on the command line. 


Compile code:

gcc -g -o  vigenere vigenere.s

Run Encryption Command

./vigenere encrypt king < file.txt >  output.txt

Run Decryption Command

./vigenere Decrypt king < file.txt >  output.txt


| Method        | Key           | File.txt content | Output.txt result  
| ------------- | ------------- | -------------    | -------------    |
| Encrypt       | KING          | MEETMEATTHECORNER| WMRZYIEMFLEVHYRGF|
| Decrypt       | KING          | WMRZYIEMFLEVHYRGF| MEETMEATTHECORNER|
