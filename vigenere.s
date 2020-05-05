	.arch	armv7
	.cpu	cortex-a53
	.fpu	neon-fp-armv8
	.global	main
	.text

@@@ Vigenere cipher implementation
@@@ CSCI-6616 Assembly Language
@@@ Krikor Herlopian/Rick Aliwalas

@ argc is the number of arguments passed (int)
@
@       int main(int argc, char *argv[])
@
@ R0 will contain the argc + 1 for the program name
@ i.e., "progname encrypt keyval" yields R0=3

main:
	mov	R3, R0		@ R3 <- R0
	str	R0, [SP,#-4]	@ store contents of R0 (#args+1) into byte
				@ address stored in [SP-4 bytes]

	str	R1, [SP,#-8]	@ store contents of R1 (arg1) into byte
				@ address stored in [SP - 8 bytes]

	cmp	R3, #3		@ is #args + 1 equal to 3?
				@ if not, write msg to user and exit

	bne	endProgram	@ if more or less arguments than 2 args passed,
				@ exit program

@ arg1 should be "encrypt" or "decrypt" (case insensitive)

checkEncrypt:	@ in loopEncrypt, checkEncryptCaseInsensitive, updateLoopEncrypt,
		@ we loop over each char in arg1, check if "e" then "n",...

	ldr 	R3, [SP,#-8]	@ load R3 with value located in byte address
				@ contained in [SP,#-8] (i.e. arg1)
	add	R3, R3, #4	@ change R3 to addr of next char in arg1
	ldr	R5, =encryptStr	@ load addr of word "encrypt" into R5
	ldr	R3, [R3]	@ load R3 with value in byte address in R3
	mov	R4, #0		@ initialize R4 (loop index)

@ we want to loop over every character, check if its "e" then "n" 
@ than c... until we confirm "encrypt" was typed

loopEncrypt:
	@ note ldrb loads a byte into the lower 8 bits of the destination
	@ register padding the upper 24 bits to zeros

	ldrb	R6, [R3,R4]	@ load R6 with value at address R3+R4 bytes
				@ i.e., char in arg1 (ideally "encrypt")

	ldrb	R7, [R5,R4]	@ load R7 with the value at address stored
				@ in R5 offset by R4 bytes (this is the char
				@ in the string "encrypt" for comparison

	cmp	R6, R7		@ check if they are equal, if not check
				@ uppercase case
	bne	checkEncryptCaseInsensitive
	b	updateLoopEncrypt

	@ check for lowercase, in case we confirm its not encrypt,
	@ call checkdecrypt to check if its decrypt.

	@ we have to check for lower case as well. in case we confirm its not encrypt,
	@ call checkdecrypt to check if its decrypt.

checkEncryptCaseInsensitive:
	add	R6, R6, #32	@ offset the char in arg1 (R6) by 32 bytes
				@ i.e., change "E" to "e" for ex
	cmp	R6, R7		@ compare, if equal, goto updateLoopEncrypt 
				@ otherwise, chk if user entered "decrypt"
	bne	checkDecrypt
	b	updateLoopEncrypt

	@ update loop index to move to compare second letter

updateLoopEncrypt:
	add	R4, R4,#1	@ increment index R4
	cmp	R4, #7		@ compare if reached 7 (encrypt is 7
				@ letters). If yes, check last element
				@ otherwise goto loopEncrypt
	beq	checkLastElementEncrypt
	b	loopEncrypt

	@ check if 1st arg is "decrypt", if confirmed it is not "encrypt"

checkDecrypt:			@ check if "decrypt" (case-insentive) passed
	ldr	R3, [SP,#-8]	@ load R3 with value in byte addrress [
				@ [SP-8 bytes] - back to start of string
	add	R3, R3, #4	@ change R3 to addr of next char in arg1
	ldr	R5, =decryptStr	@ load word decrypt for comparison
	ldr	R3, [R3]	@ load R3 with value in byte address in R3
	mov	R4, #0		@ initialize R4 (loop index)

	@ loop over every character, and check if its d than e
	@ than c ...until we confirm "decrypt" was typed

loopDecrypt:
	ldrb	R6, [R3,R4]	@ load R6 with value at address R3+R4 bytes
				@ i.e., char at index R4 of arg1
	ldrb	R7, [R5,R4]	@ load letter at index R4 of string "decrypt"
	cmp	R6, R7		@ check if equal, if not check for upper case
	bne	checkDecryptCaseInsensitive
	b	updateLoopDecrypt

	@ check for lowercase letter as well. "D" or "d". If we get to confirm
	@ its not decrypt, end program

checkDecryptCaseInsensitive:
	add	R6, R6,#32	@ add 32
	cmp	R6, R7		@ check if equal, if not end program since
				@ neither encrypt or decrypt was 1st arg
	bne	endProgram	@ arg1 is neither "encrypt" nor "decrypt"
	b	updateLoopDecrypt

	@ update loop index to move to compare second letter

updateLoopDecrypt:
        add     R4, R4,#1       @ update index R4
        cmp     R4, #7          @ in case we reached end of word decrypt(7),
                                @ check last element.
        beq     checkLastElementDecrypt
        b       loopDecrypt

	@ check if last element is 0. So that we confirm "encrypt" was
	@ typed without additional letters. For example, "encrypt1" will end
	@ program. Since last element will fail.

checkLastElementEncrypt:
	ldrb	R6, [R3,R4]	@ load last char
	cmp	R6, #0		@ if 0 goto goToEncrypt, if not it means user
				@ typed "encrypt1" for example (program ends
				@ in this case)
	beq	goToEncrypt
	b	endProgram

	@ we check if last element is 0 (null terminator) so that we confirm
	@ "decrypt" was typed without any more letters. "decrypt1" will end
	@ program. Since last element will fail.

checkLastElementDecrypt:
	ldrb	R6, [R3,R4]	@ load last letter
	cmp	R6, #0		@ if 0 gotodecrypt, if not it means user typed
				@ decrypt1 for example (program ends)
	beq	goToDecrypt
	b	endProgram

goToDecrypt:
	mov	R10, #1		@ R10=1 indicates decrypting
	b	loadKey

goToEncrypt:			@ store 0 in R10, so we know in future we
				@ are encrypting
	mov	R10, #0		@ R10=0 indicates encrypting
	b	loadKey

	@ get key (arg2) and check length.
	@ It is in R3 now.

loadKey:
	mov	R4, #0		@ initialize index
	ldr	R3, [SP,#-8]	@ load R3 with the contents at addr [SP,#-8]
				@ points to start of 3 arguments
	add	R3, R3, #8	@ add 8 to R3 to get to the key
	ldr	R3, [R3]	@ load key into R3
	b	getKeyLen

	@ We get key length here. At end, the key length will be in R4
	@ and the key will be in R3. Any character (including spaces) are
	@ acceptable for the key.

getKeyLen:
	ldrb	R6, [R3,R4]	@ load letter at index R4 of key (2nd
				@ command line argument).
	cmp	R6,#0		@ compare its not end
	beq	inputUser	@ if you reached end of key, go to input User
	sub	R8, R6, #'A'	@ subtract -65 from letter at index R4 of .
	cmp	R8, #25		@ check against 25
	bgt	checkIfSmallKeyLetter	@ if greater than, check for small case
					@ scenario
	cmp	R8, #0		@ compare against 0
				@ error should be  letters between A-Z @ less
				@ than 0, end program. Should be a-z or A-Z.
	blt	endProgram
	add	R4, R4, #1	@ update index R4, at the end R4 will be key
				@ length when loop over.
	b	getKeyLen

	@ We check if key typed in lowercase letter, we move it to uppercase
	@ letter. If the char is not A-Z or a-z, we continue but in our
	@ encryption/decryption we keep that character as it is.
	@ The key will be stored in R6.

checkIfSmallKeyLetter:
	sub	R8, R8, #32	@ subtract 32 from letter
	cmp 	R8, #25		@ compare to 25
	bgt 	asIs 		@ >25 means char is not A-Z/a-z
	cmp 	R8, #0		@ compare to 0
	blt 	asIs		@ not A-Z/a-z
	@ convert to uppercase to ease encryption/decryption:
	sub 	R6, R6, #32 
	strb 	R6, [R3,R4]
	add 	R4, R4,#1	@ update index, R4 will be key length at end
	b	getKeyLen

@ keep key as is, since its neither small or uppercase letter between A-Z/a-z
asIs:
	add 	R4, R4 ,#1	@ update index, R4 will be key length at end
	b	getKeyLen	

	@ We will read input of plain or ciphered text. We store it in R3.
	@ We want to write result to stack.We are allocating on stack space of
	@ 4 * key length * key length for inbuff and outbuff

inputUser:
	mul	R11, R4, R4
	mov	R9, #4
	mul	R11, R11, R9	@ allocating space key*key*4  (64b if key=4)
	sub	SP, SP, R11
	mov	R9, #0		@ key index

readInput:
	mul	R11, R4, R4
	mov	R12, #2
	mul	R11, R11, R12	@ 32b (if key=4)
	add     R11, SP, R11	@ where to start writing from
	mov	R0, #0
	mov	R6, R3
	mov	R1, R11
	mul	R11,R4,R4	@ read first 16b
	mov	R12, #1
	mul	R11,R11,R12
	mov	R2, R11		@ we will be reading 16 characters if key
				@ is 4 (4*4=16)
	bl	read
	mov	R3, R1
	mov	R1, R0		@ moving length of plain/ciphered text to R1
	mov	R0, R6		@ moving key to R0
	mov	R6, #0
	mov	R2, R10		@ moving whether its encrypt(0) or decrypt(1) to R2
	mov	R5, R0
	mov	R6, R1
	mov	R7, R2
	mov 	R8, R3
	mov	R11, R4

/*
	k i n g
	m e e t m e a t t h e c o r n e r
	k i n g m e e t m e a t t h e c o
*/

@ R0 is the key
@ R1 is the length of the plain/ciphered text
@ R9 is key index
@ R4 is key length
@ R3 is plain/ciphered text
@ R2 to tell whether to do encrypt(0) or decrypt(1)

	mov 	R5, #0 @ R0
	mov 	R8, #0  @ R3
	push	{R6,R7,R10}
	@ this will do encryption or decryption, result will return in R0
	bl	vigenere
	mov	R3,R8
	b	updateKey
	b	printFinal

@ in case there is more to read, we need to update the key with last few
@ letters (equal to the length of the original key) from old input we did
@ not utilize:
@
@ in the case of decryption, we are using the last few letters from the 
@ decrypted word

updateKey:
	cmp	R10, #1
	beq	up2	@ in case decrypt we go there. else its encryption
	mul	R11, R4, R4
	cmp	R6, R11
	beq	updateKey2
	b	printFinal

up2:
	mov	R3, R0	@ move the result of decrypting first part to r3,
			@ we will update our keys with it.
	mul	R11, R4, R4
	cmp	R6, R11
	beq	updateKey2
	b	printFinal

updateKey2:	
	mov	R11, #0
	b	loop100	

@ lets loop and update. In case its encrypt we read from plain text entered, 
@ in case decrypt we read from the result of decrypting first part of text.
@
@                               A
@ m e e t m e a t t h e c o r n e | r x y z a	<-- input to encrypt
@ k i n g m e e t m e a t t h e c | o r n e r	<-- key
@
@ In the encryption case:
@   at point A, we still have more input to read, so we update the key
@   to "orne"
@
@ In the decryption case, at point B, we are using the last 4 letters of
@ the decrypted word @ "orne" as the key
@
@				  B
@ w m r z y i e m f l e v h y r g | f o l d r	<-- input to decrypt
@ k i n g m e e t m e a t t h e c | o r n e f	<-- key
@ m e e t m e a t t h e c o r n e | r x y z a	<-- decrypted output

loop100:
	cmp	R11, R4
	beq	printFinal
	sub	R9, R6, R4	@ length of text - keylength
	add	R9, R9, R11
	ldrb	R12, [R3,R9]
	b	uppperCaseL

@ make key uppercase. Easy to encrypt/decrypt with.

uppperCaseL:
	cmp	R12, #65
	blt	c1
	cmp	R12, #90
	bgt	c1
	strb	R12, [R5,R11]
	add	R11, R11, #1
	b	loop100

c1:
	sub	R12, R12, #32
	cmp	R12, #65
	blt	c2
	cmp	R12, #90
	bgt	c2
	strb	R12, [R5,R11]
	add	R11, R11, #1
	b	loop100

c2:
	ldrb	R12,[R3,R9]
	strb	R12,[R5,R11]
	add	R11,R11,#1
	b	loop100

printFinal: 
	sub	R9, R6, R4
	sub	R9, R6, R9
	mov	R9, #0
	mov	R10, R0		@ moving result to R10
	mov	R0, #1
	mov	R2, R1		@ moving length to print into R2.
	mov	R1, R10		@ moving result to R1
	mov	R10, #0
	sub R12, R2 , #1
	ldrb	R12,[R3,R12]
	cmp		R12, #10
	beq		removeLast
	cmp		R12, #0
	beq		removeLast
	bl	write
	mov	R0, R6		@ length of ciphered text
	mov 	R6, R5		@ key in R6
	mov 	R10, R7		@ whether encrypt or decrypt in R10
	mov	R3, R6
	mul	R11, R4, R4
	mul	R11, R4, R4
	cmp	R0, R11
	beq	readInput	@ more input to read, continue reading
	mov	R0, #0
	mov 	R7, #1
	mov 	R3, #0
	b	printFinal
	
removeLast:
	sub R2, R2, #1
	bl	write
	mov	R0, R6		@ length of ciphered text
	mov 	R6, R5		@ key in R6
	mov 	R10, R7		@ whether encrypt or decrypt in R10
	mov	R3, R6
	mul	R11, R4, R4
	mul	R11, R4, R4
	cmp	R0, R11
	beq	readInput	@ more input to read, continue reading
	mov	R0, #0
	mov 	R7, #1
	mov 	R3, #0


endProgram:
	mov	R0, #0
	mov	R7, #1
	swi	0
	
@ function called to start to loop over every character typed, and
@ transform based on key.	

vigenere:
	mov	R7, #0

	@ we start process of loop over every character to encrypt or decrypt it.
	@ R1 is length of plain/ciphered text.R7 is index of every character we passing on for
	@ plain/ciphered text.
	@ R9 will be index of key characters i loop over.
	@ R7 index of plain/ciphered text i loop over.
	@ R11 where i want to write on stack.

encryptDecryptInit:
	mul	R11, R4, R4
	mov	R7, #4
	mul	R11, R11, R7
	add	R11, SP, R11
	mul	R7, R4, R4
	add	R11, R11, R7
	mov	R7, #0
	b 	startLoop
	
startLoop:
	@ R1 is length of plain/cipher text, R7 the index. R7 starts with 0.
	cmp 	R7, R1

	@ if less than, keep looping. Else we reached end, so print Result.
	blt 	loopPlainText

	b   	finishProcess

	@ if character not A-Z.we change it to uppercase by subtracting 32.
	@ if a result yeilded shows its not A-Z or a-z go to encrypt/decrypt
	@ next character. keep previous as is.
	@ else if its A-Z or a-z operate over it to encrypt/decrypt.

loopPlainText:
	@ load letter from cipher/plain text at index R7
	ldrb 	R5, [R3,R7]
	sub	R8, R5, #'A'	@ subtract -65
	mov 	R6, #0		@ we keeping in mind here, that it could be
				@ uppercase letter(0). we are storing that in R6
	cmp	R8, #26		@ check subtracted value against 26
	blt	operate		@ if less than go to operate
	sub	R8, R5,#32	@ else subtract another 32 for lowercase letter scenario
	@update letter to be uppercase, to make it easier to encrypt/decrypt.
	strb 	R8, [R3,R7]	
	ldrb 	R5, [R3,R7]
	sub 	R8, R5,#'A'	@subtract -65 again
	mov 	R6, #1		@ we keeping in mind here, that it was lowercase
				@ letter(1). we are storing that in R6.
	@ check against 26, if less than go to operate. Else go to update as it
	@ is not a-z or A-Z.
	cmp	R8, #26
	bge	update

	@ if R8 less than 0, so we know its not a-z or A-Z go to update.
	@ else its A-Z or a-z encrypt/decrypt that character.
operate:
	cmp	R8, #0
	blt	update
	b	encryptOrDecrypt

	@ update index to go over next character of plain/ciphered text.
	@ We keep the letter as is since it cannot be encrypted or decrypted.
	@ It's not a-z or A-Z.We update key index r9 too.

update:
	ldrb	R5, [R3,R7]
	strb 	R5, [R11], #1
	add 	R6, R6, #1
	add	R9,R9,#1
	add 	R7, R7,#1
	b 	startLoop

	@ if R2 is 0 , we know command given was encrypt.
	@ else its decrypt. R2 would be 1 in that case.

encryptOrDecrypt:
	cmp	R2, #0
	beq	encrypt	
	b	decrypt

	@ I am comparing key index r9 with key length r4, if its greater or
	@ equal I know I need to decrypt with my decrypted letters(another2way).
	@ Else I decrypt with the key (checkkeyletter1).

decrypt:
	ldrb	R5, [R3,R7]	@ loading ciphered text letter at index R7
	cmp	R9, R4
	bge	another2Way
	b	checkKeyLetter1
	
	@ checking if key is a-z, if yes i will decrypt(dothing3).
	@ else i will keep letter as is by going to update.
	
checkKeyLetter12:
	sub	R10, R10, #32
	cmp	R10, #26
	bge	update
	cmp	R10, #0
	blt	update
	b	doThing3

	@ Checking if the key is  A-Z, if yes i will decrypt(dothing3).
	@ Else I will check if letter is a-z by calling checkkeyletter12.

checkKeyLetter1:
	ldrb	R10, [R0,R9]	@ loading key letter at index r9
	sub	R10, R10, #'A'
	cmp	R10, #26
	bge	checkKeyLetter12
	cmp	R10, #0
	blt	checkKeyLetter12
	b	doThing3

	@ formula for decryption is
	@ (((encryptedWord[i] - key[i]) + 26) % 26) + 'A'
	@ for the remainder i am assuming result is between 51 and 0.
	@ ((encryptedWord[i] - key[i]) + 26)
	@ So am checking if its greater than 26 to go to subPartDecrypt,
	@ and deduct 26 so that i get remainder.
	@ I call finalEncryptDecryptPart for my final calculation.

doThing3:	
	ldrb	R10, [R0,R9]	@ loading key letter at index r9
	sub	R12, R5,R10	@ encryptedWord[i] - key[i]
	add	R12, R12,#26	@ (((encryptedWord[i] - key[i]) + 26) this result
				@ will be in range 1 - 51
	mov	R8, #26		@ get 26 to R8
	cmp	R12, R8		@ compare
	bge 	subPartDecrypt	@ if greater or equal, so we need to do another
				@ calculation to get remainder.%26.
	b	finalEncryptDecryptPart	@ if less, thats our remainder

	@ this will use the letters of decrypted word, to decrypt next set
	@ of ciphered text.since we ran out of key letters.
	@ Doing uppercase, lowercase letters check. If decrypt word letter is
	@ not a-z or A-Z keep letter as is.

another2Way:
	sub	R12, R9, R4
	mul	R10, R4, R4
	mov	R12, #4
	mul	R10, R10, R12
	sub	R12, R9, R4
	add	R10, SP, R10
	mov	R12, #1
	mul	R12, R12, R4
	mov	R10, #-1
	mul	R12, R12, R10
	ldrb	R10, [R11,R12]
	cmp	R10, #65
	bge	checkAgain2
	b	update

checkAgain2:
	cmp	R10, #90
	ble	goThing2
	sub	R10, R10, #32
	cmp	R10, #90
	ble	goThing2
	b	update

goThing2:
	sub 	R12, R5, R10	@ encryptedWord[i] - key[i]
	add 	R12,R12,#26	@ (((encryptedWord[i]-key[i])+26)
				@ this result will be in range 1 - 51
	mov	R8, #26		@ get 26 to r8.
	cmp	R12, R8		@ compare
	bge	subPartDecrypt	@ if greater or equal, so we need to do
				@ another calculation to get remainder.%26.
	b 	finalEncryptDecryptPart	@ if less, thats our remainder.


subPartDecrypt:
	sub	R12, R12, R8	@ sub another 26 to get remainder
	b	finalEncryptDecryptPart

	@ checking key index r9 with key length r4, to determine with
	@ what letter i will encrypt. If key index greater or equal than
	@ key length, i know i need to start using letters of plain text
	@ to continue encrypting. Else I keep using the key (checkKeyLetter2)
	@ letters.

encrypt:
	ldrb	R5, [R3,R7]	@ loading ciphered text letter at index r7
	cmp	R9, R4	
	bge	anotherWay
	b	checkKeyLetter2
	
	@ below 2 functions checkKeyLetter2 and checkKeyLetter22, i check
	@ if key is a-z/A-Z so i encrypt with the key letter (dothing4). 
	@ Else its space or some number, I do not encrypt and keep plain text
	@ letter as is (update).

checkKeyLetter22:
	sub	R10, R10, #32
	cmp	R10, #26
	bge	update
	cmp	R10, #0
	blt	update
	b	doThing4

checkKeyLetter2:
	ldrb	R10, [R0,R9]	@ loading key letter at index r9
	sub	R10, R10, #'A'
	cmp	R10, #26
	bge	checkKeyLetter22
	cmp	R10, #0
	blt	checkKeyLetter22
	b	doThing4

	@ formula for encryption is
	@ (((encryptedWord[i] + key[i])) % 26) + 'A'
	@ for the remainder  i am assuming result is between 180 and 130
	@ (encryptedWord[i] + key[i])
	@ So am checking if its equal to 130, if it is i go to subPartEncrypt
	@ to deduct 130-130 to get 0 as remainder. If not i go to
	@ subtractEncryptAgain

doThing4:
	ldrb	R10, [R0,R9]	@ loading key letter at index R9
	add	R12, R5, R10	@ encryptedWord[i] + key[i] result will be in
				@ range 130-180.
	mov 	R8, #130	@ move 130 to r8
	@ check if equal, call subPartEncrypt and remainder will be 0. if not we
	@ need to do subtraction.
	cmp	R12, R8
	beq	subPartEncrypt
	b	subtractEncryptAgain

	@ this will use the letters of plain text, to encrypt next set of plain
	@ text. Since we ran out of key letters.
	@ Doing uppercase, lowercase letters check. If  word letter is not
	@ a-z or A-Z keep letter as is.

anotherWay:
	sub	R12, R9, R4
	ldrb	R10, [R3,R12]	@ loading key letter at index R9
	cmp	R10,# 65
	bge	checkAgain	
	b	update
	add	R12, R5, R10	@ encryptedWord[i] + key[i]  result will be
				@ in range 130-180.
	mov	R8, #130	@ move 130 to r8
	@ check if equal, call subPartEncrypt and remainder will be 0. if not
	@ we need to do subtraction.
	cmp	R12, R8
	beq	subPartEncrypt
	b	subtractEncryptAgain

checkAgain:
	cmp	R10, #90
	ble	goThing
	sub R10, R10, #32
	cmp	R10, #65
	bge	checkAgain1	
	add R10, R10, #32
	b	update
	
checkAgain1:
	cmp	R10, #90
	ble	goThing
	add R10, R10, #32
	b	update


goThing:
	add	R12, R5, R10	@ encryptedWord[i] + key[i]  result will be in
				@ range 130-180.
	mov	R8, #130	@ move 130 to R8
	@ check if equal, call subPartEncrypt and remainder will be 0. If not
	@ we need to do subtraction.
	cmp	R12, R8	
	beq	subPartEncrypt
	b	subtractEncryptAgain

subPartEncrypt:
	sub	R12, R8, R12	@ remainder will be 0
	b	finalEncryptDecryptPart

	@ If greater than 156 ( encryptedWord[i] + key[i]) call
	@ subtractThanChangeAgain
	@ else subtract ( encryptedWord[i] + key[i]) - 130 to get remainder.

subtractEncryptAgain:
	mov	R8, #156	@ move 156 to R8
	@ compare if greater than 156, we need to do another subtraction.
	@ else if not, do that number ( 154 for example) - 130 to get remainder.
	cmp	R12, R8 
	bge	subtractThanChangeAgain
	mov	R8,#130
	sub	R12, R12, R8
	b	finalEncryptDecryptPart

	@ in case ( encryptedWord[i] + key[i]) more than 156. We do 
	@ (encryptedWord[i] + key[i]) - 156 to get remainder.

subtractThanChangeAgain:
	sub	R12, R12, R8	@ to get remainder
	b	finalEncryptDecryptPart

	@ continuting of implementation of encrypt/decrypt formula.
	@ We add A to it.Than we want to write to outbuff.
	@ We updated index of loop over plain/cipher text as well as index
	@ of key (R9) in case R9 index of key is equal to R4 (length of key)
	@ we reset R9 to 0.

finalEncryptDecryptPart:
	cmp 	R6, #1		@ we kept above in R6, whether letter we
				@ encrypting or decrypting is uppercase or
				@ lowercase.
	beq	addSmallA
	b	addCapitalA

addSmallA:
	add	R12, R12, #'a'
	b	storeValue
	

addCapitalA:
	add	R12, R12, #'A'

	@ Lets store every character encrypted/decrypted out. And update
	@ indexes. Check if we reached end of key too (cmp R9,R4). If yes,
	@ reset key index R9 back to 0.

storeValue:
	strb	R12, [R11], #1
	add	R9, R9, #1
	add	R7, R7, #1
	b	startLoop
		
	@ return into R0,the result. And R2 is length to print.

finishProcess:	
	mov	R5, R0
	mov	R8, R3
	mul	R11, R4, R4
	mov	R7, #4
	mul	R11, R11, R7
	add 	R11, SP, R11
	mul	R7, R4, R4
	add	R11, R11, R7	@ where we want to print from on stack.
	mov	R7, #0
	mov	R0, R11	
	pop	{R6,R7,R10}
	mov	pc, lr


.data
	encryptStr: .ascii "encrypt"
		.equ encryptStrlen, (.-encryptStr)

	decryptStr: .ascii "decrypt"
		.equ decryptStrlen, (.-decryptStr)
