#include <Windows.h>
#include <stdio.h>
unsigned char shellcode[] = {
	"THIS IS SHELLCODE!!!"
};
unsigned char key[] = {
0x4F, 0x2E, 0x8B, 0x7D, 0x1C, 0x6F, 0x03, 0x5A, 0x98, 0xB2, 0xE7, 0xD4, 0xF1, 0xC6, 0x03, 0x9A
};
//I used this for help to create my RC4 -> https://oryx-embedded.com/doc/rc4_8h_source.html#l00050
typedef struct
{
	int i;
	int j;
	char s[256];
} Rc4Context;
void Rc4CreateKey(Rc4Context* rc4Context, const unsigned int* key,size_t length) {
	unsigned int i, j;
	unsigned char temp;
	rc4Context->i, j = 0;
	for (i = 0; i < 256; i++) {
		rc4Context->s[i] = i;
	}
	for (i = 0, j = 0; i < 256; i++) {
		j = j + rc4Context->s[i] + key[i%length];
		j = j % 256;
		temp = rc4Context->s[i];
		rc4Context->s[i] = rc4Context->s[j];
		rc4Context->s[j] = temp;
	}
}
void Rc4Encryption(Rc4Context* rc4Context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;
	unsigned int i = rc4Context->i;
	unsigned int j = rc4Context->j;
	unsigned char* s = rc4Context->s;
	while (length > 0) {
		j = (i + 1) % 256;
		j = (j + s[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		if (input != NULL && output != NULL) {
			*output = *input ^ s[(s[i] + s[j]) % 256];
			input++;
			output++;

		}
		length--;
	}
	rc4Context->i = i;
	rc4Context->j = j;
}

void main(){
	Rc4Context ctx = { 0 };
	//ctx is the rc4context with a key
	Rc4CreateKey(&ctx, key, sizeof(key)); //Creates key
	LPVOID pStartAddressOfCipher = (unsigned char*)VirtualAlloc(
		NULL,
		strlen(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	RtlMoveMemory(pStartAddressOfCipher, shellcode, strlen(shellcode));
	BOOL bRemoveSwap = VirtualLock(
		pStartAddressOfCipher,
		strlen(shellcode)
	); if (!bRemoveSwap) { return 1; }
	//My Encryption--------------------------
	SecureZeroMemory(pStartAddressOfCipher, strlen(shellcode) * sizeof(int));
	Rc4Encryption(&ctx, shellcode, pStartAddressOfCipher, strlen(shellcode));
	
	//RtlMoveMemory(pStartAddressOfCipher, (char*)pStartAddressOfCipher, lenEncryptShell);
	printf("CipherText : \"%s\" \n", (char*)pStartAddressOfCipher);
	printf("-----------------------");
	getchar();
	//My END OF Encryption------------------------------
	// 
	Rc4CreateKey(&ctx, key, sizeof(key)); //Creates key
	//My Decryption
	LPVOID PlainText = (unsigned char*)VirtualAlloc(
		NULL,
		strlen(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	SecureZeroMemory(PlainText, strlen(shellcode) * sizeof(int));
	Rc4Encryption(&ctx, pStartAddressOfCipher,PlainText, strlen(shellcode));
	printf("[i] PlainText : \"%s\" \n", (char*)PlainText);
	RtlMoveMemory(pStartAddressOfCipher, (char*)PlainText, strlen(shellcode));
	//Frees -----------------------------------------------
	
	BOOL bBringBackSwap = VirtualUnlock(bRemoveSwap, strlen(shellcode));
	if (!bBringBackSwap) {
		return 1;
	}
	BOOL bReleaseDaMemory  = VirtualFree(pStartAddressOfCipher, strlen(shellcode), MEM_RELEASE);
	}
