#include <Windows.h>
#include <stdio.h>
unsigned char shellcode[] = {
	"THIS IS SHELLCODE!!!"
};
unsigned char key[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
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
	//printf("Rc4Encryption");
	//printf("%d ", rc4Context->s);
	while (length > 0) {
		j = (i + 1) % 256;
		j = (j + s[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		if (input != NULL && output != NULL) {
			*output = *input ^ s[(s[i] + s[j]) % 256];
			input++, output++;

		}
		length--;
	}
	rc4Context->i = i;
	rc4Context->j = j;
	//printf("%d ", rc4Context);
}
void main(){
	Rc4Context ctx = { 0 };
	//ctx is the rc4context with a key
	Rc4CreateKey(&ctx, key, sizeof(key));
	SIZE_T lenShell = strlen(shellcode) * sizeof(int);
	LPVOID pStartAddress = (unsigned char*)VirtualAlloc(
		NULL, 
		strlen(shellcode) * sizeof(int), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);
	BOOL bRemoveSwap = VirtualLock(
		pStartAddress,
		lenShell
	);
	if (!bRemoveSwap) {
		return 1;
	}
	SecureZeroMemory(pStartAddress, lenShell);
	printf("0x%p \n", pStartAddress);
	printf("[i] PlainText : \"%s\" \n", (char*)pStartAddress);
	BOOL bBringBackSwap = VirtualUnlock(bRemoveSwap, lenShell);
	if (!bBringBackSwap) {
		return 1;
	}


	BOOL bReleaseDaMemory  = VirtualFree(pStartAddress, lenShell, MEM_RELEASE);
}
