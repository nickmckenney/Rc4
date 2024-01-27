#include <Windows.h>
#include <stdio.h>
unsigned char shellcode[] = {
	"THIS IS SHELLCODE!"
};

//I used this for help to create my RC4 -> https://oryx-embedded.com/doc/rc4_8h_source.html#l00050

typedef struct
{
	int i;
	int j;
	char s[256];
} Rc4Context;

void Rc4(Rc4Context* rc4Context, const unsigned char* input, const unsigned int* j) {
	unsigned int i, j;
	unsigned char temp;

	rc4Context->i, j = 0;


}


void main(){
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



	BOOL bBringBackSwap = VirtualUnlock(bRemoveSwap, lenShell);
	if (!bBringBackSwap) {
		return 1;
	}
	BOOL bReleaseDaMemory  = VirtualFree(pStartAddress, lenShell, MEM_RELEASE);




}
