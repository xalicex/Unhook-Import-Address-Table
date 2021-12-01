#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h> 
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <dbghelp.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")

unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };


typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);

void UnhookIAT() {

	ULONG size;
	DWORD i;
	DWORD j;
	DWORD oldProtect = 0;
	LPVOID TrueRVA;
	

	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);

	// get a HANDLE to a main module == BaseImage of PE
	
	HANDLE baseAddress = GetModuleHandle(NULL);		
	
	// get Import Table of PE
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	//Get name of DLL in import table
	int nbelement = (size/20)-1;
	for (i = 0; i < nbelement ; i++){
		
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		printf("Imported DLL name : %s\n",importName);
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].OriginalFirstThunk);
		PIMAGE_IMPORT_BY_NAME functionName = NULL; 
		const LPVOID pMapping = (LPVOID)GetModuleHandle((LPCSTR)importName);
		
		//int cpt = 0;
		while (originalFirstThunk->u1.AddressOfData != NULL){
			
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)baseAddress + originalFirstThunk->u1.AddressOfData);
			if(((((
			(_stricmp(functionName->Name, "EnterCriticalSection") != 0)
			&&(_stricmp(functionName->Name, "LeaveCriticalSection") != 0))
			&&((_stricmp(functionName->Name, "DeleteCriticalSection") != 0)
			&&(_stricmp(functionName->Name, "InitializeSListHead") != 0)))
			&&((_stricmp(functionName->Name, "HeapAlloc") != 0)
			&&(_stricmp(functionName->Name, "HeapReAlloc") != 0)))
			&&(_stricmp(functionName->Name, "HeapSize") != 0)
			)){
				//load fresh dll from disk
				PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
				PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
				PIMAGE_EXPORT_DIRECTORY pImgExpDir =(PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pMapping+pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				PDWORD Address=(PDWORD)((LPBYTE)pMapping+pImgExpDir->AddressOfFunctions);
				PDWORD Name=(PDWORD)((LPBYTE)pMapping+pImgExpDir->AddressOfNames);
				PWORD Ordinal=(PWORD)((LPBYTE)pMapping+pImgExpDir->AddressOfNameOrdinals);
				DWORD OrdinalBase= pImgExpDir->Base;
				DWORD OrdFunction;

				//Get RVA from fresh DLL
				for(j=0;j<pImgExpDir->NumberOfFunctions;j++){
					if(!strcmp(functionName->Name,(char*)pMapping+Name[j])){
						TrueRVA = (PVOID)((LPBYTE)Address[Ordinal[j]]);
						break;
					}
				}
		
				uintptr_t moduleBase = (uintptr_t)pMapping;
				uintptr_t RVA = (uintptr_t)TrueRVA;
				uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
				PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;

				if(*currentFuncAddr != (PROC)(TrueAddress)) {
					oldProtect = 0;
					VirtualProtect_p((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect); 
					printf("Bad News ! Function %s is hooked ! Address is %x and it's suppose to be %x \nUnhook like the captain !\n",functionName->Name, *currentFuncAddr, TrueAddress);
					*currentFuncAddr = (PROC)(TrueAddress);
					VirtualProtect_p((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);
				}else{
					printf("Good news ! Function %s is not hooked :D\n",functionName->Name);
				}
			}
			++originalFirstThunk;
			++thunk;
		}
	}
}


int main(void) {
   
	UnhookIAT();
	
	return 0;
}
