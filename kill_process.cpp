#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <ntstatus.h>
#pragma comment(lib,"kernel32.lib")
DWORD Kill_process(char* pn)			//Process name
{
	PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = 0;
    DWORD dwExitCode = 0;
    BOOLEAN bEnabled;
 
    HANDLE hProessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProessSnap != INVALID_HANDLE_VALUE)
    {
        if (::Process32First(hProessSnap, &pe32))
        {
            do
            {
                if ( strcmp(pe32.szExeFile, pn) == 0)
                {
                    hProcess = ::OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|PROCESS_CREATE_THREAD, FALSE, pe32.th32ProcessID);
                    CloseHandle(hProessSnap);
                    break;   
                }
            }while(::Process32Next(hProessSnap, &pe32));
        }   
    }
 	
    LPVOID Param = VirtualAllocEx(hProcess, NULL, sizeof(DWORD), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, Param, (LPVOID)&dwExitCode, sizeof(DWORD), NULL);
 
    HANDLE hThread = CreateRemoteThread(hProcess, 
        NULL, 
        NULL, 
        (LPTHREAD_START_ROUTINE)ExitProcess,
        Param, 
        NULL, 
        NULL);
    return GetLastError();
}
int main(int argc, char **argv)
{
	char a[1000];
    printf("Enter the Process Name to kill:\n");
	scanf("%s", a);
	if (Kill_process(a) == 0)
		printf("Succeed!\n");
	else printf("Error!\n");
	getchar();				//pause the program
    return 0;
}
