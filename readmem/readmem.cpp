// readmem.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <iomanip>

void ProtectConstantToString(DWORD dwProtect, char * szBuffer, size_t len) 
{
	szBuffer[0] = '\0';
	int i = 0;

	if (dwProtect & PAGE_EXECUTE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_EXECUTE");
	}
	if (dwProtect & PAGE_EXECUTE_READ)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_EXECUTE_READ");
	}
	if (dwProtect & PAGE_EXECUTE_READWRITE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_EXECUTE_READWRITE");
	}
	if (dwProtect & PAGE_EXECUTE_WRITECOPY)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_EXECUTE_WRITECOPY");
	}
	if (dwProtect & PAGE_NOACCESS)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_NOACCESS");
	}
	if (dwProtect & PAGE_READONLY)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_READONLY");
	}
	if (dwProtect & PAGE_READWRITE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_READWRITE");
	}
	if (dwProtect & PAGE_WRITECOPY)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_WRITECOPY");
	}
	if (dwProtect & PAGE_TARGETS_INVALID)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_TARGETS_INVALID");
	}
	if (dwProtect & PAGE_GUARD)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_GUARD");
	}
	if (dwProtect & PAGE_NOCACHE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_NOCACHE");
	}
	if (dwProtect & PAGE_WRITECOMBINE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "PAGE_WRITECOMBINE");
	}
}

void PageStateConstantToString(DWORD dwState, char * szBuffer, size_t len) 
{
	szBuffer[0] = '\0';
	int i = 0;
	
	if (dwState & MEM_COMMIT)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_COMMIT");
	}
	if (dwState & MEM_RESERVE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_RESERVE");
	}
	if (dwState & MEM_FREE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_FREE");
	}
	if (dwState & MEM_RESET)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_RESET");
	}
	if (dwState & MEM_RESET_UNDO)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_RESET_UNDO");
	}
	if (dwState & MEM_LARGE_PAGES)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_LARGE_PAGES");
	}
	if (dwState & MEM_PHYSICAL)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_PHYSICAL");
	}
	if (dwState & MEM_TOP_DOWN)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_TOP_DOWN");
	}
	if (dwState & MEM_WRITE_WATCH)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_WRITE_WATCH");
	}
}

void PageTypeConstantToString(DWORD dwType, char * szBuffer, size_t len)
{
	szBuffer[0] = '\0';
	int i = 0;

	if (dwType & MEM_IMAGE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_IMAGE");
	}
	if (dwType & MEM_MAPPED)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_MAPPED");
	}
	if (dwType & MEM_PRIVATE)
	{
		if (i++ > 0) strcat_s(szBuffer, len, " | ");
		strcat_s(szBuffer, len, "MEM_PRIVATE");
	}
}

int main(int argc, char* argv[])
{
	ULONG dwProcessId = 0;
	DWORD pAddr = 0;
	SIZE_T dwBytes = 0;
	DWORD dwByteOutputMode = 0;
	DWORD dwWidth = 4;
	BOOL outputQuery = 0;
	char szOutputFilePath[MAX_PATH]; szOutputFilePath[0] = '\0';

	for (int i = 0; i < argc; i++)
	{
		if (_stricmp(argv[i], "-pid") == 0 && (i + 1) < argc)
		{
			DWORD pid = strtoul(argv[++i], NULL, 0);
			if (!(pid & 0xFFFF0000) && pid)
			{
				dwProcessId = pid;
			}
			else {
				printf("Process id parameter is out of range.\n");
			}
		}

		if ((_stricmp(argv[i], "-b") == 0 || _stricmp(argv[i], "-bytes") == 0) && (i + 1) < argc)
		{
			dwBytes = strtoul(argv[++i], NULL, 0);
		}

		if ((_stricmp(argv[i], "-a") == 0 || _stricmp(argv[i], "-address") == 0) && (i + 1) < argc)
		{
			DWORD addr = strtoul(argv[++i], NULL, 0);
			if (addr & 0xFFFF0000)
			{
				pAddr = addr;
			}
			else {
				printf("Address parameter is out of range.\n");
			}
		}

		if ((_stricmp(argv[i], "-m") == 0 || _stricmp(argv[i], "-mode") == 0) && (i + 1) < argc)
		{
			const char * mode = argv[++i];
			if (_stricmp(mode, "arr") == 0 || _stricmp(mode, "array") == 0)
				dwByteOutputMode = 1;
			else if (_stricmp(mode, "mem") == 0 || _stricmp(mode, "memory") == 0)
				dwByteOutputMode = 2;
			else if (_stricmp(mode, "asm") == 0 || _stricmp(mode, "assembly") == 0)
				dwByteOutputMode = 3;
		}

		if ((_stricmp(argv[i], "-w") == 0 || _stricmp(argv[i], "-width") == 0) && (i + 1) < argc)
		{
			dwWidth = strtoul(argv[++i], NULL, 0);
		}

		if (_stricmp(argv[i], "-q") == 0)
		{
			outputQuery = TRUE;
		}

		if (_stricmp(argv[i], "-o") == 0 && (i + 1) < argc)
		{
			strcpy_s(szOutputFilePath, argv[++i]);
		}
	}

	std::ofstream outputFile;
	std::streambuf *coutbuf = std::cout.rdbuf();
	if (strlen(szOutputFilePath))
	{
		outputFile.open(szOutputFilePath);
		if (!outputFile.is_open())
		{
			printf("Could not open output file at %s\n", szOutputFilePath);
			return 0;
		}

		std::cout.set_rdbuf(outputFile.rdbuf());
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwProcessId);
	if (hProcess == NULL)
	{
		printf("Could not open handle to the specified process.\n");
		return 0;
	}

	if (outputQuery)
	{
		PMEMORY_BASIC_INFORMATION pPageInfo = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(_MEMORY_BASIC_INFORMATION));
		ZeroMemory(pPageInfo, sizeof(_MEMORY_BASIC_INFORMATION));

		if (VirtualQueryEx(hProcess, (LPVOID)pAddr, pPageInfo, sizeof(_MEMORY_BASIC_INFORMATION)))
		{
			char szBuffer[512];
			
			std::cout << "BaseAddress: 0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << pPageInfo->BaseAddress << std::endl;

			std::cout << "AllocationBase: 0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << pPageInfo->AllocationBase << std::endl;

			ProtectConstantToString(pPageInfo->AllocationProtect, szBuffer, 512);
			std::cout << "AllocationProtect: 0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << pPageInfo->AllocationProtect
				<< " (" << szBuffer << ")" << std::endl;

			std::cout << "RegionSize: 0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << pPageInfo->RegionSize
				<< " (" << std::setw(0) << std::dec << pPageInfo->RegionSize << ")" << std::endl;

			PageStateConstantToString(pPageInfo->State, szBuffer, 512);
			std::cout << "State: 0x" << std::uppercase << std::setfill('0') << std::setw(5) << std::hex << pPageInfo->State
				<< " (" << szBuffer << ")" << std::endl;
			
			ProtectConstantToString(pPageInfo->Protect, szBuffer, 512);
			std::cout << "Protect: 0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << pPageInfo->Protect
				<< " (" << szBuffer << ")" << std::endl;

			PageTypeConstantToString(pPageInfo->Type, szBuffer, 512);
			std::cout << "Type: 0x" << std::uppercase << std::setfill('0') << std::setw(7) << std::hex << pPageInfo->Type
				<< " (" << szBuffer << ")" << std::endl;

			std::cout << std::endl;
		}
		
		free(pPageInfo);
	}

	if (dwBytes)
	{
		SIZE_T dwNumBytesRead = 0;
		PBYTE pBytes = (PBYTE)malloc(dwBytes);

		ReadProcessMemory(hProcess, (LPVOID)pAddr, pBytes, dwBytes, &dwNumBytesRead);

		CloseHandle(hProcess);

		std::cout << "Bytes read: " << std::dec << dwNumBytesRead << std::endl;

		for (int i = 0; i < dwNumBytesRead; i++)
		{
			if (dwByteOutputMode == 0)
			{
				if (i != 0) std::cout << " ";
			}
			else if (dwByteOutputMode == 1)
			{
				if (i == 0) std::cout << "{ ";
				else std::cout << ", ";
				std::cout << "0x";
			}
			else if (dwByteOutputMode == 2 || dwByteOutputMode == 3)
			{
				if (i % dwWidth == 0)
				{
					if (i != 0) std::cout << std::endl;

					std::cout << "0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << (pAddr + i) << ":\t";
				}
				else std::cout << " ";
			}

			std::cout << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (INT)pBytes[i];

			if (dwByteOutputMode == 1 && i == (dwNumBytesRead - 1)) std::cout << " };";
		}

		std::cout << std::endl;

		free(pBytes);
	}
	
	if (outputFile.is_open())
	{
		std::cout.set_rdbuf(coutbuf);
		outputFile.close();

		std::cout << "Wrote output to " << szOutputFilePath << std::endl;
	}
}