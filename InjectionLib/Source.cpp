#include <Windows.h>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>
#include <list>
#include <Psapi.h>

/*
Life:
Undertale.exe + 0039A148 -> val
val + 18 -> val2
val2 + 2F8 -> addr
addr -> life

MaxLife:
Undertale.exe + 0039B224 -> val
val + 3F4 -> val2
val2 + 298 -> val3
val3 + 164 -> val4
val4 + 18 -> val5
val5 + 2C8 -> addr
addr -> lifemax
*/

#define KEY_DOWN 0
#define KEY_UP 1
#define VK_DOLLAR 186
#define HAVE_GUARD(value)((value / PAGE_GUARD) >= 1 && 2 > (value / PAGE_GUARD))
LPVOID baseAddr;
HWND cWindow;

/*Utils*/
template<typename T>
T readMemory(LPVOID addr)
{
	return *((T*)addr);
}

template<typename T>
void writeMemory(LPVOID addr, T val)
{
	*((T*)addr) = val;
}

void printLogs(std::string s)
{
	s += "\n";
	std::ofstream libfile("C:\\Users\\OOM\\Documents\\Visual Studio 2017\\Projects\\UnderTaleInfiniteLifev101PatchFr\\logs.txt", std::ios::out | std::ios::app | std::ios::binary);
	libfile.write(s.c_str(), strlen(s.c_str()));
	libfile.close();
}

/*Cheat*/
void TurnFullLife()
{
	
	LPVOID addr = baseAddr;
		
	//Read max life
	addr = baseAddr;
	addr = (LPVOID)readMemory<DWORD>(addr);
	addr = (LPVOID)readMemory<DWORD>((LPVOID)((DWORD)addr + 0));
	addr = (LPVOID)readMemory<DWORD>((LPVOID)((DWORD)addr + 4));
	addr = (LPVOID)((DWORD)addr + 0x1A0);
	double maxlife = readMemory<double>(addr);

	//Write max life
	addr = baseAddr;
	addr = (LPVOID)readMemory<DWORD>(addr);
	addr = (LPVOID)readMemory<DWORD>((LPVOID)((DWORD)addr + 0));
	addr = (LPVOID)readMemory<DWORD>((LPVOID)((DWORD)addr + 4));
	addr = (LPVOID)((DWORD)addr + 0x1D0);
	writeMemory<double>(addr, maxlife);
	
	printLogs("Done");
}

/*Key detection and main*/
BYTE hex2byte(std::string const & hex)
{
	unsigned short byte = 0;
	std::istringstream iss(hex.c_str());
	iss >> std::hex >> byte;
	return byte % 0x100;
}

bool IsWindowInFocus()
{
	HWND zb = GetForegroundWindow();
	return cWindow == zb;
}

DWORD WINAPI hookKeys(LPVOID lparam)
{
	bool keydown = false;
	bool keystate = false;
	while (true)
	{
		keystate = (GetAsyncKeyState(VK_DOLLAR) & 0x8000) ? 0 : 1;
		if (keystate == KEY_DOWN && !keydown)
			keydown = true;
		else if (keystate == KEY_UP && keydown)
		{
			keydown = false;
			if (IsWindowInFocus()) //check after to win time on key detection
				TurnFullLife();
		}
		Sleep(10);
	}

	return 1;
}

LPVOID ScanCurrentProcessMemoryFromPattern(std::string pattern) //get pattern in memory 
{
	printLogs("Lancement du thread");
	std::list<std::string> dividedPattern;
	size_t pos = 0;
	std::string token;

	printLogs("Pattern: " + pattern);
	while ((pos = pattern.find(" ")) != std::string::npos) { //get all byte in string
		token = pattern.substr(0, pos);
		dividedPattern.push_back(token);
		pattern.erase(0, pos + 1);
	}
	printLogs("Pattern parsé");

	MEMORY_BASIC_INFORMATION mbi; //scan memory
	DWORD ptr = NULL;
	int index = 0;
	int number = 0;
	while (VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi)) != 0)
	{

		number++;
		if ((DWORD)ptr != 0x0078D000)
		{
			ptr = ((DWORD)mbi.BaseAddress + mbi.RegionSize);
			continue;
		}
		if (mbi.State != MEM_RESERVE && mbi.Protect != PAGE_NOACCESS && !(HAVE_GUARD(mbi.Protect)) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE || mbi.AllocationProtect == PAGE_READWRITE))
		{
			printLogs("Nouvel plage");
			std::stringstream stream;
			stream << "--Numéro" << std::dec << number << std::endl;
			stream << "--AllocationBase: 0x" << std::hex << mbi.AllocationBase << std::endl;
			stream << "--RegionSize: 0x" << std::hex << mbi.RegionSize << std::endl;
			stream << "--State: 0x" << std::hex << mbi.State << std::endl;
			stream << "--Protect: 0x" << std::hex << mbi.Protect << std::endl;
			stream << "--AllocationProtect: 0x" << std::hex << mbi.AllocationProtect << std::endl;

			printLogs(stream.str());
			SIZE_T i = 0;
			SIZE_T scanindex = 0;
			BYTE currval = 0;
			BYTE byte = 0;
			std::list<std::string>::iterator it;
			SIZE_T sizescan = dividedPattern.size();
			for (i = 0; i < mbi.RegionSize; i++)
			{
				currval = *((BYTE*)((DWORD)mbi.BaseAddress + i));
				it = std::next(dividedPattern.begin(), scanindex);
				if (*it == "*") //joker token
				{
					scanindex++;
					if (sizescan <= scanindex)
						return (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1)); //find
				}
				else //check byte
				{
					byte = hex2byte(*it);
					if (currval == byte)
					{
						scanindex++;
						if (sizescan <= scanindex)
							return (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1)); //find
					}
					else if (scanindex > 0 && currval != byte)
					{
						i = (i - scanindex) + 1;
						scanindex = 0;
					}
				}
			}
		}
		ptr = (DWORD)((DWORD)mbi.BaseAddress + mbi.RegionSize);
	}
	return 0;
} //useless but good for future

LPVOID ScanMainModuleFromPattern(std::string pattern)
{
	printLogs("Lancement scan main module");
	std::list<std::string> dividedPattern;
	size_t pos = 0;
	std::string token;

	printLogs("Pattern: " + pattern);
	while ((pos = pattern.find(" ")) != std::string::npos) { //get all byte in string
		token = pattern.substr(0, pos);
		dividedPattern.push_back(token);
		pattern.erase(0, pos + 1);
	}
	printLogs("Pattern parsé");

	HMODULE base = GetModuleHandle(NULL);
	HANDLE proc = GetCurrentProcess();
	MODULEINFO  lpmodinfo;
	GetModuleInformation(proc, base, &lpmodinfo, sizeof(lpmodinfo));


	SIZE_T scanindex = 0;
	BYTE currval = 0;
	BYTE byte = 0;
	std::list<std::string>::iterator it;
	SIZE_T sizescan = dividedPattern.size();
	DWORD i = 0;
	for (i = 0; i < lpmodinfo.SizeOfImage; i++)
	{
		currval = *((BYTE*)((DWORD)lpmodinfo.lpBaseOfDll + i));
		it = std::next(dividedPattern.begin(), scanindex);
		if (*it == "*") //joker token
		{
			scanindex++;
			if (sizescan <= scanindex)
				return (LPVOID)((DWORD)lpmodinfo.lpBaseOfDll + (i - scanindex + 1)); //find
		}
		else //check byte
		{
			byte = hex2byte(*it);
			if (currval == byte)
			{
				scanindex++;
				if (sizescan <= scanindex)
					return (LPVOID)((DWORD)lpmodinfo.lpBaseOfDll + (i - scanindex + 1)); //find
			}
			else if (scanindex > 0 && currval != byte)
			{
				i = (i - scanindex) + 1;
				scanindex = 0;
			}
		}
	}

	return 0;
}

DWORD WINAPI runDll(LPVOID lparam)
{
	HANDLE thread;

	printLogs("Lancement du Thread (scan)");
	baseAddr = ScanMainModuleFromPattern("89 5E * 8B 0D * * * * 8D 87");
	printLogs(baseAddr == 0 ? "PAS TROUVER" : "TROUVEYYYYYY");
	baseAddr = (LPVOID)((DWORD)baseAddr + 5);
	thread = CreateThread(NULL, 0, &hookKeys, NULL, 0, NULL); //runkey detection thread
	CloseHandle(thread);
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	HANDLE thread;

	if (reason == DLL_PROCESS_ATTACH)
	{
		printLogs("Lancement du Thread (DLL)");
		cWindow = FindWindowA(NULL, "UNDERTALE");
		thread = CreateThread(NULL, 0, &runDll, NULL, 0, NULL); //run memoryscan
		CloseHandle(thread);
	}
	return TRUE;
}