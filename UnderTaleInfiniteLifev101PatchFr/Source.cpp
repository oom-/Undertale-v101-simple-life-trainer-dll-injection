#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <cstdio>
#include <fstream>
#include <list>
#include <sstream>
#include <Windows.h>
#include <tlhelp32.h>

#include <Psapi.h>

bool writeTempLibrary(const std::string& path)
{
	char lib[] = { (char)0X1
	};

	try {
		std::ofstream libfile(path, std::ios::out | std::ios::trunc | std::ios::binary);
		libfile.write(lib, sizeof(lib));
		return true;
	}
	catch (std::exception const& e)
	{
		return false;
	}
}

bool deleteTempLibrary(const std::string& path)
{
	try {
		return remove(path.c_str()) == 0;
	}
	catch (std::exception const&e)
	{
		return false;
	}
}

int getProcID(const std::string& processName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };
	int id = 0;

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);
	if (snapshot == INVALID_HANDLE_VALUE) return id;
	if (Process32First(snapshot, &structprocsnapshot) == FALSE) return id;
	while (Process32Next(snapshot, &structprocsnapshot))
	{
		if (!strcmp(structprocsnapshot.szExeFile, processName.c_str()))
		{
			id = structprocsnapshot.th32ProcessID;
			break;
		}
	}
	CloseHandle(snapshot);
	return id;
}

bool InjectDLL(const int &pid, const std::string &path)
{
	long dllPathSize = path.length() + 1;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProc == NULL)
	{
		std::cerr << "[!]Fail to open target process!" << std::endl;
		return false;
	}
	std::cout << "[+]Opening Target Process..." << std::endl;

	LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, dllPathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (MyAlloc == NULL)
	{
		std::cerr << "[!]Fail to allocate memory in Target Process." << std::endl;
		return false;
	}

	std::cout << "[+]Allocating memory in Targer Process." << std::endl;
	int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, path.c_str(), dllPathSize, 0);
	if (IsWriteOK == 0)
	{
		std::cerr << "[!]Fail to write in Target Process memory." << std::endl;
		return false;
	}
	std::cout << "[+]Creating Remote Thread in Target Process" << std::endl;

	DWORD dWord;
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
	HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL)
	{
		std::cerr << "[!]Fail to create Remote Thread" << std::endl;
		return false;
	}

	if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteOK != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL))
	{
		std::cout << "[+]DLL Successfully Injected :)" << std::endl;
		return true;
	}

	return false;
}


/*Key detection and main*/
BYTE hex2byte(std::string const & hex)
{
	unsigned short byte = 0;
	std::istringstream iss(hex.c_str());
	iss >> std::hex >> byte;
	return byte % 0x100;
}

#define HAVE_GUARD(value)((value / PAGE_GUARD) >= 1 && 2 > (value / PAGE_GUARD))

LPVOID ScanMainModuleFromPattern(std::string pattern)
{
	std::cout << "Lancement scan main module" << std::endl;;
	std::list<std::string> dividedPattern;
	size_t pos = 0;
	std::string token;

	std::cout << "Pattern: " + pattern << std::endl;
	while ((pos = pattern.find(" ")) != std::string::npos) { //get all byte in string
		token = pattern.substr(0, pos);
		dividedPattern.push_back(token);
		pattern.erase(0, pos + 1);
	}
	std::cout << "Pattern parsé" << std::endl;

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


LPVOID ScanCurrentProcessMemoryFromPattern(std::string pattern) //get pattern in memory 
{
	std::list<std::string> dividedPattern;
	size_t pos = 0;
	std::string token;

	while ((pos = pattern.find(" ")) != std::string::npos) { //get all pattern bytes
		token = pattern.substr(0, pos);
		std::cout << token << std::endl;
		dividedPattern.push_back(token);
		pattern.erase(0, pos + 1);
	}

	MEMORY_BASIC_INFORMATION mbi;
	DWORD mainModuleAddr = (DWORD)GetModuleHandle(NULL);
	VirtualQuery((LPVOID)mainModuleAddr, &mbi, sizeof(mbi));
	std::cout << "Main module Region Size: " << mbi.RegionSize << std::endl;


	LPVOID ptr = 0;
	int index = 0;
	while (VirtualQuery(ptr, &mbi, sizeof(mbi)) != 0)
	{
		if (mbi.State != MEM_RESERVE && !(HAVE_GUARD(mbi.Protect)) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE || mbi.AllocationProtect == PAGE_READWRITE))
		{
			//TODO: check le pattern -> byte now avec les ??
			std::cout << "Page: " << "0x" << std::hex << mbi.BaseAddress;
			std::cout << " Size: " << std::dec << mbi.RegionSize << std::endl;
			std::cout << " -- Scan -- " << std::endl;
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
				if (*it == "*")
				{
					if (scanindex > 1)
						std::cout << "Found(" << std::dec << i << "/" << std::dec << scanindex << "): " << "joker" << std::endl;
					scanindex++;
					if (sizescan <= scanindex)
					{
						std::cout << "Found -> 0x" << std::hex << (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1)) << std::endl;
						return (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1));
					}
				}
				else
				{
					byte = hex2byte(*it);
					if (currval == byte)
					{
						if (scanindex > 1)
							std::cout << "Found(" << std::dec << i << "/" << std::dec << scanindex << "): " << std::hex << byte << std::endl;
						scanindex++;
						if (sizescan <= scanindex)
						{
							std::cout << "Found -> 0x" << std::hex << (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1)) << std::endl;
							return (LPVOID)((DWORD)mbi.BaseAddress + (i - scanindex + 1));
						}
					}
					else if (scanindex > 0 && currval != byte)
					{

						i = (i - scanindex) + 1;
						if (scanindex > 1)
							std::cout << " -- Reset(" << std::dec << i << "/" << scanindex << ") -- " << std::endl;
						scanindex = 0;
					}
				}
			}
		}
		ptr = (LPVOID)((DWORD)mbi.BaseAddress + mbi.RegionSize);
	}

	return 0;
}

int main()
{
	std::string c = "COUCOU";
	const char *bo = c.c_str();

	std::cout << std::hex << (int)bo[0] << std::endl;
	std::cout << std::hex << (int)bo[1] << std::endl;
	std::cout << std::hex << (int)bo[2] << std::endl;
	std::cout << std::hex << (int)bo[3] << std::endl;
	std::cout << std::hex << (int)bo[4] << std::endl;
	std::cout << std::hex << (int)bo[5] << std::endl;
	std::cout << c << std::endl;
	bool keydown = false;
	bool keystate = true; //true UP
	LPVOID adress = ScanMainModuleFromPattern("43 4f 55 * 4f 55"); //"89 5E * 8B 0D * * * * 8D 87"
	std::cout << "-> 0x" << std::hex << adress << std::dec << std::endl;/*
	while (true)
	{

		/*for (int i = 0; i < 256; i++)
			if (GetAsyncKeyState(i) != 0)
				std::cout << "GetAsyncKeyState (" << i << "): " << GetAsyncKeyState(i) << std::endl.
		keystate = (GetAsyncKeyState(VK_DOLLAR) & 0x8000) ? 0 : 1;

		if (keystate == KEY_DOWN && !keydown)
		{
			std::cout << "DOWN: " << std::endl;
			keydown = true;
		}
		else if (keystate == KEY_UP && keydown)
		{
			keydown = false;
			std::cout << "UP -> PRESSED" << std::endl;
			if (IsWindowInFocus())
			{
				std::cout << "ET DANS LE FENETRE EN PLUS MDR LOL" << std::endl;
			}
		}
		Sleep(10);
	}
	std::cout << c << std::endl;*/
	//TEST

	bool success = false;
	int wait = 0;
	int processId = 0;
	std::string libpath = "C:\\Users\\OOM\\Documents\\Visual Studio 2017\\Projects\\UnderTaleInfiniteLifev101PatchFr\\Release\\InjectionLiba.dll";
	std::cout << "\
  _   _           _           _        _        ____       _       _				\n\
 | | | |_ __   __| | ___ _ __| |_ __ _| | ___  |  _ \\ __ _| |_ ___| |__				\n\
 | | | | '_ \\ / _` |/ _ \\ '__| __/ _` | |/ _ \\ | |_) / _` | __/ __| '_ \\		\n\
 | |_| | | | | (_| |  __/ |  | || (_| | |  __/ |  __/ (_| | || (__| | | |			\n\
  \\___/|_| |_|\\__,_|\\___|_|   \\__\\__,_|_|\\___| |_|   \\__,_|\\__\\___|_| |_|	\n\
        " << std::endl;
	std::cout << "Appuyer sur la touche '$' en jeux pour remettre votre vie au max" << std::endl;
	std::cout << "\nTrouver Undertale..."; //Step 1

	while (processId == 0)
	{
		processId = getProcID("UNDERTALE.exe");
		if (processId == 0)
		{
			if (wait == 0)
				std::cout << std::endl;
			std::cout << "Le jeux n'est pas lance, reessai (" << (wait + 1) << ") dans 5 sec..." << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(5));
			wait++;
		}
	}
	if (wait > 0)
		std::cout << "Trouver Undertale...";
	std::cout << "OK" << std::endl;;
	std::cout << "Ecriture de la librairie a injecter..."; //Step 2
	success = true;//writeTempLibrary(libpath);
	if (success)
	{
		std::cout << "OK" << std::endl;
		std::cout << "Injection de la librairie dans Undertale...";
		success = InjectDLL(processId, libpath);
	}
	else
		std::cout << "KO\n[Erreur]: impossible de créer la librairie sur le disque" << std::endl;
	std::cout << "Fermeture dans 5 sec..." << std::endl;
	std::this_thread::sleep_for(std::chrono::seconds(5));
	return 0;
}