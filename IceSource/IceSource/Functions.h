#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT _WIN32_WINNT_WINXP
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN 

#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <fstream>
#include <sstream>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinINet.h>
#include <algorithm>
#include <random>
#include <ostream>
#include <chrono>
#include <typeinfo>
#include <fcntl.h>
#include <io.h>
#include <urlmon.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <typeinfo>
#include <WinInet.h>
#include <fstream>
#include <algorithm>
#include <Psapi.h>
#include <tlhelp32.h>
#include <math.h>
#include <cmath>
#include <Windows.h>
#include <iostream>
#include <string> 
#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <istream>
#include <iterator>
#include <algorithm>
#include <string>
#include <Psapi.h>
#include <tlhelp32.h>
#include <Windows.h>
#include <assert.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <conio.h>
#include <time.h>
#include <map>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "wininet")
#pragma once

#include "stdafx.h"

#include "Rlua.h"
#include "Defs.h"

using namespace Rlua;

std::string WebContent;
std::string PlayerName;
int PlayerID;
int DataModel;
int Players;
int Lighting;
int Workspace;
int ScriptContext;
int luaState;

bool MaliciousAppCheckOn = true;

std::string ConvertToString(int i) {

	std::string returnval;
	if (i) {
		returnval = std::to_string(i);
	}
	return returnval;
}

std::vector<std::string> Split(std::string str, char Delim) {
	std::vector<std::string> Args;
	std::stringstream ss(str);
	std::string Arg;
	while (getline(ss, Arg, Delim))
		Args.push_back(Arg);
	return Args;
}

std::string tolower(std::string str)
{
	std::string retn("");
	for (int i = 0; i < str.length(); i++)
	{
		int ascii = (int)str.at(i);
		if (ascii >= (int)'a' && ascii <= (int)'z')
			retn += (char)ascii;
		else
			retn += (char)(ascii + ((int)'a' - (int)'A'));
	}
	return retn;
}

void getService(std::string service)
{
	using namespace Rlua;
	rlua_getfield(luaState, LUA_GLOBALSINDEX, "game");
	rlua_getfield(luaState, -1, "GetService");
	rlua_pushvalue(luaState, -2);
	rlua_pushstring(luaState, service.c_str());
	rlua_pcall(luaState, 2, 1, 0);
}

void FindFirstChild(std::string baseinst, std::string childname)
{
	using namespace Rlua;
	rlua_getfield(luaState, LUA_GLOBALSINDEX, "game");
	rlua_getfield(luaState, -1, baseinst.c_str());
	rlua_getfield(luaState, -1, "FindFirstChild");
	rlua_pushvalue(luaState, -2);
	rlua_pushstring(luaState, childname.c_str());
	rlua_pcall(luaState, 2, 1, 0);
}

const char* GetClass(int self)
{
	return (const char*)(*(int(**)(void))(*(int*)self + 16));
}

int GetParent(int Instance) {
	return *(int*)(Instance + 0x34);
}

std::string* GetName(int Instance) {
	return (std::string*)(*(int*)(Instance + 0x28));
}

int FindFirstClass(int Instance, const char* ClassName) {
	if (Instance > 10000) {
		DWORD StartOfChildren = *(DWORD*)(Instance + 0x2C);
		if (StartOfChildren != 0) {
			DWORD EndOfChildren = *(DWORD*)(StartOfChildren + 4);
			if (EndOfChildren != 0) {
				for (int i = *(int*)StartOfChildren; i != EndOfChildren; i += 8) {
					try {
						if (memcmp(GetClass(*(int*)i), ClassName, strlen(ClassName)) == 0) {
							return *(int*)i;
						}
					}
					catch (std::exception) {
						Sleep(1);
					}
					catch (...) {
						Sleep(1);
					}
				}
			}
		}
	}
	return 0;
}

std::string LocalPlayerName() {
	using namespace Rlua;
	std::string name;
	getService("Players");
	rlua_getfield(luaState, -1, "LocalPlayer");
	rlua_getfield(luaState, -1, "Name");
	name = rlua_tostring(luaState, -1);
	return name;
}

void Scan() {
	using namespace std;
	DWORD ScriptContextVFTable = *(DWORD*)((aobscan::scan("\xC7\x07\x00\x00\x00\x00\xC7\x47\x00\x00\x00\x00\x00\x8B\x87", "xx????xx?????xx")) + 0x02); //GetAddr(0x1172F28);
	ScriptContext = Memory::Scan(PAGE_READWRITE, (char*)&ScriptContextVFTable, "xxxx");
	DataModel = GetParent(ScriptContext);
	Workspace = FindFirstClass(DataModel, "Workspace");
	Players = FindFirstClass(DataModel, "Players");
	Lighting = FindFirstClass(DataModel, "Lighting");
	luaState = *(DWORD*)(ScriptContext + 220) - (ScriptContext + 220);
}

void CustomizeConsole(char* title) {
	DWORD Null;
	VirtualProtect((PVOID)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &Null);
	*(BYTE*)(&FreeConsole) = 0xC3;
	AllocConsole();
	SetConsoleTitleA(title);
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
	//SetWindowLong(GetConsoleWindow(), GWL_STYLE, WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU);
	HWND ConsoleHandle = GetConsoleWindow();
	::SetWindowPos(ConsoleHandle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
}

std::string GetInput() {
	std::string input;
	getline(std::cin, input);
	return input;
}

void CreateInstance(RLUAState state, const char* Instance) {
	rlua_getfield(luaState, LUA_GLOBALSINDEX, "Instance");
	rlua_getfield(luaState, -1, "new");
	rlua_pushstring(luaState, Instance);
	rlua_pushvalue(luaState, -4);
	rlua_pcall(luaState, 2, 1, 0);
}

void CreateScript(Script script) {
	switch (script.Type) {
	case RawScriptTypeNormal:
	{
		getService("Workspace");
		rlua_getfield(luaState, LUA_GLOBALSINDEX, "Instance");
		rlua_getfield(luaState, -1, "new");
		rlua_pushstring(luaState, "Script");
		rlua_pushvalue(luaState, -4);
		rlua_pcall(luaState, 2, 1, 0);

		rlua_pushstring(luaState, script.Source);
		rlua_setfield(luaState, -2, "Source");
		rlua_pushstring(luaState, (const char*)script.Name);
		rlua_setfield(luaState, -2, "Name");
	}
	case RawScriptTypeLocal:
	{
		getService("ReplicatedFirst");
		rlua_getfield(luaState, LUA_GLOBALSINDEX, "Instance");
		rlua_getfield(luaState, -1, "new");
		rlua_pushstring(luaState, "LocalScript");
		rlua_pushvalue(luaState, -4);
		rlua_pcall(luaState, 2, 1, 0);

		rlua_pushstring(luaState, script.Source);
		rlua_setfield(luaState, -2, "Source");
		rlua_pushstring(luaState, (const char*)script.Name);
		rlua_setfield(luaState, -2, "Name");
	}
	case RawScriptTypeModule:
	{
		getService("Workspace");
		rlua_getfield(luaState, LUA_GLOBALSINDEX, "Instance");
		rlua_getfield(luaState, -1, "new");
		rlua_pushstring(luaState, "ModuleScript");
		rlua_pushvalue(luaState, -4);
		rlua_pcall(luaState, 2, 1, 0);

		rlua_pushstring(luaState, script.Source);
		rlua_setfield(luaState, -2, "Source");
		rlua_pushstring(luaState, (const char*)script.Name);
		rlua_setfield(luaState, -2, "Name");
	}
	default:
		break;
	}
}

std::vector<std::string> GetPlayerVectorFromPlaceHolder(std::string inp) {
	std::vector<std::string> Players = {};
	try {
		if (inp == "all") {
			getService("Players");
			rlua_getfield(luaState, -1, "GetChildren");
			rlua_pushvalue(luaState, -2);
			rlua_pcall(luaState, 1, 1, 0);
			rlua_pushnil(luaState);
			while (rlua_next(luaState, -2) != 0) {
				rlua_getfield(luaState, -1, "Name");
				std::string CharName = rlua_tostring(luaState, -1);
				Players.push_back(CharName);
			}
		}
		if (inp == "others") {
			getService("Players");
			rlua_getfield(luaState, -1, "GetChildren");
			rlua_pushvalue(luaState, -2);
			rlua_pcall(luaState, 1, 1, 0);
			rlua_pushnil(luaState);
			while (rlua_next(luaState, -2) != 0) {
				rlua_getfield(luaState, -1, "Name");
				std::string CharName = rlua_tostring(luaState, -1);
				if (CharName != LocalPlayerName())
					Players.push_back(CharName);
			}
		}
	}
	catch (std::exception e) {
		Sleep(1);
	}
	return Players;
}

std::string replaceAll(std::string subject, const std::string& search,
	const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

bool findAll(std::string subject, const std::string& search) {
	bool found = false;
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		if (&subject[pos] == search)
			found = true;
	}
	return found;
}

std::string DownloadURL(const char* URL) {
	HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	HINTERNET urlFile;
	std::string rtn;
	if (interwebs) {
		urlFile = InternetOpenUrlA(interwebs, URL, NULL, NULL, NULL, NULL);
		if (urlFile) {
			char buffer[2000];
			DWORD bytesRead;
			do {
				InternetReadFile(urlFile, buffer, 2000, &bytesRead);
				rtn.append(buffer, bytesRead);
				memset(buffer, 0, 2000);
			} while (bytesRead);
			InternetCloseHandle(interwebs);
			InternetCloseHandle(urlFile);
			std::string p = replaceAll(rtn, "|n", "\r\n");
			return p;
		}
	}
	InternetCloseHandle(interwebs);
	std::string p = replaceAll(rtn, "|n", "\r\n");
	return p;
}

size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up)
{
	for (int c = 0; c<size*nmemb; c++)
	{
		WebContent.push_back(buf[c]);
	}
	return size*nmemb;
}

extern int CheckForMaliciousApps();

void Whitelist() {
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)CheckForMaliciousApps, NULL, NULL, NULL);
	std::string hwid;
	HW_PROFILE_INFO hwProfileInfo;
	if (GetCurrentHwProfile(&hwProfileInfo) != NULL) {
		return;
	}

	typedef unsigned long DWORD;

	CHAR szVolumeNameBuffer[12];
	DWORD dwVolumeSerialNumber;
	DWORD dwMaximumComponentLength;
	DWORD dwFileSystemFlags;
	CHAR szFileSystemNameBuffer[10];

	GetVolumeInformationA("C:\\", szVolumeNameBuffer, 12, &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, szFileSystemNameBuffer, 10);
	std::string HDDserial = std::to_string(dwVolumeSerialNumber);

	std::string WebURL = "http://www.ice-exploit.us/whitelist/wl.php";
	WebURL += HDDserial;
	std::string WebResult1 = DownloadURL(WebURL.c_str());

	if (WebResult1 == "true") {

	}
	else if (WebResult1 == "trial") {

	}
	else if (WebResult1 == "false") {
		exit;
	}
}

void cURLWhitelist() {
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)CheckForMaliciousApps, NULL, NULL, NULL);
	std::string hwid;
	HW_PROFILE_INFO hwProfileInfo;
	if (GetCurrentHwProfile(&hwProfileInfo) != NULL) {
		return;
	}

	typedef unsigned long DWORD;

	CHAR szVolumeNameBuffer[12];
	DWORD dwVolumeSerialNumber;
	DWORD dwMaximumComponentLength;
	DWORD dwFileSystemFlags;
	CHAR szFileSystemNameBuffer[10];

	GetVolumeInformationA("C:\\", szVolumeNameBuffer, 12, &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, szFileSystemNameBuffer, 10);
	std::string HDDserial = std::to_string(dwVolumeSerialNumber);

	std::string WebURL = "http://www.ice-exploit.us/whitelist/wl.php";
	WebURL += HDDserial;

	if (WebContent == "true") {

	}
	else if (WebContent == "trial") {

	}
	else if (WebContent == "false") {
		exit;
	}

}

#define MALAPPFOUND(name) throw new std::exception("Found malicious application '" name "'");
#define CHECKPROC(name) strcmp(Entry.szExeFile, name) == 0

int CheckForMaliciousApps() {
	while (MaliciousAppCheckOn) {
		if (FindWindow(NULL, TEXT("Fiddler Web Debugger")) || FindWindow(NULL, TEXT("Fiddler - HTTP Debugging Proxy")))
			MALAPPFOUND("Fiddler Web Debugger/Fiddler - HTTP Debugging Proxy");
		if (OpenMutex(MUTEX_ALL_ACCESS, false, TEXT("Global\\ProxifierRunning")))
			MALAPPFOUND("Proxifier");
		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (Process32First(SnapShot, &Entry) == TRUE) {
			while (Process32Next(SnapShot, &Entry) == TRUE) {

			}
		}
	}
	return 0;
}