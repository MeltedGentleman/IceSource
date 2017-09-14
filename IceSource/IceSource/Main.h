#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT _WIN32_WINNT_WINXP
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN 

#include <Commdlg.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <Richedit.h>
#include <string>
#include <iostream>
#include <fstream>
#include <thread>
#include <CommCtrl.h>
#include <sstream>
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
#include "Scan.h"
#include "Functions.h"
#include "Commands.h"

using namespace std;

int Init() {
	//Whitelist();
	HWND ConsoleHandle = GetConsoleWindow();
	CustomizeConsole("ICE // By: Josh() and Cosmology");
	Scan();
	::ShowWindow(ConsoleHandle, SW_HIDE);
	cout << "---------------------------------------------" << endl;
	cout << "                Welcome To Ice               " << endl;
	cout << "   Type `cmds` To Get The List Of Commands   " << endl;
	cout << "---------------------------------------------" << endl;
	cout << ">-> ";

	do {
		try {
			luaC(GetInput());
		}
		catch (std::exception e) {
			MessageBoxA(NULL, e.what(), "Ice - Uh Oh", MB_OK);
		}
		catch (...) {
			MessageBoxA(NULL, "An Unhandled Error Has Occured!", "Ice - Uh Oh", MB_OK);
			cout << "ERROR: An Unexpected Error Has Occured!" << endl;
		}
	} while (true);

	return 0;
}