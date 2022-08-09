#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <thread>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <atlstr.h>
#include <string>
#include <TlHelp32.h>
#include <discord_rpc.h>
#include <discord_register.h>
#include <assert.h>
#include <algorithm>

std::vector<std::wstring> secureDlls = {
L"hoi4.exe",L"ntdll.dll",L"KERNEL32.DLL",L"KERNELBASE.dll",L"SETUPAPI.dll",L"msvcrt.dll",L"steam_api64.dll",L"pdx_mp.dll",L"pops_api.dll",L"IMM32.dll",L"ADVAPI32.dll",L"win32u.dll",L"sechost.dll",L"WS2_32.dll",L"RPCRT4.dll",L"USER32.dll",L"SHLWAPI.dll",L"SHELL32.dll",L"GDI32.dll",L"msvcp_win.dll",L"ole32.dll",L"gdi32full.dll",L"ucrtbase.dll",L"Normaliz.dll",L"combase.dll",L"pdx_red_king.dll",L"OLEAUT32.dll",L"WLDAP32.dll",L"VERSION.dll",L"WINMM.dll",L"tbb.dll",L"IPHLPAPI.DLL",L"d3dx9_43.dll",L"OPENGL32.dll",L"d3d9.dll",L"XINPUT1_3.dll",L"D3DCOMPILER_47.dll",L"dxgi.dll",L"d3d11.dll",L"PDXBrowser_IPC.dll",L"bcrypt.dll",L"WINHTTP.dll",L"MSVCP140.dll",L"VCRUNTIME140.dll",L"VCRUNTIME140_1.dll",L"kernel.appcore.dll",L"GLU32.dll",L"dwmapi.dll",L"CRYPTSP.dll",L"dxcore.dll",L"shcore.dll",L"uxtheme.dll",L"PSAPI.DLL",L"MSWSOCK.dll",L"CRYPTBASE.DLL",L"bcryptPrimitives.dll",L"windows.storage.dll",L"wintypes.dll",L"MSCTF.dll",L"directxdatabasehelper.dll",L"ntmarta.dll",L"crypt32.dll",L"WINTRUST.DLL",L"MSASN1.dll",L"imagehlp.dll",L"rsaenh.dll",L"secur32.dll",L"SSPICLI.DLL",L"NSI.dll",L"dhcpcsvc6.DLL",L"dhcpcsvc.DLL",L"DNSAPI.dll",L"rasadhlp.dll",L"fwpuclnt.dll",L"clbcatq.dll",L"textinputframework.dll",L"sapi.dll",L"MMDevApi.dll",L"DEVOBJ.dll",L"cfgmgr32.dll",L"avrt.dll",L"AUDIOSES.DLL",L"resourcepolicyclient.dll",L"powrprof.dll",L"UMPDC.dll",L"hid.dll",L"dinput8.dll",L"inputhost.dll",L"CoreMessaging.dll",L"XInput1_4.dll",L"WINNSI.DLL",L"webio.dll",L"schannel.DLL",L"mskeyprotect.dll",L"NTASN1.dll",L"ncrypt.dll",L"ncryptsslp.dll",L"DPAPI.DLL",L"nvldumdx.dll",L"nvd3dumx.dll",L"igdumdim64.dll",L"igdusc64.dll",L"dcomp.dll",L"mscms.dll",L"Windows.Internal.Graphics.Display.DisplayColorManagement.dll",L"CoreUIComponents.dll", };
static bool cheatEngineDetected = false;
static bool debug = false;
static std::vector<std::wstring> dataList;
static std::vector<std::wstring> secureList;
static std::vector<std::wstring> unSecureList;
#define _PROTECTION_DELAY_MILLISECONDS 1*1000
#define ClientId "731505120952582205"
class Discord
{
public:

	DWORD c_timeStamp = 0;
	DiscordRichPresence discordPresence;
	bool SetInfo(const char* applicationID) {
		DiscordEventHandlers handle;
		memset(&handle, 0, sizeof(handle));
		Discord_Initialize(applicationID, &handle, 1, NULL);
		return true;
	}


	bool Deploy(const char* state, const char* details, int timeStamp, int endTimeStamp) {
		memset(&discordPresence, 0, sizeof(discordPresence));
		discordPresence.largeImageKey = "agora";
		discordPresence.state = state;
		discordPresence.details = details;
		discordPresence.startTimestamp = timeStamp;
		c_timeStamp = timeStamp;
		discordPresence.endTimestamp = endTimeStamp;
		Discord_UpdatePresence(&discordPresence);
		return true;
	}

	bool ChangeDescription(const char* details) {
		discordPresence.details = details;
		Discord_UpdatePresence(&discordPresence);
		return true;
	}

	bool ChangeStatus(const char* stat) {
		discordPresence.state = stat;
		Discord_UpdatePresence(&discordPresence);
		return true;
	}

};

static Discord dc;


DWORD GetProcessID(LPCWSTR pName) {
	PROCESSENTRY32 pent;
	pent.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snap, &pent)) {
		do {
			if (!lstrcmp(pent.szExeFile, pName)) {
				CloseHandle(snap);
				return pent.th32ProcessID;
			}
		} while (Process32Next(snap,&pent));
	}
	return 0;
}

int getModuleNames(DWORD pId) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	uint32_t i = 0;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pId);
	if (!hProcess) return 1;

	if (EnumProcessModules(hProcess, hMods,sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE));  i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleBaseName(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::wstring data(szModName);
				dataList.push_back(data);
			}
		}
	}
	CloseHandle(hProcess);
	return -1;
}

void ProtectionAgainstInternal() {
	while (true) {
		system("cls");
		int isSecure = 0;
		DWORD pID = GetProcessID(L"hoi4.exe");
		if (pID == 0) {
			dc.ChangeStatus("Hearts of Iron IV not found.");
			dc.ChangeDescription("Idling");
		}
		else if(!cheatEngineDetected) {
			dc.ChangeStatus("Hearts of Iron IV: Agora RP!");
			dc.ChangeDescription("Playing");
			getModuleNames(pID);
			for (auto& b : dataList) {
				for (auto& c : secureDlls) {
					if (lstrcmp(b.c_str(), c.c_str()) == 0) {
						isSecure++;
						secureList.push_back(c);
					}
				}
			}

			std::sort(secureList.begin(), secureList.end());
			std::sort(dataList.begin(), dataList.end());
			std::set_difference(
				dataList.begin(), dataList.end(),
				secureList.begin(), secureList.end(),
				std::back_inserter(unSecureList)
			);

		}
		if (debug) {
			printf("----------- DEBUG -----------\n\rTotal DLL Count: %d\n\Founded Secure DLL Count: %d\n", dataList.size(), isSecure, cheatEngineDetected);
			(cheatEngineDetected) ? printf("Cheat Engine Running?: true\n") : printf("Cheat Engine Running?: false\n");
			(pID == 0) ? printf("Game is Running?: false\n") : printf("Game is Running?: true\n");
			if (unSecureList.size() != 0) {
				printf("----------- UNSECURE MODULES LIST -----------\n\r");
				printf("---Unsecure Module Size: %d\n", unSecureList.size());
				for (auto& a : unSecureList) {
					wprintf(L"--%s\n", a.c_str());
				}
			}
		}
		dataList.clear();
		secureList.clear();
		unSecureList.clear();
		std::this_thread::sleep_for(std::chrono::milliseconds(_PROTECTION_DELAY_MILLISECONDS));
	}
}

void ProtectionAgainstCheatEngine() {
	while (true) {
		HWND cheatEngine = FindWindow(NULL, L"Cheat Engine 7.4");
		DWORD cheatEnginepId = GetProcessID(L"cheatengine-x86_64-SSE4-AVX2.exe");
		if (cheatEngine || cheatEnginepId != 0) {
			cheatEngineDetected = true;
			dc.ChangeStatus("Cheat Engine detected!");
		}
		else {
			cheatEngineDetected = false;
		}
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}



int main(int argc, char** argv) {
	if (argc >= 2 && strcmp(argv[1], "debug") == 0) {
		debug = true;

	}
	if (argc >= 2 && strcmp(argv[1], "list") == 0) {
		DWORD pID = GetProcessID(L"hoi4.exe");
		getModuleNames(pID);
		FILE* f = fopen("modules.txt", "w");
		for (auto& a : dataList) {
			std::string data(a.begin(), a.end());
			fputc('L',f);
			fputc('"', f);
			fwrite(data.c_str(), strlen(data.c_str()), 1,f);
			fputc('"', f);
			fputc(',', f);
		}
		printf("Done!\n");
		exit(EXIT_SUCCESS);
	}
	dc.SetInfo("731505120952582205");
	dc.Deploy("", "Idling", std::time(NULL), NULL);
	std::thread protectionInternal(ProtectionAgainstInternal);
	std::thread protectionCheatEngine(ProtectionAgainstCheatEngine);
	






	for (;;) {
		Sleep(10);
	}
}