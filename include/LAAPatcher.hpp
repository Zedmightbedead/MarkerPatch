#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace LAAPatcher
{
    // ========================
    // Error Handling
    // ========================

    inline void ShowError(const char* message)
    {
        MessageBoxA(NULL, message, "MarkerPatch - LAAPatcher Error", MB_ICONERROR);
    }

    inline void ShowError(const std::string& message)
    {
        MessageBoxA(NULL, message.c_str(), "MarkerPatch - LAAPatcher Error", MB_ICONERROR);
    }

    // ========================
    // Validation Helpers
    // ========================

    inline bool CheckBounds(size_t offset, size_t size, size_t bufferSize, const char* context, char* outError, size_t errorSize)
    {
        if (offset + size <= bufferSize)
            return true;

        sprintf_s(outError, errorSize, "%s exceeds bounds (offset=0x%zX, size=0x%zX, bufferSize=%zu).", context, offset, size, bufferSize);
        return false;
    }

    // ========================
    // PE Header Wrapper
    // ========================

    class PEFile
    {
    public:
        explicit PEFile(std::vector<uint8_t>& buffer) : m_buffer(buffer) {}

        bool Validate(char* outError, size_t errorSize)
        {
            if (m_buffer.size() < sizeof(IMAGE_DOS_HEADER))
            {
                sprintf_s(outError, errorSize, "File too small (%zu bytes, need at least %zu).", m_buffer.size(), sizeof(IMAGE_DOS_HEADER));
                return false;
            }

            if (DosHeader()->e_magic != IMAGE_DOS_SIGNATURE)
            {
                sprintf_s(outError, errorSize, "Invalid DOS signature (0x%04X, expected 0x%04X).", DosHeader()->e_magic, IMAGE_DOS_SIGNATURE);
                return false;
            }

            if (DosHeader()->e_lfanew < 0)
            {
                sprintf_s(outError, errorSize, "Invalid e_lfanew value (%d, must be non-negative).", DosHeader()->e_lfanew);
                return false;
            }

            if (!CheckBounds(DosHeader()->e_lfanew, sizeof(IMAGE_NT_HEADERS), m_buffer.size(), "NT header", outError, errorSize))
                return false;

            if (NtHeaders()->Signature != IMAGE_NT_SIGNATURE)
            {
                sprintf_s(outError, errorSize, "Invalid NT signature (0x%08X, expected 0x%08X).", NtHeaders()->Signature, IMAGE_NT_SIGNATURE);
                return false;
            }

            if (NtHeaders()->FileHeader.NumberOfSections == 0)
            {
                sprintf_s(outError, errorSize, "PE file has zero sections.");
                return false;
            }

            size_t sectionHeadersOffset = DosHeader()->e_lfanew + sizeof(IMAGE_NT_HEADERS);
            size_t sectionHeadersSize = NtHeaders()->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

            if (!CheckBounds(sectionHeadersOffset, sectionHeadersSize, m_buffer.size(), "Section headers", outError, errorSize))
                return false;

            return true;
        }

        PIMAGE_DOS_HEADER DosHeader() { return reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer.data()); }
        PIMAGE_NT_HEADERS NtHeaders() { return reinterpret_cast<PIMAGE_NT_HEADERS>(m_buffer.data() + DosHeader()->e_lfanew); }

        bool IsLAAEnabled() const { return (const_cast<PEFile*>(this)->NtHeaders()->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0; }
        void EnableLAA() { NtHeaders()->FileHeader.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE; }
        void ClearChecksum() { NtHeaders()->OptionalHeader.CheckSum = 0; }
        size_t Size() const { return m_buffer.size(); }
        uint8_t* Data() { return m_buffer.data(); }

    private:
        std::vector<uint8_t>& m_buffer;
    };

    // ========================
    // File I/O
    // ========================

    inline bool ReadFile(const fs::path& path, std::vector<uint8_t>& buffer)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
            return false;

        std::streamsize size = file.tellg();
        if (size <= 0)
            return false;

        file.seekg(0, std::ios::beg);

        try
        {
            buffer.resize(static_cast<size_t>(size));
        }
        catch (...)
        {
            return false;
        }

        return file.read(reinterpret_cast<char*>(buffer.data()), size).good();
    }

    // ========================
    // Validation
    // ========================

    inline bool ValidatePatchedFile(const fs::path& origPath, const fs::path& patchPath)
    {
        char error[512];
        std::vector<uint8_t> origData, patchData;

        if (!ReadFile(origPath, origData))
        {
            sprintf_s(error, "Validation failed: Could not read original file.\nPath: %s", origPath.string().c_str());
            ShowError(error);
            return false;
        }

        if (!ReadFile(patchPath, patchData))
        {
            sprintf_s(error, "Validation failed: Could not read patched file.\nPath: %s", patchPath.string().c_str());
            ShowError(error);
            return false;
        }

        if (origData.empty())
        {
            ShowError("Validation failed: Original file is empty.");
            return false;
        }

        if (patchData.empty())
        {
            ShowError("Validation failed: Patched file is empty.");
            return false;
        }

        PEFile origPE(origData);
        PEFile patchPE(patchData);

        if (!origPE.Validate(error, sizeof(error)))
        {
            ShowError(error);
            return false;
        }

        if (!patchPE.Validate(error, sizeof(error)))
        {
            ShowError(error);
            return false;
        }

        if (origData.size() != patchData.size())
        {
            sprintf_s(error, "Validation failed: File size changed (original=%zu, patched=%zu).", origData.size(), patchData.size());
            ShowError(error);
            return false;
        }

        origPE.EnableLAA();
        origPE.ClearChecksum();
        patchPE.ClearChecksum();

        if (memcmp(origData.data(), patchData.data(), origData.size()) != 0)
        {
            ShowError("Validation failed: File differs in more than just LAA flag and checksum.");
            return false;
        }

        return true;
    }

    // ========================
    // Main Patching Logic
    // ========================

    inline bool PerformLAAPatch(HMODULE hModule, bool showConfirmation)
    {
        char error[512];

        if (!hModule)
        {
            ShowError("PerformLAAPatch called with NULL module handle.");
            return false;
        }

        char modulePathRaw[MAX_PATH];
        DWORD pathLen = GetModuleFileNameA(hModule, modulePathRaw, MAX_PATH);
        if (pathLen == 0)
        {
            sprintf_s(error, "GetModuleFileNameA failed. Error: %d", GetLastError());
            ShowError(error);
            return false;
        }

        if (pathLen >= MAX_PATH)
        {
            ShowError("Module path exceeds MAX_PATH. Path may be truncated.");
            return false;
        }

        fs::path exePath = modulePathRaw;
        fs::path exeName = exePath.filename();
        fs::path newPath = exePath; newPath += ".new";
        fs::path bakPath = exePath; bakPath += ".bak";

        if (!fs::exists(exePath))
        {
            sprintf_s(error, "Executable path does not exist: %s", exePath.string().c_str());
            ShowError(error);
            return false;
        }

        std::vector<uint8_t> buffer;
        if (!ReadFile(exePath, buffer))
        {
            sprintf_s(error, "Could not read executable file.\nPath: %s\nError: %d", exePath.string().c_str(), GetLastError());
            ShowError(error);
            return false;
        }

        if (buffer.empty())
        {
            sprintf_s(error, "Executable file is empty.\nPath: %s", exePath.string().c_str());
            ShowError(error);
            return false;
        }

        std::error_code ec;
        auto spaceInfo = fs::space(exePath.parent_path(), ec);
        if (!ec)
        {
            uintmax_t requiredSpace = buffer.size() * 2;
            if (spaceInfo.available < requiredSpace)
            {
                sprintf_s(error, "Not enough disk space to create backup and patched files.\n\nRequired: %llu MB\nAvailable: %llu MB", (requiredSpace / (1024 * 1024)) + 1, spaceInfo.available / (1024 * 1024));
                ShowError(error);
                return false;
            }
        }

        PEFile pe(buffer);
        if (!pe.Validate(error, sizeof(error)))
        {
            ShowError(error);
            return false;
        }

        if (pe.IsLAAEnabled())
            return true;

        if (showConfirmation)
        {
            std::string msg = "Your game executable is missing the 4GB/LAA patch. "
                "This allows the game to use 4GB of memory instead of 2GB, which prevents crashes.\n\n"
                "MarkerPatch will patch " + exeName.string() + " and create a backup.\n\n"
                "Apply patch and restart the game?\n\n"
                "(This check can be disabled by setting CheckLAAPatch=0 in the [General] section of MarkerPatch.ini)";

            if (MessageBoxA(NULL, msg.c_str(), "4GB/Large Address Aware patch missing!", MB_YESNO | MB_ICONEXCLAMATION) != IDYES)
                return false;
        }

        pe.EnableLAA();
        pe.ClearChecksum();

        if (fs::exists(newPath))
        {
            fs::remove(newPath, ec);
            if (ec)
            {
                sprintf_s(error, "Failed to remove existing .new file.\nPath: %s\nError: %s", newPath.string().c_str(), ec.message().c_str());
                ShowError(error);
                return false;
            }
        }

        {
            std::ofstream outFile(newPath, std::ios::binary);
            if (!outFile)
            {
                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED)
                    sprintf_s(error, "Unable to write patched file (Access Denied).\n\nYour Anti-Virus may be blocking modification.\nPlease add an exception for this folder.\nPath: %s", newPath.string().c_str());
                else
                    sprintf_s(error, "Failed to create patched file.\nPath: %s\nError: %d", newPath.string().c_str(), err);

                ShowError(error);
                return false;
            }

            outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

            if (!outFile.good())
            {
                sprintf_s(error, "Failed to write patched file data.\nPath: %s", newPath.string().c_str());
                ShowError(error);
                fs::remove(newPath, ec);
                return false;
            }
        }

        Sleep(100);

        auto writtenSize = fs::file_size(newPath, ec);
        if (ec || writtenSize != buffer.size())
        {
            sprintf_s(error, "Written file size mismatch (expected=%zu, actual=%zu).\nPath: %s", buffer.size(), static_cast<size_t>(writtenSize), newPath.string().c_str());
            ShowError(error);
            fs::remove(newPath, ec);
            return false;
        }

        if (!ValidatePatchedFile(exePath, newPath))
        {
            fs::remove(newPath, ec);
            return false;
        }

        if (!MoveFileExA(exePath.string().c_str(), bakPath.string().c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            DWORD err = GetLastError();

            if (err == ERROR_ACCESS_DENIED)
            {
                ShowError("LAA Patch failed: Access Denied (Error 5).\n\n"
                    "Windows is blocking the file modification.\n"
                    "Please restart the game as Administrator to apply the patch.\n\n"
                    "You can disable this check by setting CheckLAAPatch=0 in MarkerPatch.ini");
                fs::remove(newPath, ec);
                return false;
            }

            if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION)
            {
                sprintf_s(error, "LAA Patch failed: File is locked by another process.\n\nError: %d\n\nYou can disable this check by setting CheckLAAPatch=0 in MarkerPatch.ini", err);
                ShowError(error);
                fs::remove(newPath, ec);
                return false;
            }

            sprintf_s(error, "Failed to backup original executable.\n\nError: %d", err);
            ShowError(error);
            fs::remove(newPath, ec);
            return false;
        }

        if (!MoveFileA(newPath.string().c_str(), exePath.string().c_str()))
        {
            DWORD err = GetLastError();
            MoveFileA(bakPath.string().c_str(), exePath.string().c_str());
            sprintf_s(error, "Failed to rename patched file to original. Restored from backup.\n\nError: %d", err);
            ShowError(error);
            return false;
        }

        Sleep(50);

        INT_PTR shellResult = reinterpret_cast<INT_PTR>(ShellExecuteA(NULL, "open", exePath.string().c_str(), NULL, NULL, SW_SHOWDEFAULT));
        if (shellResult > 32)
        {
            ExitProcess(0);
        }
        else
        {
            sprintf_s(error, "Patching completed successfully, but failed to restart the application.\nShellExecute returned: %d\n\nPlease restart the game manually.", static_cast<int>(shellResult));
            MessageBoxA(NULL, error, "MarkerPatch - LAAPatcher Warning", MB_ICONWARNING);
            return true;
        }
    }
}