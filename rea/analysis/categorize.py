"""Map API / symbol names to behavioural categories.

Triage is mostly about behaviour, not names. Grouping imports into categories
such as ``process_injection`` or ``crypto`` lets the scoring engine reason about
*what a binary can do* even when it is packed and strings are obfuscated.
"""

from __future__ import annotations

from typing import Dict, List

CATEGORIES: Dict[str, List[str]] = {
    "process_execution": [
        "CreateProcess", "ShellExecute", "WinExec", "system", "execve", "execvp",
        "popen", "posix_spawn", "fork", "CreateThread", "NtCreateThreadEx",
        "queueuserapc", "loadlibrary", "getprocaddress",
    ],
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtWriteVirtualMemory", "NtMapViewOfSection", "SetThreadContext",
        "ResumeThread", "OpenProcess", "ZwMapViewOfSection", "ptrace",
        "process_vm_writev", "dlopen",
    ],
    "persistence": [
        "RegSetValue", "RegCreateKey", "CreateService", "ChangeServiceConfig",
        "schtasks", "crontab", "StartService", "setsockopt",
    ],
    "network": [
        "socket", "connect", "send", "recv", "sendto", "recvfrom", "bind",
        "listen", "accept", "WSAStartup", "InternetOpen", "InternetConnect",
        "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen", "getaddrinfo",
        "curl_easy_perform", "SSL_connect", "getaddrinfo",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt", "EVP_EncryptInit", "EVP_DecryptInit",
        "AES_encrypt", "RC4", "RSA_public_encrypt", "sodium_", "bcrypt",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "ptrace", "sleep", "GetSystemInfo", "NtQuerySystemInformation",
        "VirtualProtect", "FlushInstructionCache",
    ],
    "file_system": [
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "MoveFile",
        "CopyFile", "FindFirstFile", "open", "read", "write", "unlink",
        "chmod", "fopen", "fwrite", "unlinkat",
    ],
    "registry": [
        "RegOpenKey", "RegQueryValue", "RegDeleteKey", "RegEnumKey",
        "RegQueryInfoKey", "NtQueryValueKey",
    ],
    "credential_access": [
        "CredEnumerate", "CredRead", "LsaEnumerateLogonSessions",
        "SamQueryInformationUser", "GetUserName", "NetUserGetInfo",
    ],
    "privilege": [
        "AdjustTokenPrivileges", "OpenProcessToken", "Setuid", "Setgid",
        "ImpersonateLoggedOnUser", "SeDebugPrivilege", "setuid", "seteuid",
    ],
    "memory_management": [
        "VirtualAlloc", "VirtualFree", "HeapAlloc", "malloc", "calloc",
        "mmap", "mprotect", "LocalAlloc", "GlobalAlloc", "RtlMoveMemory",
    ],
    "com_ole": [
        "CoInitialize", "CoCreateInstance", "OleInitialize", "CoGetObject",
        "VariantInit", "SysAllocString",
    ],
    "browser_data": [
        "sqlite3_open", "CryptUnprotectData", "bcrypt", "NSS", "key3.db",
    ],
}


def categorize_import(name: str) -> str:
    """Return the behavioural category for an import name."""
    lowered = name.lower().lstrip("_").split("@")[0]
    for category, needles in CATEGORIES.items():
        for needle in needles:
            n = needle.lower()
            if lowered == n or lowered.startswith(n) or n in lowered:
                return category
    return "other"


def category_summary(names: List[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for name in names:
        cat = categorize_import(name)
        counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def capabilities_from_categories(counts: Dict[str, int]) -> List[str]:
    """Human-readable capability statements derived from category counts."""
    out: List[str] = []
    if counts.get("process_injection"):
        out.append("process injection / code injection into other processes")
    if counts.get("network"):
        out.append("network communication (C2 or exfiltration capable)")
    if counts.get("crypto"):
        out.append("cryptographic operations (possible ransomware or C2 encryption)")
    if counts.get("persistence"):
        out.append("persistence mechanisms")
    if counts.get("anti_analysis"):
        out.append("anti-analysis / evasion techniques")
    if counts.get("credential_access"):
        out.append("credential access")
    if counts.get("privilege"):
        out.append("privilege manipulation")
    if counts.get("registry"):
        out.append("registry manipulation")
    return out
