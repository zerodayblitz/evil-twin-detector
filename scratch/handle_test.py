"""
Phase 0 proof-of-concept: confirm Python can reach the Windows Native WLAN API.

Opens a handle to the WLAN AutoConfig service via wlanapi.dll (called by hand
through ctypes), prints the session handle on success. This is a throwaway
environment check, not part of the detector.
"""

import ctypes
from ctypes import wintypes

wlanapi = ctypes.WinDLL("wlanapi.dll")

# WlanOpenHandle(dwClientVersion, pReserved, pdwNegotiatedVersion, phClientHandle)
WlanOpenHandle = wlanapi.WlanOpenHandle
WlanOpenHandle.argtypes = [
    wintypes.DWORD,  # client version requested
    ctypes.c_void_p,  # reserved, must be NULL
    ctypes.POINTER(wintypes.DWORD),  # out: negotiated version
    ctypes.POINTER(wintypes.HANDLE),  # out: session handle
]
WlanOpenHandle.restype = wintypes.DWORD  # Win32 error code, 0 = success

# Output boxes the API writes into.
negotiated_version = wintypes.DWORD()
client_handle = wintypes.HANDLE()

# Version 2 = Vista and later (the modern WLAN API).
result = WlanOpenHandle(
    2, None, ctypes.byref(negotiated_version), ctypes.byref(client_handle)
)

if result == 0:
    print("Success - WLAN handle opened")
    print("Handle value:", client_handle.value)
else:
    print("Failed - error code:", result)
