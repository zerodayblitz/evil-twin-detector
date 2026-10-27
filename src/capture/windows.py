"""
Windows beacon capture for the evil-twin-detector

Reads nearby access points and their raw beacon data through the Windows Native API (wlanapi.dll), called via ctypes
"""

import time
import ctypes
from ctypes import wintypes

wlanapi = ctypes.WinDLL("wlanapi.dll")

WlanOpenHandle = wlanapi.WlanOpenHandle
WlanOpenHandle.argtypes = [
    wintypes.DWORD, 
    ctypes.c_void_p, 
    ctypes.POINTER(wintypes.DWORD), 
    ctypes.POINTER(wintypes.HANDLE)
]
WlanOpenHandle.restype = wintypes.DWORD

class GUID(ctypes.Structure): # GUID structure
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

class WLAN_INTERFACE_INFO(ctypes.Structure): # single Wi-Fi Adapter Info
    _fields_ = [
        ("InterfaceGuid", GUID),                           # GUID
        ("strInterfaceDescription", wintypes.WCHAR * 256), # Adapter Name
        ("isState", wintypes.DWORD)                        # Adapter connectivity state
    ]

class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD), # of adapters
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)
    ]

WlanEnumInterfaces = wlanapi.WlanEnumInterfaces 
WlanEnumInterfaces.argtypes = [                              #using the open session listing adapters on the machine
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)) # Adapter count is abiratry, so rather than passing a pointer witha fixed size, allow windows to
]

class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG), # how many bites of the SSID is used
        ("ucSSID", ctypes.c_ubyte * 32)  # actually SSID bytes
    ]

class WLAN_RATE_SET(ctypes.Structure): # unused; holds AP's supported data rates
    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", wintypes.USHORT *126)
    ]
class WLAN_BSS_ENTRY(ctypes.Structure): # An APs complete Beacon data
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),                   # network name
        ("uPhyId", wintypes.DWORD),                       
        ("dot11Bssid", ctypes.c_ubyte * 6),          # BSSID
        ("dot11BssType", wintypes.DWORD),
        ("dot11BssPhyType", wintypes.DWORD),
        ("lRssi", wintypes.LONG),                    # signal strength 
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", wintypes.BOOL),
        ("usBeaconPeriod", wintypes.USHORT),
        ("ullTimestamp", ctypes.c_ulonglong),        # TSF
        ("ullHostTimestamp", ctypes.c_ulonglong),       
        ("usCapabilityInformation", wintypes.USHORT), # Capability flags
        ("ulChCenterFrequency", wintypes.ULONG),     # channel/frequency
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),              # where IE blob starts
        ("ulIeSize", wintypes.ULONG)                 # how big the IE blob is
    ]

class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),       # entire list of APs in bytes
        ("dwNumberOfItems", wintypes.DWORD),   # how many APs Windows found
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1) # array of each APs beacon data
    ]

WlanGetNetworkBssList = wlanapi.WlanGetNetworkBssList
WlanGetNetworkBssList.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(GUID),
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.BOOL,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST))
]
WlanGetNetworkBssList.restype = wintypes.DWORD

WlanScan = wlanapi.WlanScan                     # Active Scanning for APs
WlanScan.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(GUID),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p
]
WlanScan.restype = wintypes.DWORD

WlanCloseHandle = wlanapi.WlanCloseHandle
WlanCloseHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p
]
WlanCloseHandle.restype = wintypes.DWORD

def scan(interface_guid=None):
    # Scanning for nearby APs and returning their beacon data
    client_handle = wintypes.HANDLE()
    negotiated_version = wintypes.DWORD()

    result = WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(client_handle))
    if result != 0:
        raise OSError(f"WlanOpenHandle failed with error {result}")
    
    interface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()                     # holding the address of the set of interfaces

    result = WlanEnumInterfaces(client_handle, None, ctypes.byref(interface_list))
    if result != 0:
        raise OSError(f"WlanEnumInterfaces failed with error {result}")

    info_list = interface_list.contents
    if info_list.dwNumberOfItems == 0:
        raise OSError("No Wi-Fi interfaces found")

    chosen_guid = info_list.InterfaceInfo[0].InterfaceGuid

    result = WlanScan(client_handle, ctypes.byref(chosen_guid), None, None, None) # Starts active AP scan on chosen adapter
    if result != 0:
        raise OSError(f"WlanScan failed with error {result}")

    time.sleep(4)

    bss_list_ptr = ctypes.POINTER(WLAN_BSS_LIST)()                           # holding the address of the the AP data for Windows to fill

    result = WlanGetNetworkBssList(client_handle, ctypes.byref(chosen_guid), None, 0, False, None, ctypes.byref(bss_list_ptr))
    if result != 0:
        raise OSError(f"WlanGetNetworkBssList failed with error {result}")

    bss_list = bss_list_ptr.contents
    count = bss_list.dwNumberOfItems

    print(f"Found {count} access points: \n")

    for i in range(count):
        entry = bss_list.wlanBssEntries[i]

        ssid_bytes = bytes(entry.dot11Ssid.ucSSID[:entry.dot11Ssid.uSSIDLength])
        ssid = ssid_bytes.decode("utf-8", errors="replace")

        bssid = ":".join(f"{b:02x}" for b in entry.dot11Bssid)
        
        rssi = entry.lRssi
        channel_khz = entry.ulChCenterFrequency
        ie_size = entry.ulIeSize

        print(f"SSID:    {ssid}")
        print(f"BSSID:   {bssid}")
        print(f"RSSI:    {rssi} dBm")
        print(f"Channel: {channel_khz} kHz")
        print(f"IE size: {ie_size} bytes")
        print("-" * 40)

    wlanapi.WlanFreeMemory(bss_list_ptr)
    wlanapi.WlanFreeMemory(interface_list)
    WlanCloseHandle(client_handle, None)

if __name__ == "__main__":
    scan()