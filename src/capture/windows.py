"""
Windows beacon capture for the evil-twin-detector

Reads nearby access points and their raw beacond data through the Windows Native API (wlanapi.dll), called via ctypes
"""

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
        ("Data4", ctypes.c_ubtye * 8)
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

class DOT11_SSID(cytpes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG), # how many bites of the SSID is used
        ("ucSSID", cytpes.c_ubtye * 32)  # actually SSID bytes
    ]

class WLAN_RATE_SET(ctypes.Structure): # unused; holds AP's supported data rates
    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", wintypes.USHORT *126)
    ]
class WLAN_BSS_ENTRY(ctypes.Structure): # An APs complete Beacon data
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),                   # network name
        ("uPhyId", wintypes),                       
        ("dot11Bssid", ctypes.c_ubtye * 6),          # BSSID
        ("dot11BssType", wintypes.DWORD)
        ("dot11BssPhyType", wintypes.DWORD),
        ("1Rssi", wintypes.LONG),                    # signal strength 
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", wintypes.BOOL),
        ("usBeaconPeriod", wintypes.USHORT),
        ("ullTimestamp", ctypes.c_ulonglong),        # TSF
        ("ullHostTimestamp", ctypes.c_ulonglong),       
        ("usCapabilityInformation", wintypes.ULONG), # Capability flags
        ("ulChCenterFrequency", wintypes.ULONG),     # channel/frequency
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),              # where IE blob starts
        ("ulIeSize", wintypes.ULONG)                 # how big the IE blob is
    ]

class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),       # entire list of APs in bytes
        ("dwNumberofItems", wintypes.DWORD),   # how many APs Windows found
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1) # array of each As beacon data
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

WlanCloseHandle = wlanapi.WlanCloseHandle
WlanClose.argtypes = [
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
        raise OSError(f"WlanOpenHandle failled with error" {result})


        