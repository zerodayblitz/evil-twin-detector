"""

802.11 Information Element parser
Walks the raw IE byte blob (TLV) from the beacon frames and constructs
them into an ordered and structured list of elements

"""

from dataclasses import dataclass

@dataclass
class InformationElement:
    element_id: int
    data: bytes

def parse_ies(ie_bytes):
    # Walk a raw IE byte blob and return ordered list of Information Elements

    elements = []
    offset = 0
    malformed = False

    while offset + 2 <= len(ie_bytes):
        element_id = ie_bytes[offset]           # read the single byte at position 'offset'; the TYPE
        length = ie_bytes[offset + 1]           # read the single byte at position 'offset + 1"; the LENGTH

        if offset + 2 + length > len(ie_bytes): # Comparing TLV claimed length against remaining bytes in the IE blob
            malformed = True
            break

        data = ie_bytes[offset + 2 : offset + 2 + length]
        elements.append(InformationElement(element_id=element_id, data=data))
        offset += 2 + length                    # Updating IE blob position

    return elements, malformed