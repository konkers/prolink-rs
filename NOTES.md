byte 0x21 seems to be protocal version.  CDJ-3000s have a 3 here.

Proto version 3 differences:

Anounce packet (0x00) has an extra byte at the end.  Observed to be 0x0.

CDJ-3000 uses port 32819 for metadata looksup.

CDJ-3000 metadata arg tags are not padded with zero.  Only the number of tags corresponding to the args are present.

CDJ-3000 has 16 metadata fields and they are numbered differently than in the doc.   Important to read the "menu type' field.

More notes:
   Byte 0x30 of keep alive is "peers seen" including self
   Bytes 0x35 of keep alive is variable.  CDJ3000 sets this to 0x24.
   Claim3 packet's device number is zero on CDJ3000's