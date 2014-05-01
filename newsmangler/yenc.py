# Copyright (c) 2005-2012 freddie@wafflemonster.org
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Useful functions for yEnc encoding/decoding."""

import re
import zlib
from sys import version_info

# ---------------------------------------------------------------------------

HAVE_PSYCO = False
HAVE_YENC = False
HAVE_YENC_FRED = False

# ---------------------------------------------------------------------------
# Translation tables
YDEC_TRANS = ''.join([chr((i + 256 - 42) % 256) for i in range(256)])
YENC_TRANS = ''.join([chr((i + 42) % 256) for i in range(256)])

if (version_info > (3,0)):
    YENC_TRANS2 = b''
    for i in range(256):
        YENC_TRANS2 += ((i + 42) % 256).to_bytes(1, byteorder='big')
    NOENC_TRANS = b''
    for i in range(256):
        NOENC_TRANS += i.to_bytes(1, byteorder='big')

#yenc_trans42 = string.join(map(lambda x: chr((x+42) % 256), range(256)), "")

YDEC_MAP = {}
for i in range(256):
    YDEC_MAP[chr(i)] = chr((i + 256 - 64) % 256)

# ---------------------------------------------------------------------------

def yDecode(data):
    # unescape any escaped char (grr)
    data = re.sub(r'=(.)', yunescape, data)
    return data.translate(YDEC_TRANS)

def yunescape(m):
    return YDEC_MAP[m.group(1)]

def yEncode_C(postfile, data):
    # If we don't have my modified yenc module, we have to do the . quoting
    # ourselves. This is about 50% slower.
    if HAVE_YENC_FRED:
        yenced, tempcrc = _yenc.encode_string(data, escapedots=1)[:2]
    else:
        yenced, tempcrc = _yenc.encode_string(data)[:2]
        yenced = yenced.replace('\r\n.', '\r\n..')
    
    postfile.write(yenced)
    
    if not yenced.endswith('\r\n'):
        postfile.write('\r\n')
    
    return '%08x' % ((tempcrc ^ -1) & 2**32 - 1)


char_to_yenc_byte = lambda char, base=64: ((char + base) % 256).to_bytes(1, byteorder='big')


def _yenc_encodeEscaped(data):
    if isinstance(data, str):        
        translated = data.translate(YENC_TRANS)
    
        # escape {=, NUL, LF, CR}
        for i in (61, 0, 10, 13):
            j = '=%c' % (i + 64)
            translated = translated.replace(chr(i), j)
    else:
        #python3 behavoral
        transTable = bytes.maketrans(NOENC_TRANS, YENC_TRANS2)
        translated = data.translate(transTable)
        
        charsToBeEscaped = (ord('='), ord('\0'), ord('\n'), ord('\r'))
        for eachChar in charsToBeEscaped:
            escapeChar = b'=' + char_to_yenc_byte(eachChar, 64)
            translated = translated.replace((eachChar).to_bytes(1, byteorder='big'), escapeChar)
    
    return translated

def _yenc_splitIntoLines(translated, maxLineLen=128):
    lineList = []
    
    # split the rest of it into lines
    start = end = 0
    datalen = len(translated)
    
    while end < datalen:
        end = min(datalen, start + maxLineLen)
        line = translated[start:end]
        
        # FIXME: line consisting entirely of a space/tab
        if start == end - 1:
            if line[0] in (ord('\t'), ord(' ')):
                line = b'=' + char_to_yenc_byte(line[0])
        else:
            if line[0] in (ord('\t'), ord(' ')):
                line = b'=' + char_to_yenc_byte(line[0]) + line[1:-1]
                end -= 1
            elif line[0] == ord('.'):
                line = b'.' + line
            
            endOfLine_byte = line[-1]
            if endOfLine_byte == ord('='):
                # escaped char occurrence at the end of the line
                # add the real char from translated buffer
                line += char_to_yenc_byte(translated[end],0)
                end += 1
            elif endOfLine_byte in (ord('\t'), ord(' ')):
                line = line[:-1] + b'=' + char_to_yenc_byte(line[-1])
        
        # FIXME: doesn't follow the "Command Query Separation" -> separate from function
        start = end
        lineList.append(line)
        
    return lineList

def yEncode_Python3(postfile, data, maxLineLen=128):
    'Encode data into yEnc format'
    
    translated = _yenc_encodeEscaped(data)
    lineList = _yenc_splitIntoLines(translated, maxLineLen)
    
    for eachLine in lineList:
        postfile.write(eachLine)
        postfile.write(b'\r\n')
    
    return CRC32(data)

# ---------------------------------------------------------------------------

YSPLIT_RE = re.compile(r'(\S+)=')

# Split a =y* line into key/value pairs
def ySplit(line):
    fields = {}
    
    parts = YSPLIT_RE.split(line)[1:]
    if len(parts) % 2:
        return fields
    
    for i in range(0, len(parts), 2):
        key, value = parts[i], parts[i+1]
        fields[key] = value.strip()
    
    return fields

# ---------------------------------------------------------------------------

def yEncMode():
    if HAVE_YENC_FRED:
        return 'yenc-fred'
    elif HAVE_YENC:
        return 'yenc-vanilla'
    elif HAVE_PSYCO:
        return 'python-psyco'
    else:
        return 'python-vanilla'

# ---------------------------------------------------------------------------
# Make a human readable CRC32 value
def CRC32(data):
    return '%08x' % (zlib.crc32(data) & 2**32 - 1)

# Come up with a 'safe' filename
def SafeFilename(filename):
    safe_filename = os.path.basename(filename)
    for char in [' ', "\\", '|', '/', ':', '*', '?', '<', '>']:
        safe_filename = safe_filename.replace(char, '_')
    return safe_filename

# ---------------------------------------------------------------------------
# Use the _yenc C module if it's available. If not, try to use psyco to speed
# up part encoding 25-30%.
try:
    import _yenc
except ImportError:
    try:
        import psyco
    except ImportError:
        pass
    else:
        HAVE_PSYCO = True
        psyco.bind(yEncode_Python3)
    yEncode = yEncode_Python3
else:
    HAVE_YENC = True
    HAVE_YENC_FRED = ('Freddie mod' in _yenc.__doc__)
    yEncode = yEncode_C
