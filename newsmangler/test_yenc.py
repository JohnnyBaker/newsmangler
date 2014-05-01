import unittest
#import time
from sys import version_info
    
from yenc import *
from yenc import _yenc_encodeEscaped, _yenc_splitIntoLines

class TestYencoding(unittest.TestCase):
    def setUp(self):
        try:
            from cStringIO import StringIO
            self.postFile = StringIO()
        except ImportError:
            #python 3.x
            from io import BytesIO
            self.postFile = BytesIO()
    
    def test_yenc_encodeEscaped_basic(self):
        self.assertEqual(b'r\x8f\x96\x96\x99J\xa1\x99\x9c\x96\x8e', 
            _yenc_encodeEscaped(b'Hello world') )
        self.assertEqual('r\x8f\x96\x96\x99J\xa1\x99\x9c\x96\x8e', 
            _yenc_encodeEscaped('Hello world') )
        
    def test_yenc_encodeEscaped_specialChar(self):
        self.assertEqual(b'\x3d\x7d',
            _yenc_encodeEscaped(b'\x13') )
        
    @unittest.skipIf(version_info < (3, 0), "python3 specific method")
    def test_yEncode_CRC(self):
        self.assertEqual('8bd69e52', yEncode_Python3(self.postFile, b"Hello world", 11))
    
    def test_yenc_splitIntoLines(self):
        #>(1.2) Careful writers of encoders will encode TAB (09h) SPACES (20h)
        #>if they would appear in the first or last column of a line.
        #>Implementors who write directly to a TCP stream will care about the
        #doubling of dots in the first column - or also encode a DOT in the 
        #first column.
        result = _yenc_splitIntoLines(b'asdfasdf', 4)
        self.assertEqual([b'asdf', b'asdf'], result)
        
        result = _yenc_splitIntoLines('asdfasdf', 4)
        self.assertEqual(['asdf', 'asdf'], result )
        
        result = _yenc_splitIntoLines(b'asd=fasdf', 4) 
        self.assertEqual([b'asd=f', b'asdf'], result)
        
        #tab at the begin/end of line
        result = _yenc_splitIntoLines(b'\t', 100)
        self.assertEqual([b'=\x49'], result )
        
        result = _yenc_splitIntoLines(b'.sd\t', 4) 
        self.assertEqual([b'..sd=\x49'], result )
    
if __name__ == '__main__':
    unittest.main(verbosity=3)
