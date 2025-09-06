#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized RexNDR and RexText classes for NDR encoding and text manipulation
"""

import struct
import random
import binascii
import string
from collections import defaultdict


class RexNDR:
    """Network Data Representation (NDR) encoding utilities"""
    
    @staticmethod
    def align(data: bytes) -> bytes:
        """Provide padding to align data to 32-bit boundary"""
        padding_len = (4 - (len(data) % 4)) % 4
        return b"\x00" * padding_len

    @staticmethod
    def long(value: int) -> bytes:
        """Encode a 4-byte integer (little-endian)"""
        return struct.pack('<I', value)

    @staticmethod
    def short(value: int) -> bytes:
        """Encode a 2-byte integer (little-endian)"""
        return struct.pack('<H', value)

    @staticmethod
    def byte(value: int) -> bytes:
        """Encode a single byte"""
        return struct.pack('B', value)

    @staticmethod
    def uni_conformant_array(data: bytes) -> bytes:
        """Encode a conformant byte array"""
        length = RexNDR.long(len(data))
        padding = RexNDR.align(data)
        return length + data + padding

    @staticmethod
    def string(s: str) -> bytes:
        """Encode an ASCII string with NDR format"""
        ascii_data = (s + '\x00').encode('ascii')
        length = len(ascii_data)
        return RexNDR.long(length) + RexNDR.long(0) + RexNDR.long(length) + ascii_data + RexNDR.align(ascii_data)

    @staticmethod
    def wstring(s: str) -> bytes:
        """Encode a Unicode string with NDR format"""
        utf16_data = (s + '\x00').encode('utf-16le')
        char_count = len(utf16_data) // 2
        return RexNDR.long(char_count) + RexNDR.long(0) + RexNDR.long(char_count) + utf16_data + RexNDR.align(utf16_data)

    @staticmethod
    def uwstring(s: str) -> bytes:
        """Encode a unique Unicode string with NDR format"""
        utf16_data = (s + '\x00').encode('utf-16le')
        char_count = len(utf16_data) // 2
        unique_id = random.randint(0, 0xFFFFFFFF)
        return (
            RexNDR.long(unique_id) +
            RexNDR.long(char_count) +
            RexNDR.long(0) +
            RexNDR.long(char_count) +
            utf16_data +
            RexNDR.align(utf16_data)
        )

    @staticmethod
    def wstring_prebuilt(utf16_data: bytes) -> bytes:
        """Encode prebuilt UTF-16 data with NDR format"""
        if len(utf16_data) % 2 != 0:
            utf16_data += b'\x00'
        
        char_count = len(utf16_data) // 2
        return (
            RexNDR.long(char_count) +
            RexNDR.long(0) +
            RexNDR.long(char_count) +
            utf16_data +
            RexNDR.align(utf16_data)
        )

    @staticmethod
    def unicode_conformant_varying_string(s: str) -> bytes:
        """Alias for wstring"""
        return RexNDR.wstring(s)

    @staticmethod
    def unicode_conformant_varying_string_prebuilt(utf16_data: bytes) -> bytes:
        """Alias for wstring_prebuilt"""
        return RexNDR.wstring_prebuilt(utf16_data)


class RexText:
    """Text encoding and decoding utilities"""
    
    # Codepage cache simulation
    _codepage_map_cache = defaultdict(dict)
    
    @staticmethod
    def to_unicode(
        s: str, 
        encoding: str = 'utf-16le', 
        mode: str = '', 
        size: int = 2
    ) -> bytes:
        """Convert text to Unicode bytes with various encoding options"""
        if not s:
            return b''
        
        if encoding == 'utf-16le':
            return s.encode('utf-16le')
        if encoding == 'utf-16be':
            return s.encode('utf-16be')
        if encoding == 'utf-32le':
            return s.encode('utf-32le')
        if encoding == 'utf-32be':
            return s.encode('utf-32be')
        if encoding == 'utf-7':
            return RexText._encode_utf7(s, mode)
        if encoding == 'utf-8':
            return RexText._encode_utf8(s, mode, size)
        
        raise ValueError(f'Unsupported encoding: {encoding}')

    @staticmethod
    def _encode_utf7(s: str, mode: str) -> bytes:
        """Encode text using UTF-7 encoding"""
        if mode == 'all':
            encoded = ''.join(
                f"+{binascii.b2a_base64(c.encode('utf-16be')).decode().strip().replace('=', '')}-" 
                for c in s
            )
            return encoded.encode('ascii')
        
        # Only encode non-alphanumeric characters
        safe_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\'(),-./:? '
        return ''.join(
            c if c in safe_chars 
            else f"+{binascii.b2a_base64(c.encode('utf-16be')).decode().strip().replace('=', '')}-"
            for c in s
        ).encode('ascii')

    @staticmethod
    def _encode_utf8(s: str, mode: str, size: int) -> bytes:
        """Encode text using UTF-8 with optional modes"""
        if size < 2 or size > 7:
            raise ValueError('Invalid UTF-8 size (2-7 allowed)')
        
        result = bytearray()
        for char in s:
            code = ord(char)
            if code < 0x80 and not mode:
                result.append(code)
            else:
                if mode == 'overlong':
                    result.extend(RexText._overlong_utf8(char, size))
                elif mode == 'invalid':
                    result.extend(RexText._invalid_utf8(size))
                else:
                    result.extend(char.encode('utf-8'))
        return bytes(result)

    @staticmethod
    def _overlong_utf8(char: str, size: int) -> bytes:
        """Generate overlong UTF-8 encoding for a character"""
        code = ord(char)
        bin_str = bin(code)[2:].zfill(8)
        out = [0] * (8 * size)
        
        # Set continuation bits
        for i in range(size):
            out[i * 8] = 1
            if i > 0:
                out[i] = 1
        
        # Distribute bits
        bit_idx = 0
        for bit in reversed(bin_str):
            if bit_idx < 6:
                pos = (size * 8 - 1) - (bit_idx // 8) * 8 - (bit_idx % 8)
                out[pos] = int(bit)
                bit_idx += 1
        
        # Convert to bytes
        byte_seq = bytearray()
        for i in range(size):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | out[i * 8 + j]
            byte_seq.append(byte_val)
        return byte_seq

    @staticmethod
    def _invalid_utf8(size: int) -> bytes:
        """Generate invalid UTF-8 byte sequence"""
        byte_seq = bytearray(size)
        byte_seq[0] = 0xC0 + random.randint(0, 0x1F)
        for i in range(1, size):
            byte_seq[i] = random.randint(0x80, 0xBF)
        return byte_seq

    @staticmethod
    def to_ascii(data: bytes, encoding: str = 'utf-16le') -> str:
        """Convert Unicode bytes to ASCII text"""
        if not data:
            return ''
        
        if encoding == 'utf-16le':
            return data.decode('utf-16le')
        if encoding == 'utf-16be':
            return data.decode('utf-16be')
        if encoding == 'utf-32le':
            return data.decode('utf-32le')
        if encoding == 'utf-32be':
            return data.decode('utf-32be')
        
        raise ValueError(f'Unsupported encoding: {encoding}')

    @staticmethod
    def to_unescape(
        data: bytes, 
        endian: str = 'little', 
        prefix: str = '%u'
    ) -> str:
        """Convert bytes to JavaScript unicode escape format"""
        if len(data) % 2 != 0:
            data += b'A'  # Padding
        
        result = []
        for i in range(0, len(data), 2):
            c1, c2 = data[i], data[i+1]
            if endian == 'little':
                result.append(f"{prefix}{c2:02X}{c1:02X}")
            else:
                result.append(f"{prefix}{c1:02X}{c2:02X}")
        return ''.join(result)

    @staticmethod
    def unicode_filter_encode(s: str) -> str:
        """Encode string with custom unicode filter"""
        if any(ord(c) > 0x7F for c in s):
            safe_chars = ''.join(c for c in s if 0x20 <= ord(c) <= 0x7E and c != '-')
            hex_data = binascii.hexlify(s.encode('utf-8')).decode()
            return f"$U${safe_chars}-0x{hex_data}"
        return s

    @staticmethod
    def unicode_filter_decode(s: str) -> str:
        """Decode string encoded with unicode_filter_encode"""
        parts = s.split('$U$')
        if len(parts) < 2:
            return s
        
        result = []
        for part in parts[1:]:
            if '-0x' in part:
                safe_part, hex_part = part.split('-0x', 1)
                try:
                    decoded = binascii.unhexlify(hex_part).decode('utf-8')
                    result.append(safe_part + decoded)
                except:
                    result.append(safe_part)
            else:
                result.append(part)
        return parts[0] + ''.join(result)

    @staticmethod
    def to_utf8(s: str) -> str:
        """Convert text to UTF-8, skipping invalid characters"""
        return s.encode('utf-8', errors='ignore').decode('utf-8')
    
    @staticmethod
    def hex_dump(data: bytes, width: int = 16) -> str:
        """Generate formatted hexadecimal dump with line numbers and offsets"""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]

            # Format line number and offset
            line_num = f"{i // width:04d}"  # 4-digit line number
            hex_offset = f"{i:08X}"  # 8-digit hexadecimal offset

            # Format hexadecimal values
            hex_str = ' '.join(f"{b:02x}" for b in chunk)

            # Pad hex string to full width
            hex_padding = '   ' * (width - len(chunk))
            hex_line = hex_str + hex_padding

            # Format ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)

            # Combine all parts
            lines.append(f"{line_num}: {hex_offset}  {hex_line}  |{ascii_str}|")

        return '\n'.join(lines)
    
    @staticmethod
    def rand_text_alpha(size: int) -> str:
        """Generate random alpha text"""
        length: int = random.randint(1, size)
        return ''.join(random.choices(string.ascii_uppercase, k=length))