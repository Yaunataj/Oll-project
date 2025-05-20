#!/usr/bin/env python3
# ollloader.py - Secure OLL Management Frontend

import os
import sys
import hashlib
import ctypes
import struct
from ctypes import (
    CDLL, CFUNCTYPE, c_int, c_char_p, 
    c_void_p, c_uint64, POINTER
)

# ======================
# Constants & Configuration
# ======================

OLL_MAGIC = b'OLL\x00'
VALID_PASSWORD = "System-BootVendor.0X00"

# ======================
# Security Verification
# ======================

def verify_environment():
    """Ensure we're running in a secure environment"""
    if not os.path.exists('/dev/tpm0'):
        raise SecurityError("TPM device not found")
    if not os.geteuid() == 0:
        raise SecurityError("Must run as root")
    if 'LD_PRELOAD' in os.environ:
        raise SecurityError("LD_PRELOAD detected")

# ======================
# OLL Core Interface
# ======================

class OLLCore:
    def __init__(self):
        verify_environment()
        
        try:
            self._lib = CDLL('./ollcore.so')
            self._setup_bindings()
            
            # Verify our own hash matches expected
            current_hash = self._calculate_file_hash()
            if not self._lib.verify_caller(current_hash):
                raise SecurityError("Caller verification failed")
        except Exception as e:
            raise SecurityError(f"Initialization failed: {str(e)}")

    def _setup_bindings(self):
        # Core functions
        self._lib.oll_build.argtypes = [
            c_char_p, c_char_p, c_char_p, c_char_p
        ]
        self._lib.oll_build.restype = c_int
        
        self._lib.oll_validate.argtypes = [c_char_p]
        self._lib.oll_validate.restype = c_int
        
        self._lib.oll_load.argtypes = [c_char_p, c_char_p]
        self._lib.oll_load.restype = c_int
        
        # Security functions
        self._lib.verify_caller.argtypes = [c_char_p]
        self._lib.verify_caller.restype = c_int

    def _calculate_file_hash(self):
        """Calculate SHA-256 of our own executable"""
        with open(sys.argv[0], 'rb') as f:
            return hashlib.sha256(f.read()).digest()

    def build(self, input_file, output_file, vendor_key):
        """Build an OLL file from binary input"""
        result = self._lib.oll_build(
            input_file.encode(),
            output_file.encode(),
            vendor_key.encode(),
            VALID_PASSWORD.encode()
        )
        if result != 0:
            raise OLLError(f"Build failed with code {result}")

    def validate(self, oll_file):
        """Validate an OLL file"""
        result = self._lib.oll_validate(oll_file.encode())
        if result != 0:
            raise OLLError(f"Validation failed with code {result}")
        return True

    def load(self, oll_file):
        """Load and execute an OLL file"""
        result = self._lib.oll_load(
            oll_file.encode(),
            VALID_PASSWORD.encode()
        )
        if result != 0:
            raise OLLError(f"Load failed with code {result}")

# ======================
# Exception Classes
# ======================

class SecurityError(Exception):
    """Critical security violation"""
    pass

class OLLError(Exception):
    """OLL operation failure"""
    pass

# ======================
# Command Line Interface
# ======================

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [build|validate|load] <file> [vendor_key]")
        sys.exit(1)

    command = sys.argv[1]
    target_file = sys.argv[2]

    try:
        oll = OLLCore()
        
        if command == "build":
            if len(sys.argv) < 4:
                print("Error: Vendor key required for build")
                sys.exit(1)
            oll.build(target_file, sys.argv[3], sys.argv[4])
            print(f"Successfully built {sys.argv[3]}")
            
        elif command == "validate":
            if oll.validate(target_file):
                print(f"{target_file} is valid")
                
        elif command == "load":
            oll.load(target_file)
            print(f"{target_file} executed successfully")
            
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
            
    except SecurityError as e:
        print(f"SECURITY VIOLATION: {str(e)}")
        sys.exit(1)
    except OLLError as e:
        print(f"OPERATION FAILED: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
