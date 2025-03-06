#!/usr/bin/env python3
"""
Author: Vahe Demirkhanyan
Advanced Cisco ASA Version Detector

This script uses multiple detection techniques to accurately identify Cisco ASA versions:
1. HTTPS web interface analysis
2. SSH banner grabbing
3. SNMP polling
4. TLS/SSL fingerprinting
5. HTTP header analysis
6. Behavioral fingerprinting
"""

import argparse
import re
import json
import socket
import struct
import time
import urllib3
import hashlib
import ssl
import os
import logging
from typing import Dict, List, Optional, Tuple, Union, Any
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache

# Third-party libraries
import requests
import paramiko
from pysnmp.hlapi import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup

from cryptography.hazmat.primitives.asymmetric import rsa

# Suppress insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cisco_detector')

# Define a dataclass to store version information with confidence levels
@dataclass
class VersionInfo:
    version: str
    confidence: float
    detection_method: str
    details: dict = None
    
    def __str__(self):
        return f"{self.version} (confidence: {self.confidence:.2f}, method: {self.detection_method})"

# load fingerprint database from JSON file if there are any, if not - go to defaults..
def load_fingerprint_database(db_path: str = 'cisco_fingerprints.json') -> dict:
    """Load fingerprint database or create a default one if not found."""
    default_db = {
        "http_patterns": [
            {
                "pattern": r"(?i)Cisco Adaptive Security Appliance.*?Version\s*([\d\(\)\.\w-]+)",
                "confidence": 0.9
            },
            {
                "pattern": r"(?i)<title>Cisco ASDM .*?Version\s*([\d\(\)\.\w-]+)</title>",
                "confidence": 0.85
            },
            {
                "pattern": r"(?i)ASDM\s*v([\d\(\)\.\w-]+)",
                "confidence": 0.8
            },
            {
                "pattern": r"(?i)Version:\s*([\d\(\)\.\w-]+)",
                "confidence": 0.85
            },
            {
                "pattern": r"(?i)asa_version\s*=\s*'([\d\(\)\.\w-]+)'",
                "confidence": 0.8
            },
            {
                "pattern": r"(?i)<meta\s+name=\"generator\"\s+content=\"Cisco ASDM\s+([\d\(\)\.\w-]+)\"",
                "confidence": 0.85
            }
        ],
        "ssh_banners": {
            "SSH-2.0-Cisco-1.25": {"versions": ["9.1(x)"], "confidence": 0.7},
            "SSH-2.0-Cisco-2.0": {"versions": ["9.2(x)", "9.3(x)"], "confidence": 0.7},
            "SSH-1.99-Cisco-1.25": {"versions": ["8.4(x)"], "confidence": 0.7},
            "SSH-2.0-Cisco-1.0": {"versions": ["8.0(x)", "8.1(x)"], "confidence": 0.7},
            "SSH-2.0-Cisco-1.5": {"versions": ["9.0(x)"], "confidence": 0.7},
            "SSH-2.0-Cisco-2.5": {"versions": ["9.4(x)", "9.5(x)"], "confidence": 0.7},
            "SSH-2.0-Cisco-3.0": {"versions": ["9.6(x)", "9.7(x)"], "confidence": 0.7}
        },
        "tls_fingerprints": {
            # Note: These are placeholders; replace with actual certificate hashes
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890": {
                "versions": ["9.8(2)"],
                "confidence": 0.75
            },
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": {
                "versions": ["9.12(1)"],
                "confidence": 0.75
            }
        },
        "snmp_oids": {
            "1.3.6.1.2.1.1.1.0": {"description": "sysDescr", "confidence": 0.9},
            "1.3.6.1.4.1.9.9.491.1.1.1.1.0": {"description": "ciscoASA version", "confidence": 0.95},
            "1.3.6.1.4.1.9.1.745": {"name": "ciscoASA5505", "confidence": 0.9},
            "1.3.6.1.4.1.9.1.1240": {"name": "ciscoASA5506", "confidence": 0.9},
            "1.3.6.1.4.1.9.1.1241": {"name": "ciscoASA5508", "confidence": 0.9},
            "1.3.6.1.4.1.9.1.1242": {"name": "ciscoASA5512", "confidence": 0.9}
        },
        "api_endpoints": {
            "/+CSCOE+/logon.html": {"status_codes": {200: ["8.4(x)", "9.1(x)"]}, "confidence": 0.6},
            "/admin/public/index.html": {"status_codes": {200: ["9.1(x)", "9.2(x)"]}, "confidence": 0.6},
            "/+CSCOE+/portal.html": {"status_codes": {200: ["9.3(x)", "9.4(x)"]}, "confidence": 0.6},
            "/api/monitoring/traffic": {"status_codes": {200: ["9.4(x)+"]}, "confidence": 0.7},
            "/doc/help/ASDM_help.html": {"status_codes": {200: ["9.0(x)", "9.1(x)"]}, "confidence": 0.6}
        },
        "http_headers": {
            "Server": {
                "Cisco HTTP Server": {"versions": ["9.x"], "confidence": 0.5},
                "Cisco-ASA": {"versions": ["8.x"], "confidence": 0.5},
                "Cisco Adaptive Security Appliance": {"versions": ["7.x", "8.x"], "confidence": 0.5}
            },
            "X-Powered-By": {
                "Cisco ASDM": {"versions": ["9.x"], "confidence": 0.6}
            }
        }
    }

    try:
        if os.path.exists(db_path):
            with open(db_path, 'r') as f:
                loaded_db = json.load(f)
            # Ensure all required keys are present, filling in from default if missing
            for key in default_db:
                if key not in loaded_db:
                    loaded_db[key] = default_db[key]
            return loaded_db
        else:
            with open(db_path, 'w') as f:
                json.dump(default_db, f, indent=4)
            logger.info(f"Created default fingerprint database at {db_path}")
            return default_db
    except json.JSONDecodeError as e:
        logger.warning(f"Error decoding JSON from {db_path}: {e}. Using default database.")
        return default_db
    except Exception as e:
        logger.warning(f"Error loading fingerprint database: {e}. Using default database.")
        return default_db

# new methods - tls, ssh, ike/vpn yahoooo
def detect_tls_versions(target: str, port: int = 443, timeout: int = 5) -> List[VersionInfo]:
    """
    Detect supported TLS versions to infer ASA version.
    TLS 1.2 was added in ASA 9.3(2)
    TLS 1.3 was added in ASA 9.19(1)
    
    Returns version information based on TLS protocol support.
    """
    results = []  # Initialize results as an empty list
    
    # Compatibility for different Python versions
    if hasattr(ssl, 'TLS_VERSION_1_3'):
        # Newer Python versions
        TLS_V1_3 = ssl.TLS_VERSION_1_3
        TLS_V1_2 = ssl.TLS_VERSION_1_2 
        TLS_V1_1 = ssl.TLS_VERSION_1_1
    else:
        # Older Python versions
        TLS_V1_3 = ssl.TLSVersion.TLSv1_3
        TLS_V1_2 = ssl.TLSVersion.TLSv1_2
        TLS_V1_1 = ssl.TLSVersion.TLSv1_1
    
    # Dictionary mapping TLS versions to ASA version info
    tls_version_map = {
        "TLSv1.3": {
            "min_version": "9.19(1)",
            "confidence": 0.85,
            "detection_method": "TLS Version Support: TLS 1.3"
        },
        "TLSv1.2": {
            "min_version": "9.3(2)", 
            "confidence": 0.8,
            "detection_method": "TLS Version Support: TLS 1.2"
        },
        "TLSv1.1": {
            "max_version": "9.3(1)",  # If only TLS 1.1 is supported (no TLS 1.2)
            "confidence": 0.75,
            "detection_method": "TLS Version Support: TLS 1.1 only"
        }
    }
    
    #modern cipher suites that indicate newer ASA versions
    modern_cipher_map = {
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
            "min_version": "9.x",  # More research needed for exact version
            "confidence": 0.7,
            "detection_method": "TLS Cipher Support: ECDHE+GCM"
        },
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": {
            "min_version": "9.x",  # More research needed for exact version
            "confidence": 0.7,
            "detection_method": "TLS Cipher Support: DHE+GCM"
        }
    }
    
    supported_tls_versions = []
    supported_ciphers = []
    
    try:
        # Test TLS 1.3
        context_tls13 = ssl.create_default_context()
        context_tls13.minimum_version = TLS_V1_3
        context_tls13.maximum_version = TLS_V1_3
        context_tls13.check_hostname = False
        context_tls13.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context_tls13.wrap_socket(sock, server_hostname=target) as ssock:
                    supported_tls_versions.append("TLSv1.3")
                    # Get negotiated cipher
                    cipher = ssock.cipher()
                    if cipher:
                        supported_ciphers.append(cipher[0])
        except ssl.SSLError:
            # TLS 1.3 not supported, which is expected for most ASA versions
            pass
        
        # Test TLS 1.2
        context_tls12 = ssl.create_default_context()
        context_tls12.minimum_version = TLS_V1_2
        context_tls12.maximum_version = TLS_V1_2
        context_tls12.check_hostname = False
        context_tls12.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context_tls12.wrap_socket(sock, server_hostname=target) as ssock:
                    supported_tls_versions.append("TLSv1.2")
                    # Get negotiated cipher
                    cipher = ssock.cipher()
                    if cipher:
                        supported_ciphers.append(cipher[0])
        except ssl.SSLError:
            # TLS 1.2 not supported
            pass
            
        # Testing for TLS 1.1
        context_tls11 = ssl.create_default_context()
        context_tls11.minimum_version = TLS_V1_1
        context_tls11.maximum_version = TLS_V1_1
        context_tls11.check_hostname = False
        context_tls11.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context_tls11.wrap_socket(sock, server_hostname=target) as ssock:
                    supported_tls_versions.append("TLSv1.1")
                    # Get negotiated cipher
                    cipher = ssock.cipher()
                    if cipher:
                        supported_ciphers.append(cipher[0])
        except ssl.SSLError:
            # TLS 1.1 not supported
            pass
            
        # Add results based on TLS version support
        if "TLSv1.3" in supported_tls_versions:
            # If TLS 1.3 is supported, ASA is running version 9.19(1) or later
            results.append(VersionInfo(
                version=tls_version_map["TLSv1.3"]["min_version"],
                confidence=tls_version_map["TLSv1.3"]["confidence"],
                detection_method=tls_version_map["TLSv1.3"]["detection_method"],
                details={"supported_tls_versions": supported_tls_versions}
            ))
        elif "TLSv1.2" in supported_tls_versions:
            # If TLS 1.2 is supported but not TLS 1.3, ASA is between 9.3(2) and 9.18(x)
            results.append(VersionInfo(
                version=tls_version_map["TLSv1.2"]["min_version"] + " - 9.18(x)",
                confidence=tls_version_map["TLSv1.2"]["confidence"],
                detection_method=tls_version_map["TLSv1.2"]["detection_method"],
                details={"supported_tls_versions": supported_tls_versions}
            ))
        elif "TLSv1.1" in supported_tls_versions:
            # If only TLS 1.1 is supported, ASA is likely older than 9.3(2)
            results.append(VersionInfo(
                version="< " + tls_version_map["TLSv1.2"]["min_version"],
                confidence=tls_version_map["TLSv1.1"]["confidence"],
                detection_method=tls_version_map["TLSv1.1"]["detection_method"],
                details={"supported_tls_versions": supported_tls_versions}
            ))
            
        # Check for modern ciphers
        for cipher_name in supported_ciphers:
            for known_cipher, info in modern_cipher_map.items():
                if known_cipher in cipher_name:
                    results.append(VersionInfo(
                        version=info["min_version"],
                        confidence=info["confidence"],
                        detection_method=info["detection_method"],
                        details={"cipher": cipher_name}
                    ))
                    
        # Get certificate and check if it's the default ASA self-signed cert
        for context in [context_tls12, context_tls11]:
            try:
                with socket.create_connection((target, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                            subject = x509_cert.subject.rfc4514_string()
                            
                            # Check for ASA default cert
                            if "ASA Temporary Self Signed Certificate" in subject:
                                results.append(VersionInfo(
                                    version="Cisco ASA (default certificate)",
                                    confidence=0.9,
                                    detection_method="TLS Certificate: Default ASA Cert",
                                    details={"certificate_subject": subject}
                                ))
                                
                            # Check key size for potential version clues
                            public_key = x509_cert.public_key()
                            if isinstance(public_key, rsa.RSAPublicKey):
                                key_size = public_key.key_size
                                if key_size == 1024:
                                    # Older ASAs used 1024-bit keys by default
                                    results.append(VersionInfo(
                                        version="Likely < 9.x (1024-bit key)",
                                        confidence=0.6,
                                        detection_method="TLS Certificate: RSA Key Size",
                                        details={"key_size": key_size}
                                    ))
                                elif key_size >= 2048:
                                    # Newer ASAs use 2048-bit or larger keys
                                    results.append(VersionInfo(
                                        version="Likely >= 9.x (2048-bit+ key)",
                                        confidence=0.6,
                                        detection_method="TLS Certificate: RSA Key Size",
                                        details={"key_size": key_size}
                                    ))
                        break  # Once we get a certificate, no need to try other contexts
            except Exception:
                continue
                    
    except Exception as e:
        logger.debug(f"TLS version detection error: {e}")
    
    return results

def enhanced_ssh_fingerprinting(target: str, port: int = 22, timeout: int = 5) -> List[VersionInfo]:
    """
    Enhanced SSH fingerprinting based on key types and algorithms supported.
    
    ASA 9.16(1) added support for ECDSA and Ed25519 host keys.
    Older versions only support RSA keys and older algorithms.
    """
    results = []  # Initialize results as an empty list
    
    # Define version indicators based on supported SSH algorithms
    ssh_algorithm_indicators = {
        "ssh-ed25519": {
            "version": "≥ 9.16(1)",
            "confidence": 0.85,
            "description": "Ed25519 support added in ASA 9.16(1)"
        },
        "ecdsa-sha2-nistp256": {
            "version": "≥ 9.16(1)",
            "confidence": 0.85,
            "description": "ECDSA support added in ASA 9.16(1)"
        },
        "curve25519-sha256": {
            "version": "≥ 9.16(1)",
            "confidence": 0.8,
            "description": "Modern key exchange added in ASA 9.16(1)"
        },
        "diffie-hellman-group-exchange-sha256": {
            "version": "≥ 9.x",
            "confidence": 0.7,
            "description": "SHA256 DH group exchange indicates later 9.x"
        },
        "diffie-hellman-group1-sha1": {
            "version": "< 9.12",
            "confidence": 0.6,
            "description": "Weak DH group indicates pre-9.12 (deprecated later)"
        }
    }
    
    try:
        # First attempt basic socket connection to grab banner
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Check for specific Cisco SSH banner
            if "SSH-2.0-Cisco" in banner:
                results.append(VersionInfo(
                    version="Cisco ASA (SSH enabled)",
                    confidence=0.9,
                    detection_method="SSH Banner",
                    details={"banner": banner}
                ))
        
        # Use paramiko for more detailed SSH fingerprinting
        transport = paramiko.Transport((target, port))
        transport.banner_timeout = timeout
        transport.handshake_timeout = timeout
        
        # Start key negotiation
        try:
            transport.start_client()
            
            # Get server key types and algorithms
            key_types = transport.get_remote_server_key().get_name()
            kex_algs = transport._preferred_kex
            key_algs = transport._preferred_keys
            cipher_algs = transport._preferred_ciphers
            mac_algs = transport._preferred_macs
            
            all_algs = []
            if hasattr(transport, '_preferred_kex'):
                all_algs.extend(transport._preferred_kex)
            if hasattr(transport, '_preferred_keys'):
                all_algs.extend(transport._preferred_keys)
            if hasattr(transport, '_preferred_ciphers'):
                all_algs.extend(transport._preferred_ciphers)
            if hasattr(transport, '_preferred_macs'):
                all_algs.extend(transport._preferred_macs)
            
            # Check for known algorithms that indicate specific versions
            for alg in all_algs:
                if alg in ssh_algorithm_indicators:
                    indicator = ssh_algorithm_indicators[alg]
                    results.append(VersionInfo(
                        version=indicator["version"],
                        confidence=indicator["confidence"],
                        detection_method=f"SSH Algorithm: {alg}",
                        details={
                            "algorithm": alg,
                            "description": indicator["description"]
                        }
                    ))
            
            # Check RSA key size if RSA key is used
            if key_types == "ssh-rsa" and hasattr(transport, 'get_remote_server_key'):
                key = transport.get_remote_server_key()
                if hasattr(key, 'key') and hasattr(key.key, 'n'):
                    key_size = key.key.n.bit_length()
                    if key_size <= 1024:
                        results.append(VersionInfo(
                            version="Likely < 9.x",
                            confidence=0.6,
                            detection_method="SSH RSA Key Size",
                            details={"key_size": key_size}
                        ))
                    elif key_size >= 2048:
                        results.append(VersionInfo(
                            version="Likely ≥ 9.x",
                            confidence=0.6,
                            detection_method="SSH RSA Key Size",
                            details={"key_size": key_size}
                        ))
                        
            # If no modern algorithms found, likely an older version
            if not any(alg in all_algs for alg in ["ssh-ed25519", "ecdsa-sha2-nistp256", "curve25519-sha256"]):
                # Check if algorithms suggest a very old version
                if "diffie-hellman-group1-sha1" in all_algs and not any(modern in all_algs for modern in ["diffie-hellman-group-exchange-sha256"]):
                    results.append(VersionInfo(
                        version="Likely < 9.x",
                        confidence=0.7,
                        detection_method="SSH Algorithm Pattern: Legacy",
                        details={"algorithms": all_algs}
                    ))
                else:
                    results.append(VersionInfo(
                        version="9.x but < 9.16(1)",
                        confidence=0.75,
                        detection_method="SSH Algorithm Pattern: Modern but Pre-ECDSA",
                        details={"algorithms": all_algs}
                    ))
                    
        except Exception as e:
            logger.debug(f"SSH detailed fingerprinting error: {e}")
            
        finally:
            transport.close()
            
    except Exception as e:
        logger.debug(f"SSH connection error: {e}")
        
    return results

def detect_ike_vpn(target: str, port: int = 500, timeout: int = 5) -> List[VersionInfo]:
    """
    Detect IKE/VPN capabilities to infer ASA version.
    IKEv2 support was added in ASA 8.4(1).
    
    This function sends IKE requests to determine version based on responses.
    """
    results = []  # Initialize results as an empty list
    
    # Function to create a basic IKEv1 packet
    def create_ikev1_packet():
        # IKEv1 Main Mode packet with standard proposals
        # Headers (ISAKMP)
        init_cookie = os.urandom(8)  # Random initiator cookie
        resp_cookie = b'\x00' * 8    # Responder cookie is all zeros in initial packet
        version = b'\x10'            # IKEv1 version 1.0
        exchange_type = b'\x02'      # Main Mode
        flags = b'\x00'              # No flags
        message_id = b'\x00' * 4     # Message ID is zero for first exchange
        length = b'\x00\x00\x00\x5c' # Total length - will be set later
        
        # Security Association payload
        next_payload = b'\x01'       # Next payload is SA
        reserved = b'\x00'           # Reserved byte
        payload_length = b'\x00\x38' # Payload length for SA
        doi = b'\x00\x00\x00\x01'    # Domain of Interpretation: IPSEC
        situation = b'\x00\x00\x00\x01' # Situation: Identity
        
        # Proposal payload
        prop_next_payload = b'\x00'  # No more payloads
        prop_reserved = b'\x00'      # Reserved
        prop_payload_length = b'\x00\x30' # Proposal payload length
        proposal_num = b'\x01'       # Proposal number
        protocol_id = b'\x01'        # Protocol ID: ISAKMP
        spi_size = b'\x00'           # SPI size is 0 for initial exchange
        num_transforms = b'\x01'     # Number of transforms
        
        # Transform payload
        trans_next_payload = b'\x00' # No more transforms
        trans_reserved = b'\x00'     # Reserved
        trans_payload_length = b'\x00\x24' # Transform payload length
        transform_num = b'\x01'      # Transform number
        transform_id = b'\x01'       # Transform ID: 3DES
        trans_reserved2 = b'\x00\x00'# Reserved
        
        # Attributes (encryption, hash, auth, DH group, lifetime)
        # Using common values that most Cisco ASAs would recognize
        attributes = (
            b'\x80\x01\x00\x07'      # Encryption: 3DES
            b'\x80\x02\x00\x02'      # Hash: SHA
            b'\x80\x03\x00\x01'      # Auth: Pre-shared key
            b'\x80\x04\x00\x02'      # Group: 2 (1024-bit MODP)
            b'\x80\x0b\x00\x01'      # Life type: seconds
            b'\x00\x0c\x00\x04\x00\x00\x70\x80' # Life duration: 28800s
        )
        
        # Assemble the packet
        packet = (
            init_cookie + resp_cookie + version + exchange_type + flags +
            message_id + length + next_payload + reserved + payload_length +
            doi + situation + prop_next_payload + prop_reserved +
            prop_payload_length + proposal_num + protocol_id + spi_size +
            num_transforms + trans_next_payload + trans_reserved +
            trans_payload_length + transform_num + transform_id +
            trans_reserved2 + attributes
        )
        
        # Update the length field with actual length
        actual_length = len(packet)
        packet = packet[:16] + struct.pack("!I", actual_length) + packet[20:]
        
        return packet
    
    # Function to create a basic IKEv2 packet
    def create_ikev2_packet():
        # IKEv2 Init request with standard proposals
        # IKE_SA_INIT packet
        init_cookie = os.urandom(8)   # Random initiator cookie
        resp_cookie = b'\x00' * 8     # Responder cookie is all zeros
        next_payload = b'\x22'        # Security Association payload
        version = b'\x20'             # Version 2.0
        exchange_type = b'\x22'       # IKE_SA_INIT
        flags = b'\x08'               # Initiator flag
        message_id = b'\x00\x00\x00\x00'  # First message
        length = b'\x00\x00\x00\x5c'  # Placeholder for length
        
        # Security Association payload
        sa_next_payload = b'\x28'     # Key Exchange payload follows
        sa_critical = b'\x00'         # Not critical
        sa_payload_length = b'\x00\x28'  # SA payload length
        
        # Proposal
        prop_next_payload = b'\x00'   # No more proposals
        prop_critical = b'\x00'       # Not critical
        prop_payload_length = b'\x00\x24'  # Proposal length
        proposal_num = b'\x01'        # Proposal number
        protocol_id = b'\x01'         # IKE protocol
        spi_size = b'\x00'            # No SPI yet
        num_transforms = b'\x03'      # 3 transforms
        
        # Transforms
        # Encryption: AES-CBC
        trans1_next_payload = b'\x03'  # Another transform follows
        trans1_critical = b'\x00'      # Not critical
        trans1_payload_length = b'\x00\x0c'  # Transform length
        trans1_type = b'\x01'          # Encryption algorithm
        trans1_reserved = b'\x00'      # Reserved
        trans1_transform_id = b'\x00\x0c'  # AES-CBC (12)
        trans1_attributes = b'\x80\x0e\x00\x80'  # Key length: 128 bits
        
        # Integrity: HMAC-SHA1-96
        trans2_next_payload = b'\x03'  # Another transform follows
        trans2_critical = b'\x00'      # Not critical
        trans2_payload_length = b'\x00\x08'  # Transform length
        trans2_type = b'\x03'          # Integrity algorithm
        trans2_reserved = b'\x00'      # Reserved
        trans2_transform_id = b'\x00\x02'  # HMAC-SHA1-96 (2)
        
        # DH Group: 2 (1024-bit MODP)
        trans3_next_payload = b'\x00'  # No more transforms
        trans3_critical = b'\x00'      # Not critical
        trans3_payload_length = b'\x00\x08'  # Transform length
        trans3_type = b'\x04'          # DH Group
        trans3_reserved = b'\x00'      # Reserved
        trans3_transform_id = b'\x00\x02'  # Group 2 (2)
        
        # Key Exchange payload
        ke_next_payload = b'\x29'      # Nonce payload follows
        ke_critical = b'\x00'          # Not critical
        ke_payload_length = b'\x00\x84'  # KE payload length
        ke_dh_group = b'\x00\x02'      # DH Group 2
        ke_reserved = b'\x00\x00'      # Reserved
        ke_key_data = os.urandom(128)  # Random DH public key (128 bytes)
        
        # Nonce payload
        nonce_next_payload = b'\x00'   # No more payloads
        nonce_critical = b'\x00'       # Not critical
        nonce_payload_length = b'\x00\x1c'  # Nonce payload length
        nonce_data = os.urandom(16)    # Random nonce (16 bytes)
        
        # Build the transforms
        transform1 = (
            trans1_next_payload + trans1_critical + trans1_payload_length +
            trans1_type + trans1_reserved + trans1_transform_id + trans1_attributes
        )
        
        transform2 = (
            trans2_next_payload + trans2_critical + trans2_payload_length +
            trans2_type + trans2_reserved + trans2_transform_id
        )
        
        transform3 = (
            trans3_next_payload + trans3_critical + trans3_payload_length +
            trans3_type + trans3_reserved + trans3_transform_id
        )
        
        # Build the proposal
        proposal = (
            prop_next_payload + prop_critical + prop_payload_length +
            proposal_num + protocol_id + spi_size + num_transforms +
            transform1 + transform2 + transform3
        )
        
        # Build the SA payload
        sa_payload = (
            sa_next_payload + sa_critical + sa_payload_length + proposal
        )
        
        # Build the KE payload
        ke_payload = (
            ke_next_payload + ke_critical + ke_payload_length +
            ke_dh_group + ke_reserved + ke_key_data
        )
        
        # Build the Nonce payload
        nonce_payload = (
            nonce_next_payload + nonce_critical + nonce_payload_length +
            nonce_data
        )
        
        # Assemble the packet
        packet = (
            init_cookie + resp_cookie + next_payload + version +
            exchange_type + flags + message_id + length +
            sa_payload + ke_payload + nonce_payload
        )
        
        # Update the length field with actual length
        actual_length = len(packet)
        packet = packet[:16] + struct.pack("!I", actual_length) + packet[20:]
        
        return packet
    
    try:
        # First, check if IKEv2 is supported (ASA 8.4+)
        ikev2_response = False
        
        # Create and send IKEv2 packet
        sock_v2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_v2.settimeout(timeout)
        
        try:
            ikev2_packet = create_ikev2_packet()
            sock_v2.sendto(ikev2_packet, (target, port))
            
            # Try to receive a response
            response, addr = sock_v2.recvfrom(2048)
            
            # If we got a response, IKEv2 is supported
            if response and len(response) > 0:
                ikev2_response = True
                # Check if it's a valid IKEv2 response (should have the same initiator cookie)
                if len(response) >= 8 and response[0:8] == ikev2_packet[0:8]:
                    results.append(VersionInfo(
                        version="≥ 8.4(1)",
                        confidence=0.85,
                        detection_method="IKE Version Support: IKEv2",
                        details={"ike_version": "v2", "response_length": len(response)}
                    ))
                    
                    # Parse vendor IDs if present (could contain more version clues)
                    if len(response) > 40:  # Minimum size to contain headers + vendor ID
                        # Simplified parsing - in a real implementation, you'd need to walk through all payloads
                        vendor_id_found = False
                        for i in range(28, len(response) - 16):
                            # Look for known Cisco vendor ID patterns
                            if response[i:i+9] == b'Cisco VPN':
                                vendor_id_found = True
                                vendor_id = response[i:i+16].hex()
                                results.append(VersionInfo(
                                    version="Cisco ASA (VPN enabled)",
                                    confidence=0.9,
                                    detection_method="IKE Vendor ID",
                                    details={"vendor_id": vendor_id}
                                ))
                                break
                        
                        if not vendor_id_found:
                            # Generic IKEv2 support without specific Cisco ID
                            results.append(VersionInfo(
                                version="≥ 8.4(1) (IKEv2 supported)",
                                confidence=0.8,
                                detection_method="IKE Version: IKEv2 Generic",
                                details={}
                            ))
        except Exception as e:
            logger.debug(f"IKEv2 detection error: {e}")
        finally:
            sock_v2.close()
        
        # If IKEv2 is not supported, try IKEv1 (could be pre-8.4 ASA)
        if not ikev2_response:
            sock_v1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_v1.settimeout(timeout)
            
            try:
                ikev1_packet = create_ikev1_packet()
                sock_v1.sendto(ikev1_packet, (target, port))
                
                # Try to receive a response
                response, addr = sock_v1.recvfrom(2048)
                
                # If we got a response, IKEv1 is supported
                if response and len(response) > 0:
                    # Check if it's a valid IKEv1 response (should have the same initiator cookie)
                    if len(response) >= 8 and response[0:8] == ikev1_packet[0:8]:
                        # If IKEv1 is supported but IKEv2 isn't, this suggests pre-8.4
                        results.append(VersionInfo(
                            version="< 8.4(1)",
                            confidence=0.8,
                            detection_method="IKE Version Support: IKEv1 only",
                            details={"ike_version": "v1", "response_length": len(response)}
                        ))
                        
                        # Check for Cisco Unity vendor ID which indicates ASA or PIX
                        cisco_unity_found = False
                        for i in range(28, len(response) - 16):
                            # The exact pattern might vary; this is a simplified check
                            if b'Cisco Unity' in response[i:i+16]:
                                cisco_unity_found = True
                                results.append(VersionInfo(
                                    version="Cisco ASA (Unity VPN)",
                                    confidence=0.85,
                                    detection_method="IKE Vendor ID: Cisco Unity",
                                    details={}
                                ))
                                break
                        
                        if not cisco_unity_found:
                            # Generic IKEv1 support without specific Cisco ID
                            results.append(VersionInfo(
                                version="< 8.4(1) (IKEv1 only)",
                                confidence=0.75,
                                detection_method="IKE Version: IKEv1 Generic",
                                details={}
                            ))
            except socket.timeout:
                # No response might mean IKE/VPN is not enabled
                pass
            except Exception as e:
                logger.debug(f"IKEv1 detection error: {e}")
            finally:
                sock_v1.close()
                
        # If neither IKEv1 nor IKEv2 response, VPN might not be enabled
        if not results:
            logger.debug(f"No IKE response from {target}:{port}, VPN might not be enabled")
    
    except Exception as e:
        logger.debug(f"IKE VPN detection error: {e}")
    return results 

# HTTP analysis methods
def get_http_version(target: str, port: int, timeout: int = 10, paths: List[str] = None) -> List[VersionInfo]:
    """
    Analyze HTTP/HTTPS interfaces for version information using multiple techniques:
    1. HTTP header analysis
    2. Known endpoint responses
    3. HTML content regex matching
    4. JavaScript version parameters

    Args:
        target (str): Target hostname or IP address.
        port (int): Port to connect to (e.g., 443 for HTTPS).
        timeout (int): Request timeout in seconds.
        paths (List[str]): List of paths to test; defaults to common Cisco ASA paths.

    Returns:
        List[VersionInfo]: List of detected version information with confidence scores.
    """
    if paths is None:
        paths = ['/', '/admin/', '/+CSCOE+/logon.html', '/admin/public/index.html']
    
    results = []
    db = load_fingerprint_database()
    
    for path in paths:
        url = f"https://{target}:{port}{path}"
        try:
            response = requests.get(
                url,
                verify=False,  # Ignore SSL verification for testing
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Analyze HTTP Headers
            for header, patterns in db["http_headers"].items():
                if header in response.headers:
                    header_value = response.headers[header]
                    for pattern, info in patterns.items():
                        if pattern in header_value:
                            for version in info["versions"]:
                                results.append(VersionInfo(
                                    version=version,
                                    confidence=info["confidence"],
                                    detection_method=f"HTTP Header: {header}",
                                    details={"header": header, "value": header_value}
                                ))
            
            # Check known API endpoints
            if path in db["api_endpoints"]:
                endpoint_info = db["api_endpoints"][path]
                if response.status_code in endpoint_info["status_codes"]:
                    for version in endpoint_info["status_codes"][response.status_code]:
                        results.append(VersionInfo(
                            version=version,
                            confidence=endpoint_info["confidence"],
                            detection_method=f"API endpoint: {path}",
                            details={"status_code": response.status_code}
                        ))
            
            if response.status_code != 200:
                continue
                
            html = response.text
            
            # Regex matching in HTML content
            for pattern_info in db["http_patterns"]:
                pattern = pattern_info["pattern"]
                matches = re.findall(pattern, html)
                for match in matches:
                    results.append(VersionInfo(
                        version=match,
                        confidence=pattern_info["confidence"],
                        detection_method="HTML Regex",
                        details={"pattern": pattern, "url": url}
                    ))
            
            # Check JavaScript files for version info
            soup = BeautifulSoup(html, 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                version_match = re.search(r'version=([\d\.]+)', src)
                if version_match:
                    results.append(VersionInfo(
                        version=version_match.group(1),
                        confidence=0.7,
                        detection_method="JavaScript Version Parameter",
                        details={"script_src": src}
                    ))
            
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to {url}: {e}")
            continue
    
    return results

# SSH banner grabbing
def get_ssh_version(target: str, port: int = 22, timeout: int = 5) -> List[VersionInfo]:
    """Grab SSH banner and match against known Cisco ASA SSH banner patterns."""
    results = []
    
    # Load fingerprint database
    db = load_fingerprint_database()
    
    try:
        # First try simple socket connection to grab banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Check if banner matches known patterns
        for known_banner, info in db["ssh_banners"].items():
            if known_banner in banner:
                for version in info["versions"]:
                    results.append(VersionInfo(
                        version=version,
                        confidence=info["confidence"],
                        detection_method="SSH Banner Grab",
                        details={"banner": banner}
                    ))
        
        # If no match found but banner contains "Cisco", record with lower confidence
        if "Cisco" in banner and not results:
            results.append(VersionInfo(
                version="Unknown (Cisco device detected)",
                confidence=0.4,
                detection_method="SSH Banner Grab",
                details={"banner": banner}
            ))
            
        # Try more advanced SSH connection with paramiko
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with timeout but don't authenticate
            client.connect(
                hostname=target,
                port=port,
                username="invalid_user",
                password="invalid_password",
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
        except paramiko.ssh_exception.AuthenticationException:
            # Authentication failed but we got the banner - good
            transport = client.get_transport()
            if transport:
                server_banner = transport.remote_version
                
                # Check if banner matches known patterns
                for known_banner, info in db["ssh_banners"].items():
                    if known_banner in server_banner:
                        for version in info["versions"]:
                            results.append(VersionInfo(
                                version=version,
                                confidence=info["confidence"] + 0.1,  # Higher confidence with paramiko
                                detection_method="SSH Paramiko Banner",
                                details={"banner": server_banner}
                            ))
        except Exception as e:
            logger.debug(f"Paramiko SSH connection error: {e}")
        finally:
            client.close()
            
    except Exception as e:
        logger.debug(f"SSH connection error to {target}:{port}: {e}")
    
    return results

# SNMP polling
def get_snmp_version(target: str, community: str = 'public', port: int = 161, timeout: int = 2) -> List[VersionInfo]:
    """
    Poll SNMP information to identify Cisco ASA devices and versions.
    Uses common OIDs for Cisco device identification.
    """
    results = []
    
    # Load fingerprint database
    db = load_fingerprint_database()
    
    # Key OIDs for Cisco ASA device detection
    oids_to_check = [
        # System description
        '1.3.6.1.2.1.1.1.0',  
        # System name
        '1.3.6.1.2.1.1.5.0',  
        # Cisco specific device OIDs
        '1.3.6.1.2.1.47.1.1.1.1.13.1',  # Version info
        '1.3.6.1.4.1.9.9.221.1.1.1.1.3.7'  # ASA-specific OID
    ]
    
    for oid in oids_to_check:
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),  # SNMPv1
                    UdpTransportTarget((target, port), timeout=timeout, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
            )
            
            if errorIndication:
                logger.debug(f"SNMP error: {errorIndication}")
                continue
            
            if errorStatus:
                logger.debug(f"SNMP error: {errorStatus}")
                continue
                
            for varBind in varBinds:
                oid_str = str(varBind[0])
                value_str = str(varBind[1])
                
                # Check if this OID is in our fingerprint database
                if oid_str in db["snmp_oids"]:
                    oid_info = db["snmp_oids"][oid_str]
                    
                    # Check for version information in the value
                    version_match = re.search(r'Version\s+([\d\.\(\)]+)', value_str)
                    if version_match:
                        results.append(VersionInfo(
                            version=version_match.group(1),
                            confidence=oid_info["confidence"],
                            detection_method="SNMP OID",
                            details={"oid": oid_str, "value": value_str}
                        ))
                    elif "name" in oid_info:
                        # Device model identification
                        results.append(VersionInfo(
                            version=f"Unknown ({oid_info['name']} detected)",
                            confidence=oid_info["confidence"] - 0.3,  # Lower confidence as it's just the model
                            detection_method="SNMP Device ID",
                            details={"oid": oid_str, "device": oid_info["name"]}
                        ))
                
                # Check for Cisco ASA version patterns in any value
                version_match = re.search(r'(?i)Cisco Adaptive Security Appliance.*?Version\s*([\d\(\)\.\w-]+)', value_str)
                if version_match:
                    results.append(VersionInfo(
                        version=version_match.group(1),
                        confidence=0.9,  # High confidence for direct version match
                        detection_method="SNMP Version String",
                        details={"oid": oid_str, "value": value_str}
                    ))
                
                # Look for ASA model indicators
                if "ASA" in value_str and "Cisco" in value_str:
                    model_match = re.search(r'ASA\s*(\d+)', value_str)
                    if model_match:
                        model = model_match.group(0)
                        results.append(VersionInfo(
                            version=f"Unknown ({model} detected)",
                            confidence=0.5,  # Medium confidence for model only
                            detection_method="SNMP Model",
                            details={"oid": oid_str, "model": model}
                        ))
                        
        except Exception as e:
            logger.debug(f"SNMP error for OID {oid}: {e}")
            
    return results

# TLS/SSL fingerprinting
def get_tls_fingerprint(target: str, port: int = 443, timeout: int = 5) -> List[VersionInfo]:
    """
    Analyze TLS/SSL certificates and cipher suites to fingerprint the Cisco ASA version.
    Different ASA versions support different cipher suites and have specific certificate characteristics.
    """
    results = []
    
    # Load fingerprint database
    db = load_fingerprint_database()
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                # Get certificate
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    return results
                
                # Parse certificate
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Get cipher suite
                cipher = ssock.cipher()
                
                # Fingerprint the certificate
                cert_fingerprint = cert.fingerprint(hashlib.sha256).hex()
                
                # Check if fingerprint matches known ASA versions
                if cert_fingerprint in db["tls_fingerprints"]:
                    fingerprint_info = db["tls_fingerprints"][cert_fingerprint]
                    for version in fingerprint_info["versions"]:
                        results.append(VersionInfo(
                            version=version,
                            confidence=fingerprint_info["confidence"],
                            detection_method="TLS Certificate Fingerprint",
                            details={"fingerprint": cert_fingerprint}
                        ))
                
                # Look for Cisco indicators in the certificate
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                
                if "Cisco" in subject or "Cisco" in issuer:
                    # Extract serial number as additional fingerprint
                    serial = cert.serial_number
                    
                    # Look for version info in certificate fields
                    for field in [subject, issuer]:
                        version_match = re.search(r'(?i)Version[=:]\s*([\d\.\(\)]+)', field)
                        if version_match:
                            results.append(VersionInfo(
                                version=version_match.group(1),
                                confidence=0.7,
                                detection_method="TLS Certificate Field",
                                details={"field": field}
                            ))
                    
                    # If we identified it's Cisco but no specific version
                    if not results:
                        results.append(VersionInfo(
                            version="Unknown (Cisco certificate)",
                            confidence=0.4,
                            detection_method="TLS Certificate Brand",
                            details={"subject": subject, "issuer": issuer}
                        ))
                
                # Analyze supported cipher suites (would require multiple connections with different offers)
                # This is a simplified version
                cipher_name = cipher[0]
                if "DHE-RSA" in cipher_name and "AES256" in cipher_name:
                    # More recent ASA versions prefer these ciphers
                    results.append(VersionInfo(
                        version="9.x (based on cipher preference)",
                        confidence=0.3,
                        detection_method="TLS Cipher Suite",
                        details={"cipher": cipher_name}
                    ))
                elif "RC4" in cipher_name:
                    # Older ASA versions might still use RC4
                    results.append(VersionInfo(
                        version="8.x (based on cipher preference)",
                        confidence=0.3,
                        detection_method="TLS Cipher Suite",
                        details={"cipher": cipher_name}
                    ))
    
    except ssl.SSLError as e:
        logger.debug(f"SSL error: {e}")
    except socket.error as e:
        logger.debug(f"Socket error: {e}")
    except Exception as e:
        logger.debug(f"TLS fingerprinting error: {e}")
    
    return results

# Behavioral fingerprinting
def behavioral_fingerprinting(target: str, port: int = 443, timeout: int = 5) -> List[VersionInfo]:
    """
    Use behavioral differences between ASA versions to identify the version.
    This includes:
    1. Testing specific API endpoints
    2. Analyzing response timing
    3. Checking for version-specific header ordering
    """
    results = []
    
    # Test paths that behave differently in different ASA versions
    test_paths = [
        '/+CSCOE+/logon.html',
        '/+CSCOE+/null.html',
        '/admin/public/index.html',
        '/CSCOSW/logon.html',
        '/cgi-bin/welcome.pl',
        '/sslvpn/portal.html'
    ]
    
    # Expected response codes or content for specific versions
    version_behaviors = {
        # Example: path: {status_code: version, ...}
        '/+CSCOE+/logon.html': {
            200: "8.x or 9.x with AnyConnect",
            302: "9.x with redirect configured",
            404: "Pre-8.0 or no AnyConnect"
        },
        '/+CSCOE+/null.html': {
            200: "8.0 - 9.6",
            404: "9.7+"
        }
    }
    
    # Test response timing (some versions have specific timing characteristics)
    timing_markers = {}
    
    for path in test_paths:
        url = f"https://{target}:{port}{path}"
        try:
            start_time = time.time()
            response = requests.get(
                url, 
                verify=False, 
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            response_time = time.time() - start_time
            
            timing_markers[path] = response_time
            
            # Check if this path and status code combination indicates a specific version
            if path in version_behaviors and response.status_code in version_behaviors[path]:
                version_indicator = version_behaviors[path][response.status_code]
                results.append(VersionInfo(
                    version=version_indicator,
                    confidence=0.6,  # Medium confidence
                    detection_method="Behavioral Response",
                    details={"path": path, "status": response.status_code}
                ))
            
            # Check for specific headers ordering
            if response.status_code == 200 or response.status_code == 302:
                headers = list(response.headers.keys())
                headers_str = ','.join(headers)
                
                # Specific header patterns for different versions
                if 'Set-Cookie' in headers and 'Content-Type' in headers:
                    idx_cookie = headers.index('Set-Cookie')
                    idx_content = headers.index('Content-Type')
                    
                    if idx_cookie < idx_content:
                        # Some versions have a specific header ordering
                        results.append(VersionInfo(
                            version="8.x-9.1 (header ordering)",
                            confidence=0.3,
                            detection_method="Header Ordering",
                            details={"headers": headers_str}
                        ))
                
                # Look for specific cookie attributes
                if 'Set-Cookie' in response.headers:
                    cookie = response.headers['Set-Cookie']
                    if 'webvpn' in cookie and 'secure' in cookie.lower():
                        results.append(VersionInfo(
                            version="9.x with AnyConnect",
                            confidence=0.5,
                            detection_method="Cookie Attribute",
                            details={"cookie": cookie}
                        ))
        
        except requests.exceptions.RequestException:
            continue
    
    # Analyze timing patterns
    if len(timing_markers) >= 2:
        # Calculate timing ratios between different endpoints
        # Some ASA versions have consistent timing differences between endpoints
        timing_analysis = {}
        paths = list(timing_markers.keys())
        
        for i in range(len(paths)):
            for j in range(i+1, len(paths)):
                if timing_markers[paths[i]] > 0 and timing_markers[paths[j]] > 0:
                    ratio = timing_markers[paths[i]] / timing_markers[paths[j]]
                    timing_analysis[f"{paths[i]}-{paths[j]}"] = ratio
        
        # Example timing pattern for version detection
        # This would need to be calibrated with real-world data
        for pattern, ratio in timing_analysis.items():
            if 1.9 <= ratio <= 2.1:
                results.append(VersionInfo(
                    version="9.1-9.3 (timing pattern)",
                    confidence=0.3,
                    detection_method="Response Timing",
                    details={"pattern": pattern, "ratio": ratio}
                ))
    
    return results

# Combine all detection methods with confidence scoring
"""
This patch fixes the function argument mismatch in the Cisco ASA Version Detector.
The problem is that when we updated the function signature of detect_asa_version()
to include the use_vuln_probes parameter, we need to ensure all function
definitions match.

Here's the correct function signature for the detect_asa_version function:
"""

def probe_version_specific_vulnerabilities(target: str, port: int = 443, timeout: int = 10) -> List[VersionInfo]:
    """
    Probes for version-specific behaviors, endpoints, and safe vulnerability checks.
    This doesn't exploit vulnerabilities but checks for signatures of specific versions.
    """
    results = []
    
    # Dictionary of version-specific probes
    # Each probe contains a URL path, expected status code(s), and a regex pattern for content
    version_probes = [
        # CVE-2020-3187 - Path traversal in ASA 9.1 - 9.6
        {
            "path": "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
            "versions": ["9.1", "9.2", "9.3", "9.4", "9.5", "9.6"],
            "status_codes": [200],
            "content_pattern": r"INTERNAL_PASSWORD_PROMPT",
            "negative_pattern": r"Error report",
            "confidence": 0.85,
            "name": "CVE-2020-3187 Path Traversal Check"
        },
        # CVE-2020-3452 - Directory traversal in ASA 9.5(1) - 9.12
        {
            "path": "/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua",
            "versions": ["9.5", "9.6", "9.7", "9.8", "9.9", "9.10", "9.11", "9.12"],
            "status_codes": [200],
            "content_pattern": r"INTERNAL_PASSWORD_PROMPT|SESSION_PASSWORD_PROMPT",
            "confidence": 0.85,
            "name": "CVE-2020-3452 Directory Traversal Check"
        },
        # WebVPN customization endpoints - ASA 8.0+
        {
            "path": "/+CSCOE+/customization/custom.css",
            "versions": ["8.0", "8.1", "8.2", "8.3", "8.4", "9.0", "9.1", "9.2"],
            "status_codes": [200],
            "confidence": 0.5,
            "name": "WebVPN Custom CSS Check"
        },
        # AnyConnect download page - ASA 8.0+
        {
            "path": "/+CSCOE+/anyconnect",
            "versions": ["8.0", "8.1", "8.2", "8.3", "8.4", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8"],
            "status_codes": [200],
            "content_pattern": r"AnyConnect|SSLVPN|Cisco Systems",
            "confidence": 0.6,
            "name": "AnyConnect Download Check"
        },
        # ASA 8.2 specific cookie behavior
        {
            "path": "/+CSCOE+/logon.html",
            "versions": ["8.2"],
            "status_codes": [200, 302],
            "cookie_pattern": r"webvpn=",
            "confidence": 0.75,
            "name": "ASA 8.2 Cookie Check"
        },
        # ASA 8.3+ redirect behavior
        {
            "path": "/",
            "versions": ["8.3", "8.4", "9.0", "9.1"],
            "status_codes": [301, 302],
            "header_pattern": r"Location:.*\/\+CSCOE\+\/logon\.html",
            "confidence": 0.6,
            "name": "ASA 8.3+ Redirect Check"
        },
        # ASA 9.1+ REST API
        {
            "path": "/api/",
            "versions": ["9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9", "9.10"],
            "status_codes": [401, 403, 404],  # Still indicates API might exist even with auth error
            "content_pattern": r"REST|API|Unauthorized|Authentication",
            "confidence": 0.7,
            "name": "ASA 9.1+ REST API Check"
        },
        # ASA 9.6+ REST API v2
        {
            "path": "/api/v2/",
            "versions": ["9.6", "9.7", "9.8", "9.9", "9.10"],
            "status_codes": [401, 403, 404],
            "content_pattern": r"REST|API|Unauthorized|Authentication",
            "confidence": 0.75,
            "name": "ASA 9.6+ REST API v2 Check"
        },
        # Version specific error message for 8.x
        {
            "path": "/CSCOE/invalid_endpoint_nonexistent.html",
            "versions": ["8.0", "8.1", "8.2", "8.3", "8.4"],
            "status_codes": [404],
            "content_pattern": r"file cannot be found|Error report|404",
            "confidence": 0.6,
            "name": "ASA 8.x Error Message Check"
        },
        # Version specific error message for 9.x
        {
            "path": "/CSCOE/invalid_endpoint_nonexistent.html",
            "versions": ["9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9", "9.10"],
            "status_codes": [404],
            "content_pattern": r"Error|404|Not Found",
            "confidence": 0.6,
            "name": "ASA 9.x Error Message Check"
        },
        # Specific to ASA 9.1(1) - distinct HTML layout
        {
            "path": "/+CSCOE+/logon.html",
            "versions": ["9.1(1)"],
            "status_codes": [200],
            "content_pattern": r"<div\s+id=\"(main_content_gray|login_form_table)\"",
            "confidence": 0.8,
            "name": "ASA 9.1(1) HTML Layout Check"
        },
        # CVE-2018-0296 - Directory listing in ASA 9.x
        {
            "path": "/%2bCSCOE%2b/session/0/../../../logo.gif",
            "versions": ["9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9"],
            "status_codes": [200],
            "content_pattern": r"GIF|image",
            "confidence": 0.8,
            "name": "CVE-2018-0296 Directory Traversal Check"
        },
        # Check for specific behavior in ASA 9.4(x)
        {
            "path": "/+CSCOE+/session_password.html",
            "versions": ["9.4"],
            "status_codes": [200, 302],
            "content_pattern": r"login_secondary|session_password",
            "confidence": 0.7,
            "name": "ASA 9.4 Session Password Check"
        }
    ]
    
    # Loop through each probe
    for probe in version_probes:
        url = f"https://{target}:{port}{probe['path']}"
        try:
            response = requests.get(
                url,
                verify=False,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=False  # Don't follow redirects to check redirect behavior
            )
            
            logger.debug(f"Probe {probe['name']} received status {response.status_code}")
            
            # Check if status code matches expected
            status_match = response.status_code in probe["status_codes"]
            
            # Check content pattern if specified
            content_match = True
            if "content_pattern" in probe and status_match:
                content_match = bool(re.search(probe["content_pattern"], response.text))
            
            # Check for negative pattern (pattern that should NOT be present)
            negative_match = False
            if "negative_pattern" in probe and status_match:
                negative_match = bool(re.search(probe["negative_pattern"], response.text))
            
            # Check cookie pattern if specified
            cookie_match = True
            if "cookie_pattern" in probe:
                if "Set-Cookie" in response.headers:
                    cookie_match = bool(re.search(probe["cookie_pattern"], response.headers["Set-Cookie"]))
                else:
                    cookie_match = False
            
            # Check header pattern if specified
            header_match = True
            if "header_pattern" in probe:
                header_str = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
                header_match = bool(re.search(probe["header_pattern"], header_str))
            
            # Determine if this probe matched the target
            probe_match = status_match and content_match and (not negative_match) and cookie_match and header_match
            
            if probe_match:
                logger.debug(f"Probe matched: {probe['name']}")
                
                # Add a result for each potential version
                for version in probe["versions"]:
                    results.append(VersionInfo(
                        version=version,
                        confidence=probe["confidence"],
                        detection_method=f"Vulnerability Probe: {probe['name']}",
                        details={
                            "url": url,
                            "status": response.status_code,
                            "probe": probe["name"]
                        }
                    ))
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error with probe {probe['name']} to {url}: {e}")
            continue
    
    return results


def detect_asa_version(
    target: str, 
    http_port: int = 443, 
    ssh_port: int = 22, 
    snmp_port: int = 161,
    community: str = 'public',
    timeout: int = 10,
    use_all_methods: bool = True,
    use_vuln_probes: bool = True,
    use_advanced_probes: bool = True  # New parameter for the advanced detection methods
) -> Dict[str, Any]:
    """
    Combines all detection methods, correlation of results, and confidence scoring
    to provide the most accurate Cisco ASA version detection.
    """
    all_results = []
    detection_methods = []
    
    with ThreadPoolExecutor(max_workers=9) as executor:  # Increased worker count for new methods
        future_http = executor.submit(get_http_version, target, http_port, timeout)
        detection_methods.append("HTTP")
        
        future_ssh = future_tls = future_snmp = future_behavioral = future_vuln = None
        future_tls_version = future_ssh_enhanced = future_ike = None  # New futures
        
        if use_all_methods:
            future_ssh = executor.submit(get_ssh_version, target, ssh_port, timeout)
            future_tls = executor.submit(get_tls_fingerprint, target, http_port, timeout)
            future_snmp = executor.submit(get_snmp_version, target, community, snmp_port, timeout)
            future_behavioral = executor.submit(behavioral_fingerprinting, target, http_port, timeout)
            
            detection_methods.extend(["SSH", "TLS", "SNMP", "Behavioral"])
        
        if use_vuln_probes:
            future_vuln = executor.submit(probe_version_specific_vulnerabilities, target, http_port, timeout)
            detection_methods.append("Vulnerability Probes")
            
        if use_advanced_probes:
            future_tls_version = executor.submit(detect_tls_versions, target, http_port, timeout)
            future_ssh_enhanced = executor.submit(enhanced_ssh_fingerprinting, target, ssh_port, timeout)
            future_ike = executor.submit(detect_ike_vpn, target, 500, timeout)
            
            detection_methods.extend(["TLS Version Detection", "SSH Enhanced", "IKE/VPN Detection"])
        
        # Collect results from all methods
        http_results = future_http.result()
        all_results.extend(http_results)
        
        if use_all_methods:
            all_results.extend(future_ssh.result())
            all_results.extend(future_tls.result())
            all_results.extend(future_snmp.result())
            all_results.extend(future_behavioral.result())
            
        if use_vuln_probes and future_vuln:
            all_results.extend(future_vuln.result())
            
        if use_advanced_probes:
            if future_tls_version:
                all_results.extend(future_tls_version.result())
            if future_ssh_enhanced:
                all_results.extend(future_ssh_enhanced.result())
            if future_ike:
                all_results.extend(future_ike.result())
    
    # Process and correlate results
    version_confidence = {}
    method_results = {}
    
    # Group by detection method
    for result in all_results:
        method = result.detection_method.split(':')[0].strip()
        if method not in method_results:
            method_results[method] = []
        method_results[method].append(result)
    
    # Combine and weight results
    for result in all_results:
        version = result.version
        
        # Skip low-confidence "Unknown" versions if we have specific versions
        if "Unknown" in version and any(r for r in all_results if "Unknown" not in r.version):
            continue
            
        # Initialize if this is a new version
        if version not in version_confidence:
            version_confidence[version] = {
                "confidence": 0,
                "weight_sum": 0,
                "methods": set(),
                "details": []
            }
        
        # Add this result's confidence, weighted by detection method
        method_weight = 1.0
        
        # Prioritize methods that directly provide version info
        if "HTML" in result.detection_method or "SNMP Version" in result.detection_method:
            method_weight = 1.2
        elif "Vulnerability Probe" in result.detection_method:
            method_weight = 1.3  # Higher weight for vulnerability probes
        elif "TLS Version Support" in result.detection_method:
            method_weight = 1.4  # Higher weight for TLS version detection
        elif "IKE Version Support" in result.detection_method:
            method_weight = 1.35  # Higher weight for IKE version detection
        elif "SSH Algorithm" in result.detection_method:
            method_weight = 1.25  # Higher weight for SSH algorithm detection
        elif "TLS" in result.detection_method:
            method_weight = 0.8
        elif "Behavioral" in result.detection_method:
            method_weight = 0.7
            
        # Apply weighted confidence
        weighted_conf = result.confidence * method_weight
        version_confidence[version]["confidence"] += weighted_conf
        version_confidence[version]["weight_sum"] += method_weight
        version_confidence[version]["methods"].add(result.detection_method)
        version_confidence[version]["details"].append({
            "method": result.detection_method,
            "confidence": result.confidence,
            "weighted_confidence": weighted_conf,
            "details": result.details
        })
    
    # Normalize confidence scores
    for version, data in version_confidence.items():
        if data["weight_sum"] > 0:
            data["confidence"] = data["confidence"] / data["weight_sum"]
            
            # Boost confidence if multiple detection methods agree
            method_count = len(data["methods"])
            if method_count >= 3:
                data["confidence"] = min(0.99, data["confidence"] * 1.2)
            elif method_count >= 2:
                data["confidence"] = min(0.95, data["confidence"] * 1.1)
    
    # Sort versions by confidence
    sorted_versions = sorted(
        version_confidence.items(), 
        key=lambda x: x[1]["confidence"], 
        reverse=True
    )
    
    # Prepare final result
    result = {
        "target": target,
        "detection_methods_used": detection_methods,
        "versions": [],
        "most_likely_version": None,
        "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # Add versions to result
    for version, data in sorted_versions:
        version_data = {
            "version": version,
            "confidence": data["confidence"],
            "detection_methods": list(data["methods"]),
        }
        result["versions"].append(version_data)
    
    # Set most likely version
    if result["versions"]:
        result["most_likely_version"] = result["versions"][0]["version"]
        result["confidence_score"] = result["versions"][0]["confidence"]
    
    return result

def print_results(results: Dict[str, Any]) -> None:
    """Pretty print the detection results."""
    print("\n" + "=" * 60)
    print(f"Cisco ASA Version Detection Results for {results['target']}")
    print("=" * 60)
    
    if not results["versions"]:
        print("No Cisco ASA version information detected.")
        return
    
    print(f"\nMost Likely Version: {results['most_likely_version']}")
    print(f"Confidence Score: {results['confidence_score']:.2f}")
    print(f"\nDetection methods used: {', '.join(results['detection_methods_used'])}")
    print("\nAll Detected Versions (ordered by confidence):")
    print("-" * 60)
    
    for i, version_data in enumerate(results["versions"], 1):
        print(f"{i}. Version: {version_data['version']}")
        print(f"   Confidence: {version_data['confidence']:.2f}")
        print(f"   Detection Methods: {', '.join(version_data['detection_methods'])}")
        print()
    
    print(f"Detection completed at: {results['detection_time']}")
    print("=" * 60 + "\n")

def main():
    """
    Main function to parse arguments and run the ASA detection.
    """
    parser = argparse.ArgumentParser(
        description="Advanced Cisco ASA Version Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic detection (HTTP only)
  %(prog)s 192.168.1.1
  
  # Use all detection methods
  %(prog)s 192.168.1.1 --all
  
  # Specify custom ports
  %(prog)s 192.168.1.1 --http-port 8443 --ssh-port 2222 --snmp-port 161
  
  # Try SNMP with a different community string
  %(prog)s 192.168.1.1 --all --community private
  
  # Increase detection timeout
  %(prog)s 192.168.1.1 --all --timeout 15
  
  # Output results to JSON file
  %(prog)s 192.168.1.1 --all --output results.json
"""
    )
    
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--http-port", type=int, default=443, help="HTTP/HTTPS port (default: 443)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--snmp-port", type=int, default=161, help="SNMP port (default: 161)")
    parser.add_argument("--all", action="store_true", help="Use all detection methods (slower but more accurate)")
    parser.add_argument("--community", default="public", help="SNMP community string (default: public)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--fingerprint-db", help="Path to custom fingerprint database JSON file")
    parser.add_argument("--no-vuln-probes", action="store_true", help="Disable version-specific vulnerability probing")
    parser.add_argument("--no-advanced-probes", action="store_true", help="Disable advanced detection methods (TLS version, SSH enhanced, IKE)")
    parser.add_argument("--safe-mode", action="store_true", help="Use only the safest detection methods")
    
    args = parser.parse_args()
    
    # Configure logging based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Custom fingerprint database
    if args.fingerprint_db:
        load_fingerprint_database(args.fingerprint_db)
    
    print(f"Starting Cisco ASA version detection for {args.target}...")
    detection_methods = ["HTTP"]
    if args.all:
        detection_methods.extend(["SSH", "SNMP", "TLS", "Behavioral"])
    if not args.no_vuln_probes and not args.safe_mode:
        detection_methods.append("Vulnerability Probes")
    if not args.no_advanced_probes and not args.safe_mode:
        detection_methods.extend(["TLS Version", "SSH Enhanced", "IKE/VPN"])
    
    print(f"Using detection methods: {', '.join(detection_methods)}")
    
    if args.safe_mode:
        print("Running in safe mode: using only passive detection techniques.")
    elif args.no_vuln_probes:
        print("Vulnerability probing disabled.")
    else:
        print("Vulnerability probing enabled (safe checks only, no exploitation).")
    
    try:
        results = detect_asa_version(
            target=args.target,
            http_port=args.http_port,
            ssh_port=args.ssh_port,
            snmp_port=args.snmp_port,
            community=args.community,
            timeout=args.timeout,
            use_all_methods=args.all,
            use_vuln_probes=not args.no_vuln_probes and not args.safe_mode,
            use_advanced_probes=not args.no_advanced_probes and not args.safe_mode
        )
        
        # Print results to console
        print_results(results)
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"Results saved to {args.output}")
            
    except KeyboardInterrupt:
        print("\nDetection cancelled by user.")
    except Exception as e:
        logger.error(f"Error during detection: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
