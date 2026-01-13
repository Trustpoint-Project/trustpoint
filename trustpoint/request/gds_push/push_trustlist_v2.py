"""Push trustlist to OPC UA server using v2 TrustListManager.

This script uses the improved TrustListManager v2 implementation to push
the complete CA chain (root + both intermediate CAs + CRLs) to the server
at 10.100.13.93:48010.

Requirements:
- Server must already trust at least one CA (bootstrap requirement)
- Client certificate signed by trusted CA
- Unencrypted client private key
- Secure connection (SignAndEncrypt mode)
- Authentication credentials (root/secret)
"""

import os
import shutil
import struct
from opcua import Client, ua
from opcua.crypto import security_policies
from trustlist_cert_manager_v2 import TrustListManager

# Server configuration
SERVER_URL = "opc.tcp://10.100.13.93:48010"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.join(SCRIPT_DIR, "ca_workspace")
ACTUAL_CONFIG_DIR = os.path.join(SCRIPT_DIR, "actual_config")


def extract_first_cert_from_chain(cert_data):
    """Extract the first certificate from a DER-encoded certificate chain.
    
    Some OPC UA servers incorrectly send a certificate chain in the endpoint
    metadata when they should only send their own certificate. This function
    extracts just the first certificate from such chains.
    
    Args:
        cert_data: DER-encoded certificate or certificate chain (bytes)
        
    Returns:
        bytes: First certificate only
    """
    # DER format: 0x30 (SEQUENCE) 0x82 [2 bytes length] [certificate data]
    if len(cert_data) > 4 and cert_data[0] == 0x30 and cert_data[1] == 0x82:
        cert_len = struct.unpack('>H', cert_data[2:4])[0]
        first_cert = cert_data[:4 + cert_len]
        
        # If we extracted less than the full data, it was a chain
        if len(first_cert) < len(cert_data):
            print(f"⚠️  Server sent certificate chain ({len(cert_data)} bytes)")
            print(f"   Extracting first certificate ({len(first_cert)} bytes)")
        
        return first_cert
    
    # Not a chain or different DER format, return as-is
    return cert_data


def get_latest_server_cert():
    """Get the server certificate from actual_config directory.
    
    Returns:
        str: Path to the server certificate (uaservercpp.der), or None if not found
    """
    # Look for server certificate in actual_config/opc_server/own/certs/uaservercpp.der
    cert_path = os.path.join(ACTUAL_CONFIG_DIR, "opc_server", "own", "certs", "uaservercpp.der")
    if os.path.exists(cert_path):
        return cert_path
    
    return None


def backup_server_config(server_dir):
    """Backup the current server PKI configuration to actual_config directory.
    
    Args:
        server_dir: Path to the OPC UA server directory (e.g., /path/to/UaCPPServer)
    """
    backup_dir = os.path.join(ACTUAL_CONFIG_DIR, "opc_server")
    
    print()
    print("="*70)
    print("BACKING UP SERVER CONFIGURATION")
    print("="*70)
    print(f"Backup directory: {backup_dir}")
    print()
    
    try:
        server_pki = os.path.join(server_dir, "pkiserver")
        
        # Backup trusted certificates and CRLs
        trusted_certs_src = os.path.join(server_pki, "trusted", "certs")
        if os.path.exists(trusted_certs_src):
            trusted_certs_dst = os.path.join(backup_dir, "trusted", "certs")
            os.makedirs(trusted_certs_dst, exist_ok=True)
            for item in os.listdir(trusted_certs_src):
                src_file = os.path.join(trusted_certs_src, item)
                dst_file = os.path.join(trusted_certs_dst, item)
                shutil.copy2(src_file, dst_file)
            print(f"✓ Backed up trusted certificates: {len(os.listdir(trusted_certs_dst))} files")
        
        trusted_crl_src = os.path.join(server_pki, "trusted", "crl")
        if os.path.exists(trusted_crl_src):
            trusted_crl_dst = os.path.join(backup_dir, "trusted", "crl")
            os.makedirs(trusted_crl_dst, exist_ok=True)
            for item in os.listdir(trusted_crl_src):
                src_file = os.path.join(trusted_crl_src, item)
                dst_file = os.path.join(trusted_crl_dst, item)
                shutil.copy2(src_file, dst_file)
            print(f"✓ Backed up CRLs: {len(os.listdir(trusted_crl_dst))} files")
        
        # Backup own certificates for reference (preserves uaservercpp.der naming)
        own_certs_src = os.path.join(server_pki, "own", "certs")
        if os.path.exists(own_certs_src):
            own_certs_dst = os.path.join(backup_dir, "own", "certs")
            os.makedirs(own_certs_dst, exist_ok=True)
            for item in os.listdir(own_certs_src):
                src_file = os.path.join(own_certs_src, item)
                dst_file = os.path.join(own_certs_dst, item)
                shutil.copy2(src_file, dst_file)
            print(f"✓ Backed up own certificates: {len(os.listdir(own_certs_dst))} files")
        
        print()
        print("✅ Server configuration backed up successfully!")
        print(f"📁 Location: {backup_dir}")
        return True
        
    except Exception as e:
        print(f"⚠️  Backup failed: {e}")
        return False


def push_trustlist(server_dir):
    """Push complete CA chain to the server using v2 TrustListManager.
    
    Args:
        server_dir: Path to the OPC UA server directory for initial bootstrap.
                   After first run, uses certificates from actual_config.
    """
    
    print("="*70)
    print("TRUSTLIST PUSH V2 - SECURE CONNECTION")
    print(f"Server: {SERVER_URL}")
    print("="*70)
    print()
    
    # Initialize TrustListManager
    manager = TrustListManager(WORKSPACE)
    
    # Define certificate paths
    root_cert = os.path.join(WORKSPACE, "root", "root.cert.der")
    root_crl = os.path.join(WORKSPACE, "root", "root.crl.der")
    
    int1_cert = os.path.join(WORKSPACE, "intermediate", "intermediate.cert.der")
    int1_crl = os.path.join(WORKSPACE, "intermediate", "intermediate.crl.der")
    
    int2_cert = os.path.join(WORKSPACE, "intermediate2", "intermediate2.cert.der")
    int2_crl = os.path.join(WORKSPACE, "intermediate2", "intermediate2.crl.der")
    
    # Build TrustList with all CAs
    print("📂 Building TrustList...")
    trustlist = manager.build_trustlist(
        trusted_cert_paths=[root_cert, int1_cert, int2_cert],
        issuer_cert_paths=[root_cert, int1_cert, int2_cert],
        trusted_crl_paths=[root_crl, int1_crl, int2_crl],
        issuer_crl_paths=[root_crl, int1_crl, int2_crl]
    )
    
    # Count certificates and CRLs
    num_certs = len(trustlist.TrustedCertificates)
    num_crls = len(trustlist.TrustedCrls)
    print(f"   ✓ {num_certs} certificates (Root + 2 Intermediate CAs)")
    print(f"   ✓ {num_crls} CRLs")
    print()
    
    # Get server certificate path - use latest from actual_config or provided server_dir
    if server_dir:
        server_cert_path = os.path.join(server_dir, "pkiserver/own/certs/uaservercpp.der")
    else:
        server_cert_path = get_latest_server_cert()
        if not server_cert_path:
            print("❌ No server certificate found")
            print("   Please provide server_dir parameter for first run")
            return False
        print(f"📂 Using latest server certificate from: {os.path.dirname(server_cert_path)}")
    
    # Setup secure connection
    client_cert_path = os.path.join(WORKSPACE, "server", "server.cert.der")
    client_key_path = os.path.join(WORKSPACE, "server", "server.key.pem")
    
    # Verify files exist
    for path, name in [(server_cert_path, "Server certificate"),
                       (client_cert_path, "Client certificate"),
                       (client_key_path, "Client private key")]:
        if not os.path.exists(path):
            print(f"❌ {name} not found: {path}")
            return False
    
    print("🔐 Setting up secure connection...")
    print(f"   Server cert: {server_cert_path}")
    print(f"   Client cert: {client_cert_path}")
    print(f"   Client key: {client_key_path}")
    print("   Security: Basic256Sha256 + SignAndEncrypt")
    print("   Authentication: root/secret")
    print()
    
    # Create client
    client = Client(SERVER_URL)
    client.application_uri = "urn:example.com:MyApplication"
    
    try:
        # Workaround for server sending certificate chain instead of single certificate:
        # We need to monkey-patch the x509_from_der function to handle chains
        from opcua.crypto import uacrypto
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        _original_x509_from_der = uacrypto.x509_from_der
        chain_detected = [False]  # Use list to allow modification in nested function
        
        def _patched_x509_from_der(data):
            """Patched version that extracts first cert from chains"""
            try:
                # Try the original function first
                return _original_x509_from_der(data)
            except ValueError as e:
                if "ExtraData" in str(e):
                    # Extract first certificate from chain
                    print(f"⚠️  Server sent certificate chain ({len(data)} bytes)")
                    fixed_cert = extract_first_cert_from_chain(data)
                    print(f"   Extracting first certificate ({len(fixed_cert)} bytes)")
                    chain_detected[0] = True
                    return x509.load_der_x509_certificate(fixed_cert, default_backend())
                raise
        
        # Apply the patch
        uacrypto.x509_from_der = _patched_x509_from_der
        
        # Also monkey-patch the Client.create_session to handle certificate chain comparison
        from opcua.client import client as opcua_client
        _original_create_session = opcua_client.Client.create_session
        
        def _patched_create_session(self):
            """Patched version that handles certificate chains in comparison"""
            from opcua import ua
            from opcua.common import utils
            from opcua.client.client import KeepAlive
            import logging
            
            desc = ua.ApplicationDescription()
            desc.ApplicationUri = self.application_uri
            desc.ProductUri = self.product_uri
            desc.ApplicationName = ua.LocalizedText(self.name)
            desc.ApplicationType = ua.ApplicationType.Client

            params = ua.CreateSessionParameters()
            nonce = utils.create_nonce(32)
            params.ClientNonce = nonce
            params.ClientCertificate = self.security_policy.client_certificate
            params.ClientDescription = desc
            params.EndpointUrl = self.server_url.geturl()
            params.SessionName = self.description + " Session" + str(self._session_counter)
            params.RequestedSessionTimeout = self.session_timeout
            params.MaxResponseMessageSize = 0
            response = self.uaclient.create_session(params)
            if self.security_policy.client_certificate is None:
                data = nonce
            else:
                data = self.security_policy.client_certificate + nonce
            self.security_policy.asymmetric_cryptography.verify(data, response.ServerSignature.Signature)
            self._server_nonce = response.ServerNonce
            if not self.security_policy.server_certificate:
                self.security_policy.server_certificate = response.ServerCertificate
            elif self.security_policy.server_certificate != response.ServerCertificate:
                # Handle case where server sends chain but we have single cert
                server_resp_cert = extract_first_cert_from_chain(response.ServerCertificate)
                if self.security_policy.server_certificate != server_resp_cert:
                    raise ua.UaError("Server certificate mismatch")
                else:
                    print("   ✓ Certificate validated (extracted from chain)")
            
            ep = opcua_client.Client.find_endpoint(response.ServerEndpoints, self.security_policy.Mode, self.security_policy.URI)
            self._policy_ids = ep.UserIdentityTokens
            if self.session_timeout != response.RevisedSessionTimeout:
                logging.getLogger(__name__).warning("Requested session timeout to be %dms, got %dms instead",
                                    self.secure_channel_timeout,
                                    response.RevisedSessionTimeout)
                self.session_timeout = response.RevisedSessionTimeout
            self.keepalive = KeepAlive(
                self, min(self.session_timeout, self.secure_channel_timeout) * 0.7)
            self.keepalive.start()
            return response
        
        # Apply create_session patch
        opcua_client.Client.create_session = _patched_create_session
        
        # Set security with the cached certificate
        client.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            certificate_path=client_cert_path,
            private_key_path=client_key_path,
            server_certificate_path=server_cert_path,
            mode=ua.MessageSecurityMode.SignAndEncrypt
        )
        
        # Set authentication
        client.set_user("root")
        client.set_password("secret")
        
        # Connect
        print("🔌 Connecting to server...")
        client.connect()
        print("✅ Secure connection established")
        print()
        
        # Check server support
        print("🔍 Checking server capabilities...")
        support_info = manager.check_server_certificate_support(client)
        
        if not support_info['has_certificate_groups']:
            print("❌ Server does not support certificate management")
            return False
        print()
        
        # Discover TrustList nodes
        print("🔎 Discovering TrustList nodes...")
        trustlist_nodes = manager.discover_trustlist_nodes(client)
        
        if not trustlist_nodes:
            print("❌ No TrustList nodes found")
            return False
        print()
        
        # Push to each TrustList
        success_count = 0
        
        for node_info in trustlist_nodes:
            print(f"📤 Pushing to: {node_info.group_name}")
            print(f"   Group ID: {node_info.group_id}")
            print(f"   TrustList: {node_info.trustlist_node.nodeid}")
            
            success = manager.update_trustlist(
                trustlist_node=node_info.trustlist_node,
                trustlist_data=trustlist,
                max_chunk_size=1024
            )
            
            if success:
                print(f"   ✅ Successfully pushed to {node_info.group_name}")
                success_count += 1
            else:
                print(f"   ❌ Failed to push to {node_info.group_name}")
            print()
        
        # Disconnect
        client.disconnect()
        print("🔌 Disconnected")
        print()
        
        # Summary
        print("="*70)
        print("SUMMARY")
        print("="*70)
        print(f"Certificate groups: {len(trustlist_nodes)}")
        print(f"Successful pushes: {success_count}")
        print(f"Success rate: {success_count}/{len(trustlist_nodes)}")
        
        if success_count > 0:
            print()
            print("✅ TRUSTLIST PUSH SUCCESSFUL!")
            print()
            print("📋 What was updated:")
            print("   • Root CA: Trustpoint TLS Root CA")
            print("   • Intermediate CA 1: Trustpoint TLS Intermediate CA")
            print("   • Intermediate CA 2: Trustpoint TLS Intermediate CA 2")
            print("   • All corresponding CRLs")
            
            # Backup server configuration after successful push (only if server_dir provided)
            if server_dir:
                backup_server_config(server_dir)
            
            print()
            print("💡 Next steps:")
            print("   1. The server now trusts the complete CA chain")
            print("   2. You can connect with certificates signed by any of these CAs")
            print("   3. Server certificates can be updated using UpdateCertificate")
            print()
            print("🔍 To verify:")
            print("   • Check server logs for trustlist update events")
            print("   • Connect with a CA-signed certificate")
            print("   • Certificate validation should succeed")
        else:
            print()
            print("❌ TRUSTLIST PUSH FAILED")
            print()
            print("💡 Troubleshooting:")
            print("   1. Ensure at least one CA is manually trusted (bootstrap)")
            print("   2. Verify client certificate is signed by trusted CA")
            print("   3. Check server logs for detailed error messages")
            print("   4. Confirm server supports GDS certificate management")
        
        return success_count > 0
        
    except Exception as e:
        print(f"❌ Operation failed: {e}")
        
        # Provide helpful error messages
        error_msg = str(e)
        if "certificate mismatch" in error_msg.lower():
            print()
            print("💡 Server certificate mismatch:")
            print("   The cached certificate in actual_config/ doesn't match the server's current certificate.")
            print()
            print("   Or manually copy the current server certificate:")
            cert_path = get_latest_server_cert()
            if cert_path:
                print(f"   cp /path/to/UaCPPServer/pkiserver/own/certs/uaservercpp.der \\")
                print(f"      {cert_path}")
        elif "BadSecurityChecksFailed" in error_msg:
            print()
            print("💡 Security check failed - possible causes:")
            print("   1. Server doesn't trust the client certificate's issuing CA")
            print("   2. Bootstrap required: manually copy CA to server first")
            print("   3. Certificate validation failed on server side")
            print()
            print("Bootstrap command:")
            print(f"   cp {int1_cert} <server_dir>/pkiserver/trusted/certs/")
        elif "BadCertificateUriInvalid" in error_msg:
            print()
            print("💡 Certificate URI mismatch:")
            print("   1. Client certificate Application URI doesn't match")
            print("   2. Check certificate SAN (Subject Alternative Name)")
            print("   3. Regenerate certificate with correct Application URI")
        elif "encrypted" in error_msg.lower() and "private key" in error_msg.lower():
            print()
            print("💡 Private key is encrypted:")
            print("   1. Regenerate certificates with ENCRYPT_KEYS=false")
            print("   2. Or decrypt the existing private key")
        
        import traceback
        traceback.print_exc()
        
        try:
            client.disconnect()
        except Exception:
            pass
        
        return False


if __name__ == "__main__":
    import sys
    
    # For first run, provide server directory as command line argument
    # Example: python push_trustlist_v2.py /path/to/UaCPPServer
    # After first run, it will use certificates from actual_config/
    server_dir = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not server_dir and not get_latest_server_cert():
        print("❌ No server directory provided and no backups found in actual_config/")
        print()
        print("Usage for first run:")
        print(f"  python {sys.argv[0]} /path/to/UaCPPServer")
        print()
        print("After the first successful run, the script will use certificates")
        print("from actual_config/ automatically.")
        exit(1)
    
    success = push_trustlist(server_dir)
    exit(0 if success else 1)
