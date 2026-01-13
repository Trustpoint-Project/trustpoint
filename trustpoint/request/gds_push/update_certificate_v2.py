"""Update server certificate using v2 CertificateUpdateManager.

This script implements the OPC UA GDS UpdateCertificate workflow (Part 12 Section 7.7.4):
1. Server generates CSR (CreateSigningRequest)
2. GDS signs CSR with intermediate CA
3. Upload signed certificate to server (UpdateCertificate)
4. Apply changes if required (ApplyChanges)

The server generates its own private key and CSR, we just sign it and send back
the signed certificate with the issuer chain.

Requirements:
- Server must trust the CA chain (use push_trustlist_v2.py first)
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
from trustlist_cert_manager_v2 import CertificateUpdateManager, CertificateTypes

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
    
    This captures the state of the server's certificate infrastructure after
    a successful certificate update, including:
    - Server's own certificates
    - Trusted certificates
    - Certificate Revocation Lists (CRLs)
    - Rejected certificates
    
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
        # Source directories in server
        server_pki = os.path.join(server_dir, "pkiserver")
        
        # Backup own certificates
        own_certs_src = os.path.join(server_pki, "own", "certs")
        own_private_src = os.path.join(server_pki, "own", "private")
        
        if os.path.exists(own_certs_src):
            own_certs_dst = os.path.join(backup_dir, "own", "certs")
            os.makedirs(own_certs_dst, exist_ok=True)
            for item in os.listdir(own_certs_src):
                src_file = os.path.join(own_certs_src, item)
                # Preserve original filename (e.g., uaservercpp.der)
                dst_file = os.path.join(own_certs_dst, item)
                shutil.copy2(src_file, dst_file)
            print(f"✓ Backed up own certificates: {len(os.listdir(own_certs_dst))} files")
        
        if os.path.exists(own_private_src):
            own_private_dst = os.path.join(backup_dir, "own", "private")
            os.makedirs(own_private_dst, exist_ok=True)
            for item in os.listdir(own_private_src):
                src_file = os.path.join(own_private_src, item)
                # Preserve original filename (e.g., uaservercpp.pem)
                dst_file = os.path.join(own_private_dst, item)
                shutil.copy2(src_file, dst_file)
            print(f"✓ Backed up private keys: {len(os.listdir(own_private_dst))} files")
        
        # Backup trusted certificates
        trusted_certs_src = os.path.join(server_pki, "trusted", "certs")
        if os.path.exists(trusted_certs_src):
            trusted_certs_dst = os.path.join(backup_dir, "trusted", "certs")
            os.makedirs(trusted_certs_dst, exist_ok=True)
            for item in os.listdir(trusted_certs_src):
                shutil.copy2(os.path.join(trusted_certs_src, item), trusted_certs_dst)
            print(f"✓ Backed up trusted certificates: {len(os.listdir(trusted_certs_dst))} files")
        
        # Backup CRLs
        trusted_crl_src = os.path.join(server_pki, "trusted", "crl")
        if os.path.exists(trusted_crl_src):
            trusted_crl_dst = os.path.join(backup_dir, "trusted", "crl")
            os.makedirs(trusted_crl_dst, exist_ok=True)
            for item in os.listdir(trusted_crl_src):
                shutil.copy2(os.path.join(trusted_crl_src, item), trusted_crl_dst)
            print(f"✓ Backed up CRLs: {len(os.listdir(trusted_crl_dst))} files")
        
        # Backup rejected certificates (if any)
        rejected_src = os.path.join(server_pki, "rejected")
        if os.path.exists(rejected_src):
            rejected_dst = os.path.join(backup_dir, "rejected")
            os.makedirs(rejected_dst, exist_ok=True)
            for item in os.listdir(rejected_src):
                shutil.copy2(os.path.join(rejected_src, item), rejected_dst)
            if os.listdir(rejected_dst):
                print(f"✓ Backed up rejected certificates: {len(os.listdir(rejected_dst))} files")
        
        print()
        print("✅ Server configuration backed up successfully!")
        print(f"📁 Location: {backup_dir}")
        return True
        
    except Exception as e:
        print(f"⚠️  Backup failed: {e}")
        print("   (This is non-critical - certificate update was still successful)")
        import traceback
        traceback.print_exc()
        return False


def update_server_certificate(server_dir=None):
    """Update server certificate using the UpdateCertificate workflow.
    
    Args:
        server_dir: Path to OPC UA server directory. If None, uses latest backup from actual_config.
    """
    
    print("="*70)
    print("UPDATE SERVER CERTIFICATE V2 - CSR-BASED WORKFLOW")
    print(f"Server: {SERVER_URL}")
    print("="*70)
    print()
    
    # Initialize CertificateUpdateManager
    print("🔧 Initializing CertificateUpdateManager...")
    manager = CertificateUpdateManager(
        workspace_path=WORKSPACE,
        ca_cert_path=os.path.join(WORKSPACE, "intermediate", "intermediate.cert.der"),
        ca_key_path=os.path.join(WORKSPACE, "intermediate", "intermediate.key.pem")
    )
    print("   ✓ CA Certificate: intermediate/intermediate.cert.der")
    print("   ✓ CA Private Key: intermediate/intermediate.key.pem")
    print()
    
    # Get server certificate path
    if server_dir:
        server_cert_path = os.path.join(server_dir, "pkiserver/own/certs/uaservercpp.der")
    else:
        # Use latest from actual_config
        server_cert_path = get_latest_server_cert()
        if not server_cert_path:
            print("❌ No server certificate found in actual_config/")
            print("   Please provide server_dir parameter or run push_trustlist_v2.py first")
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
    print(f"   Server cert: {os.path.basename(server_cert_path)}")
    print(f"   Client cert: {os.path.basename(client_cert_path)}")
    print(f"   Client key: {os.path.basename(client_key_path)}")
    print("   Security: Basic256Sha256 + SignAndEncrypt")
    print("   Authentication: root/secret")
    print()
    
    # Create client
    client = Client(SERVER_URL)
    client.application_uri = "urn:example.com:MyApplication"
    
    try:
        # Workaround for server sending certificate chain instead of single certificate:
        # We need to monkey-patch the x509_from_der function and create_session to handle chains
        from opcua.crypto import uacrypto
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        _original_x509_from_der = uacrypto.x509_from_der
        
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
        
        # Set security
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
        
        # Discover certificate groups
        print("🔎 Discovering certificate groups...")
        groups = manager.discover_certificate_groups(client)
        
        if not groups:
            print("❌ No certificate groups found")
            return False
        print()
        
        # Update certificate for each group
        success_count = 0
        updated_certificates = []  # Store certificates that were successfully updated
        
        for group in groups:
            group_name = group['name']
            
            # Skip DefaultUserTokenGroup - it doesn't support CSR generation
            # User token groups are for user authentication certificates, not application certificates
            if 'UserToken' in group_name:
                print(f"⏭️  Skipping {group_name} (user token groups don't support CSR generation)")
                print()
                continue
            
            print("="*70)
            print(f"UPDATING CERTIFICATE FOR: {group_name}")
            print("="*70)
            print(f"Group ID: {group['node_id']}")
            print()
            
            # Update certificate with CSR-based workflow
            success, signed_cert = manager.update_single_certificate(
                client=client,
                certificate_group_id=group['node_id'],
                certificate_type_id=CertificateTypes.APPLICATION_CERTIFICATE,
                subject_name=f"CN=OPC UA Server {group['name']},O=Trustpoint,C=DE",
                regenerate_private_key=True,
                nonce=os.urandom(32)
            )
            
            if success:
                print(f"✅ Successfully updated certificate for {group['name']}")
                success_count += 1
                # Store the certificate for backup
                updated_certificates.append({
                    'group_name': group_name,
                    'certificate': signed_cert
                })
            else:
                print(f"❌ Failed to update certificate for {group['name']}")
            print()
        
        # Disconnect
        client.disconnect()
        print("🔌 Disconnected")
        print()
        
        # Summary
        print("="*70)
        print("SUMMARY")
        print("="*70)
        print(f"Certificate groups: {len(groups)}")
        print(f"Successful updates: {success_count}")
        print(f"Success rate: {success_count}/{len(groups)}")
        
        if success_count > 0:
            print()
            print("✅ CERTIFICATE UPDATE SUCCESSFUL!")
            print()
            print("📋 What happened:")
            print("   1. Server generated CSR with new private key")
            print("   2. GDS signed CSR with Intermediate CA")
            print("   3. Signed certificate uploaded to server")
            print("   4. Server updated its certificate")
            print()
            print("💡 Certificate details:")
            print("   • Issuer: Trustpoint TLS Intermediate CA")
            print("   • Subject: CN=OPC UA Server [GroupName]")
            print("   • Validity: 365 days")
            print("   • Key: Generated by server (private key stays on server)")
            print()
            
            # Save the updated certificate(s) to actual_config
            print("� Saving updated certificate to actual_config...")
            try:
                for cert_info in updated_certificates:
                    # For the main application group, save as uaservercpp.der
                    if 'Application' in cert_info['group_name']:
                        cert_save_path = os.path.join(ACTUAL_CONFIG_DIR, "opc_server", "own", "certs", "uaservercpp.der")
                        os.makedirs(os.path.dirname(cert_save_path), exist_ok=True)
                        
                        with open(cert_save_path, 'wb') as f:
                            f.write(cert_info['certificate'])
                        
                        print(f"   ✅ Saved {cert_info['group_name']} certificate")
                        print(f"   📁 Path: {cert_save_path}")
                        print(f"   📊 Size: {len(cert_info['certificate'])} bytes")
                        
                        # Display certificate details
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert = x509.load_der_x509_certificate(cert_info['certificate'], default_backend())
                        print(f"   📜 Subject: {cert.subject.rfc4514_string()}")
                        print(f"   🔏 Issuer: {cert.issuer.rfc4514_string()}")
                        
            except Exception as e:
                print(f"   ⚠️  Could not save certificate: {e}")
            
            # Backup server configuration if server_dir provided
            if server_dir:
                backup_server_config(server_dir)
            
            print()
            print("🔍 Next steps:")
            print("   1. Restart server to activate new certificate (if required)")
            print("   2. Verify certificate using:")
            print("      openssl x509 -in actual_config/opc_server/own/certs/uaservercpp.der -inform DER -text -noout")
            print("   3. Test connection with new certificate")
            print()
            print("⚠️  Important:")
            print("   • Old server certificate is replaced")
            print("   • Clients must trust the Intermediate CA")
            print("   • Cached certificate updated in actual_config/")
        else:
            print()
            print("❌ CERTIFICATE UPDATE FAILED")
            print()
            print("💡 Troubleshooting:")
            print("   1. Ensure server trusts CA chain (run push_trustlist_v2.py first)")
            print("   2. Check server has CreateSigningRequest method")
            print("   3. Verify server supports GDS certificate management")
            print("   4. Check server logs for detailed error messages")
            print("   5. Confirm server allows certificate updates")
        
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
            print("   This happens when:")
            print("   • Server certificate was updated outside of this script")
            print("   • Server was restored from backup")
            print("   • actual_config/ cache is stale")
            print()
            print("   To fix, resync the certificate by providing the server directory:")
            if server_dir:
                print(f"   uv run python {os.path.basename(__file__)} {server_dir}")
            else:
                print(f"   uv run python {os.path.basename(__file__)} /path/to/UaCPPServer")
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
            print("   2. Run push_trustlist_v2.py first to establish trust")
        elif "BadNotSupported" in error_msg or "BadNotImplemented" in error_msg:
            print()
            print("💡 Method not supported:")
            print("   1. Server may not support GDS certificate updates")
            print("   2. Check server documentation for GDS support")
            print("   3. Verify server has ServerConfiguration.CreateSigningRequest")
        elif "BadUserAccessDenied" in error_msg:
            print()
            print("💡 Access denied:")
            print("   1. User 'root' may not have permission for certificate updates")
            print("   2. Check server's role configuration")
            print("   3. Verify authentication credentials are correct")
        
        import traceback
        traceback.print_exc()
        
        try:
            client.disconnect()
        except Exception:
            pass
        
        return False


if __name__ == "__main__":
    success = update_server_certificate()
    exit(0 if success else 1)
