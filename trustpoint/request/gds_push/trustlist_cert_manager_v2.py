"""
TrustList and Certificate Manager for OPC UA GDS - Version 2

This module provides classes for managing OPC UA GDS PushManagement workflows:

1. TrustListManager - Manages UpdateTrustList workflow (OPC UA Part 12 Section 7.7.3)
   - Builds TrustList from certificate and CRL files
   - Discovers TrustList nodes on OPC UA servers
   - Orchestrates TrustList upload workflow via direct node method calls

2. CertificateUpdateManager - Manages UpdateCert workflow (OPC UA Part 12 Section 7.7.4)
   - Discovers CertificateManager nodes on OPC UA servers
   - Orchestrates CSR-based certificate issuance workflow
   - Signs CSRs using intermediate CA
   - Uploads signed certificates with full chain to servers

Key improvements in v2:
- Uses standard OPC UA node IDs (ns=0;i=2253 for Server object)
- Properly handles secure connections with client certificates
- Supports both namespace 0 (standard) and custom namespace structures
- Better error handling and diagnostics
"""

import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

from opcua import ua
from opcua.ua.ua_binary import struct_to_binary


@dataclass
class TrustListNodeInfo:
    """Information about a discovered TrustList node."""
    group_node: any  # The CertificateGroup node
    trustlist_node: any  # The TrustList node
    group_name: str  # Name of the certificate group
    group_id: ua.NodeId  # NodeId of the certificate group


class CertificateTypes:
    """OPC UA GDS Certificate Types (Section 7.8.4).
    
    Defines different categories of certificates that servers can use.
    Each CertificateGroup can support multiple CertificateTypes.
    """
    
    # Standard Application Certificate (default for OPC UA applications)
    APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=12557")
    
    # HTTPS Certificate for HTTPS endpoints
    HTTPS_CERTIFICATE = ua.NodeId.from_string("ns=0;i=12558")
    
    # Application Certificate Subtypes (Section 7.8.4.2)
    # RSA-based application certificates
    RSA_MIN_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=12559")      # RSA with minimum key size
    RSA_SHA256_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=12560")  # RSA with SHA-256
    
    # ECC-based application certificates (NIST curves)
    ECC_NIST_P256_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=23538")   # NIST P-256
    ECC_NIST_P384_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=23539")   # NIST P-384
    
    # ECC-based application certificates (Brainpool curves)
    ECC_BRAINPOOL_P256R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=23540")  # Brainpool P-256-r1
    ECC_BRAINPOOL_P384R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string("ns=0;i=23541")  # Brainpool P-384-r1


class TrustListManager:
    """Manages TrustList operations for OPC UA GDS (Part 12 Section 7.7.3)."""

    def __init__(self, workspace_path: str):
        """Initialize TrustListManager.
        
        Args:
            workspace_path: Path to workspace containing certificate files
        """
        self.workspace_path = workspace_path

    def check_server_certificate_support(self, client) -> dict:
        """Check if the server supports certificate management (GDS features).
        
        Args:
            client: Connected OPC UA client
            
        Returns:
            Dictionary with server capability information
        """
        support_info = {
            'has_certificate_groups': False,
            'certificate_groups_path': None,
            'certificate_groups_node': None,
            'server_type': 'unknown',
            'gds_compliant': False,
            'server_config_node': None
        }
        
        try:
            # Use standard OPC UA Server object (ns=0;i=2253)
            server_node = client.get_node("ns=0;i=2253")
            support_info['server_type'] = 'standard'
            
            # Try standard GDS path: Server.ServerConfiguration.CertificateGroups
            try:
                server_config = server_node.get_child("ServerConfiguration")
                support_info['server_config_node'] = server_config
                
                certificate_groups_node = server_config.get_child("CertificateGroups")
                support_info['has_certificate_groups'] = True
                support_info['certificate_groups_path'] = 'Server.ServerConfiguration.CertificateGroups'
                support_info['certificate_groups_node'] = certificate_groups_node
                support_info['gds_compliant'] = True
                print(f"✅ Server supports GDS: CertificateGroups found at {support_info['certificate_groups_path']}")
                return support_info
            except Exception as e:
                print(f"⚠️  Standard GDS path not found: {e}")
            
            # Try alternative path: Server.CertificateGroups (non-standard)
            try:
                certificate_groups_node = server_node.get_child("CertificateGroups")
                support_info['has_certificate_groups'] = True
                support_info['certificate_groups_path'] = 'Server.CertificateGroups'
                support_info['certificate_groups_node'] = certificate_groups_node
                support_info['gds_compliant'] = False
                print(f"⚠️  CertificateGroups found at non-standard location: {support_info['certificate_groups_path']}")
                return support_info
            except Exception as e:
                print(f"⚠️  Alternative path not found: {e}")
            
            # Check if server has any certificate-related nodes
            try:
                server_children = server_node.get_children()
                cert_related_nodes = []
                for child in server_children:
                    try:
                        browse_name = child.get_browse_name().Name
                        if any(keyword in browse_name.lower() for keyword in ['cert', 'group', 'trust', 'security']):
                            cert_related_nodes.append(browse_name)
                    except Exception:
                        pass
                
                if cert_related_nodes:
                    print(f"ℹ️  Server has certificate-related nodes: {cert_related_nodes}")
                else:
                    print("ℹ️  No certificate-related nodes found in Server")
                    
            except Exception as e:
                print(f"⚠️  Could not browse server children: {e}")
            
        except Exception as e:
            print(f"❌ Error checking certificate support: {e}")
        
        print("❌ Server does not support standard GDS certificate management")
        return support_info

    def load_der_file(self, path: str) -> bytes:
        """Load a DER-encoded file as bytes.
        
        Args:
            path: Path to DER file
            
        Returns:
            File contents as bytes
        """
        with open(path, "rb") as f:
            return f.read()

    def build_trustlist(self, 
                       trusted_cert_paths: List[str],
                       issuer_cert_paths: List[str] = None,
                       trusted_crl_paths: List[str] = None,
                       issuer_crl_paths: List[str] = None) -> ua.TrustListDataType:
        """Build TrustList data structure from certificate and CRL file paths.
        
        Args:
            trusted_cert_paths: List of paths to trusted certificates (CA certs)
            issuer_cert_paths: List of paths to issuer certificates (optional, defaults to trusted)
            trusted_crl_paths: List of paths to trusted CRLs (optional)
            issuer_crl_paths: List of paths to issuer CRLs (optional)
            
        Returns:
            TrustListDataType ready for serialization
        """
        # Load trusted certificates
        trusted_certs = [self.load_der_file(path) for path in trusted_cert_paths]
        
        # Load issuer certificates (default to trusted if not specified)
        if issuer_cert_paths is None:
            issuer_cert_paths = trusted_cert_paths
        issuer_certs = [self.load_der_file(path) for path in issuer_cert_paths]

        # Load CRLs
        trusted_crls = []
        if trusted_crl_paths:
            for path in trusted_crl_paths:
                if os.path.exists(path):
                    trusted_crls.append(self.load_der_file(path))
        
        issuer_crls = []
        if issuer_crl_paths:
            for path in issuer_crl_paths:
                if os.path.exists(path):
                    issuer_crls.append(self.load_der_file(path))
        elif trusted_crls:
            issuer_crls = trusted_crls

        # Build TrustListDataType
        trustlist = ua.TrustListDataType()
        trustlist.SpecifiedLists = ua.TrustListMasks.All  # 0x0F - all lists
        trustlist.TrustedCertificates = trusted_certs
        trustlist.TrustedCrls = trusted_crls
        trustlist.IssuerCertificates = issuer_certs
        trustlist.IssuerCrls = issuer_crls

        return trustlist

    def discover_trustlist_nodes(self, client) -> List[TrustListNodeInfo]:
        """Discover all available TrustList nodes on the OPC UA server.
        
        Args:
            client: Connected OPC UA client
            
        Returns:
            List of TrustListNodeInfo objects
        """
        trustlist_nodes = []

        try:
            # Use standard Server node
            server_node = client.get_node("ns=0;i=2253")
            
            # Try to get ServerConfiguration
            try:
                server_config = server_node.get_child("ServerConfiguration")
                certificate_groups_node = server_config.get_child("CertificateGroups")
                print(f"✅ Found CertificateGroups at standard location")
            except Exception as e:
                print(f"⚠️  Standard path failed, trying alternative: {e}")
                # Try alternative path
                certificate_groups_node = server_node.get_child("CertificateGroups")
                print(f"✅ Found CertificateGroups at alternative location")

            # Get all certificate groups
            groups = certificate_groups_node.get_children()
            print(f"📋 Found {len(groups)} certificate group(s)")

            # Iterate through each group to find TrustList
            for group_node in groups:
                try:
                    group_name = group_node.get_browse_name().Name
                    group_id = group_node.nodeid
                    print(f"   Checking group: {group_name} ({group_id})")

                    # Try to get TrustList child
                    try:
                        trustlist_node = group_node.get_child("TrustList")
                        print(f"   ✅ Found TrustList: {trustlist_node.nodeid}")
                        
                        # Create node info
                        node_info = TrustListNodeInfo(
                            group_node=group_node,
                            trustlist_node=trustlist_node,
                            group_name=group_name,
                            group_id=group_id
                        )
                        trustlist_nodes.append(node_info)
                        
                    except Exception as e:
                        print(f"   ⚠️  Could not find TrustList in {group_name}: {e}")
                        continue

                except Exception as e:
                    print(f"   ❌ Error processing group {group_node}: {e}")
                    continue

        except Exception as e:
            print(f"❌ Could not browse CertificateGroups: {e}")
            import traceback
            traceback.print_exc()

        return trustlist_nodes

    def update_trustlist(self, 
                        trustlist_node,
                        trustlist_data: ua.TrustListDataType,
                        max_chunk_size: int = 1024) -> bool:
        """Perform the UpdateTrustList Workflow (OPC UA Part 12 Section 7.7.3).
        
        This method implements the standard 4-step workflow:
        1. Open - Open the TrustList for writing
        2. Write - Write TrustList data in chunks
        3. CloseAndUpdate - Close and apply the new TrustList
        4. ApplyChanges (if required) - Apply changes server-wide
        
        Args:
            trustlist_node: The TrustList node to update
            trustlist_data: TrustListDataType containing certificates and CRLs
            max_chunk_size: Maximum size of each write chunk (default 1024 bytes)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize the TrustList
            serialized_trustlist = struct_to_binary(trustlist_data)
            print(f"   📦 Serialized TrustList: {len(serialized_trustlist)} bytes")

            # Step 1: Open TrustList
            print(f"   [1/4] Opening TrustList...")
            mode = ua.TrustListMasks.All
            open_method = trustlist_node.get_child("Open")
            file_handle = trustlist_node.call_method(open_method, mode)
            print(f"         ✓ Handle: {file_handle}")

            # Step 2: Write data in chunks
            print(f"   [2/4] Writing data...")
            write_method = trustlist_node.get_child("Write")
            offset = 0
            chunk_count = 0
            
            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset:offset + max_chunk_size]
                trustlist_node.call_method(write_method, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1
            
            print(f"         ✓ {len(serialized_trustlist)} bytes ({chunk_count} chunks)")

            # Step 3: CloseAndUpdate
            print(f"   [3/4] Closing and updating...")
            close_and_update_method = trustlist_node.get_child("CloseAndUpdate")
            apply_changes_required = trustlist_node.call_method(close_and_update_method, file_handle)
            print(f"         ✓ Closed (ApplyChanges required: {apply_changes_required})")

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                print(f"   [4/4] Applying changes...")
                # ApplyChanges is on ServerConfiguration, not TrustList
                server_node = trustlist_node.get_node("ns=0;i=2253")
                server_config = server_node.get_child("ServerConfiguration")
                apply_changes_method = server_config.get_child("ApplyChanges")
                server_config.call_method(apply_changes_method)
                print(f"         ✓ Changes applied")
            else:
                print(f"   [4/4] ApplyChanges not required")

            return True

        except Exception as e:
            print(f"   ❌ Failed: {e}")
            import traceback
            traceback.print_exc()
            return False


class CertificateUpdateManager:
    """Manages certificate update operations for OPC UA GDS (Part 12 Section 7.7.4)."""

    def __init__(self, workspace_path: str, ca_cert_path: str = None, ca_key_path: str = None):
        """Initialize CertificateUpdateManager with CA credentials.
        
        Args:
            workspace_path: Path to workspace containing certificate files
            ca_cert_path: Path to CA certificate (optional, auto-detected from workspace)
            ca_key_path: Path to CA private key (optional, auto-detected from workspace)
        """
        self.workspace_path = workspace_path
        
        # Auto-detect CA certificate path
        if ca_cert_path:
            self.ca_cert_path = ca_cert_path
        else:
            if "ca_workspace" in workspace_path:
                base_path = workspace_path
            else:
                base_path = os.path.join(workspace_path, "ca_workspace")
            self.ca_cert_path = os.path.join(base_path, "intermediate/intermediate.cert.der")
        
        # Auto-detect CA key path
        if ca_key_path:
            self.ca_key_path = ca_key_path
        else:
            if "ca_workspace" in workspace_path:
                base_path = workspace_path
            else:
                base_path = os.path.join(workspace_path, "ca_workspace")
            # Use PEM format key (unencrypted) instead of DER
            self.ca_key_path = os.path.join(base_path, "intermediate/intermediate.key.pem")

    def load_der_file(self, path: str) -> bytes:
        """Load a DER-encoded file as bytes."""
        with open(path, "rb") as f:
            return f.read()

    def discover_certificate_groups(self, client) -> List[dict]:
        """Discover all certificate groups on the server.
        
        Args:
            client: Connected OPC UA client
            
        Returns:
            List of dictionaries with group information
        """
        groups = []
        
        try:
            server_node = client.get_node("ns=0;i=2253")
            server_config = server_node.get_child("ServerConfiguration")
            cert_groups_node = server_config.get_child("CertificateGroups")
            
            group_nodes = cert_groups_node.get_children()
            print(f"📋 Found {len(group_nodes)} certificate group(s)")
            
            for group_node in group_nodes:
                group_name = group_node.get_browse_name().Name
                group_id = group_node.nodeid
                
                group_info = {
                    'name': group_name,
                    'node_id': group_id,
                    'node': group_node
                }
                groups.append(group_info)
                print(f"   • {group_name}: {group_id}")
            
        except Exception as e:
            print(f"❌ Could not discover certificate groups: {e}")
        
        return groups

    def sign_csr_with_ca(self, csr_der: bytes) -> Tuple[bytes, List[bytes]]:
        """Sign a Certificate Signing Request with the intermediate CA.
        
        Args:
            csr_der: DER-encoded CSR
            
        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs)
        """
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import datetime
        
        print("   🔏 Signing CSR with intermediate CA...")
        
        # Load CSR
        csr = x509.load_der_x509_csr(csr_der, default_backend())
        print(f"   📋 CSR Subject: {csr.subject}")
        
        # Load CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_der_x509_certificate(f.read(), default_backend())
        
        # Load CA private key (PEM format, unencrypted)
        with open(self.ca_key_path, "rb") as f:
            key_data = f.read()
            # Try PEM first, then DER
            try:
                ca_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
            except ValueError:
                ca_key = serialization.load_der_private_key(key_data, password=None, backend=default_backend())
        
        print(f"   🏢 CA Issuer: {ca_cert.subject}")
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        
        # Copy extensions from CSR
        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, ext.critical)
        
        # Add BasicConstraints if not present
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
        
        # Add KeyUsage if not present
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        
        # Sign the certificate
        certificate = builder.sign(ca_key, hashes.SHA256(), default_backend())
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        
        print(f"   ✅ Certificate issued successfully ({len(cert_der)} bytes)")
        
        # Build issuer chain
        ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
        issuer_chain = [ca_cert_der]
        
        # Add root CA if available
        if "ca_workspace" in self.workspace_path:
            base_path = self.workspace_path
        else:
            base_path = os.path.join(self.workspace_path, "ca_workspace")
        root_cert_path = os.path.join(base_path, "root/root.cert.der")
        
        if os.path.exists(root_cert_path):
            with open(root_cert_path, "rb") as f:
                issuer_chain.append(f.read())
            print(f"   📜 Issuer chain includes root CA")
        
        return cert_der, issuer_chain

    def update_single_certificate(self, 
                                  client,
                                  certificate_group_id: ua.NodeId,
                                  certificate_type_id: ua.NodeId = None,
                                  subject_name: str = None,
                                  regenerate_private_key: bool = True,
                                  nonce: bytes = None):
        """Perform the Update Single Certificate Workflow per OPC UA GDS Part 12 Section 7.7.4.
        
        Args:
            client: Connected OPC UA client
            certificate_group_id: NodeId of the certificate group to update
            certificate_type_id: NodeId of certificate type (defaults to ApplicationCertificate)
            subject_name: Subject name for the certificate (optional)
            regenerate_private_key: Whether server should generate new private key
            nonce: Nonce for key generation (optional)
            
        Returns:
            tuple: (success: bool, certificate: bytes or None) - Returns True and the signed certificate on success, (False, None) on failure
        """
        print("\n" + "="*70)
        print("UPDATE SINGLE CERTIFICATE WORKFLOW")
        print("="*70)
        print(f"Certificate Group: {certificate_group_id}")
        
        # Default to ApplicationCertificate type
        if certificate_type_id is None:
            certificate_type_id = CertificateTypes.APPLICATION_CERTIFICATE
        print(f"Certificate Type: {certificate_type_id}")
        
        try:
            # Get ServerConfiguration node
            server_node = client.get_node("ns=0;i=2253")
            server_config = server_node.get_child("ServerConfiguration")
            
            # Step 1: CreateSigningRequest - Server generates CSR
            print("\n[1/4] Server generates CSR via CreateSigningRequest...")
            create_signing_request = server_config.get_child("CreateSigningRequest")
            
            # IMPORTANT: Server requires SubjectName=None to generate its own subject
            # Providing a subject name causes BadInvalidArgument error
            # The server will use its configured subject name instead
            print("      Arguments:")
            print(f"        CertificateGroupId: {certificate_group_id}")
            print(f"        CertificateTypeId: {certificate_type_id}")
            print(f"        SubjectName: None (server generates its own)")
            print(f"        RegeneratePrivateKey: {regenerate_private_key}")
            print(f"        Nonce: None")
            
            csr = server_config.call_method(
                create_signing_request,
                certificate_group_id,
                certificate_type_id,
                None,  # SubjectName - MUST be None for this server
                regenerate_private_key,
                None   # Nonce - None works fine
            )
            print(f"      ✓ CSR generated by server ({len(csr)} bytes)")
            
            # Step 2: GDS signs the CSR with intermediate CA
            print("\n[2/4] GDS signs CSR with intermediate CA...")
            signed_cert, issuer_chain = self.sign_csr_with_ca(csr)
            
            # Step 3: UpdateCertificate - Upload certificate to server
            print("\n[3/4] Uploading signed certificate via UpdateCertificate...")
            update_certificate = server_config.get_child("UpdateCertificate")
            
            apply_changes_required = server_config.call_method(
                update_certificate,
                certificate_group_id,
                certificate_type_id,
                signed_cert,
                issuer_chain,
                "",  # privateKeyFormat - empty since server generated key
                b""  # privateKey - empty since server generated key
            )
            print(f"      ✓ Certificate uploaded to server")
            print(f"      ApplyChanges required: {apply_changes_required}")
            
            # Step 4: ApplyChanges if required
            if apply_changes_required:
                print("\n[4/4] Applying changes via ApplyChanges...")
                apply_changes_method = server_config.get_child("ApplyChanges")
                server_config.call_method(apply_changes_method)
                print("      ✓ Changes applied successfully")
            else:
                print("\n[4/4] ApplyChanges not required")
            
            print("\n" + "="*70)
            print("✅ UPDATE SINGLE CERTIFICATE WORKFLOW COMPLETED")
            print("="*70)
            return True, signed_cert
            
        except Exception as e:
            print(f"\n❌ Update Single Certificate Workflow failed: {e}")
            import traceback
            traceback.print_exc()
            return False, None
