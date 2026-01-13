# OPC UA GDS Push Implementation

## Overview

This implementation adds OPC UA GDS Push functionality to Trustpoint, allowing secure management of OPC UA server certificates and trust lists via the GDS (Global Discovery Server) Push protocol.

## Components

### 1. GDS Push Service (`trustpoint/request/gds_push/gds_push_service.py`)

Core service implementing the OPC UA GDS Push protocol:

- **`GdsPushService`**: Main service class that handles:
  - Secure OPC UA client connections using domain credentials
  - TrustList updates (OPC UA Part 12 Section 7.7.3)
  - Server certificate updates via CSR workflow (OPC UA Part 12 Section 7.7.4)

- **Key Features**:
  - Uses Django models instead of local files
  - Authenticates using issued domain credentials
  - Retrieves server certificates from truststore models
  - Signs CSRs with domain's issuing CA
  - Automatically updates truststore with new server certificates

### 2. Views (`trustpoint/devices/views.py`)

Two action views for triggering GDS Push operations:

- **`OpcUaGdsPushUpdateTrustlistView`**:
  - POST-only view
  - Updates OPC UA server trustlist with CA certificates from associated truststore
  - Displays success/error messages via Django messages framework

- **`OpcUaGdsPushUpdateServerCertificateView`**:
  - POST-only view
  - Generates CSR on server, signs with domain CA, updates server certificate
  - Automatically updates truststore with new server certificate
  - Creates new truststore if needed

### 3. Help Page Updates (`trustpoint/help_pages/devices_help_views.py`)

Enhanced `OpcUaGdsPushApplicationCertificateStrategy`:

- **Dynamic Actions Section**:
  - Shows action buttons if domain credential exists
  - Shows setup instructions if domain credential is missing
  
- **Action Buttons**:
  - "Update Trustlist": Pushes CA certificates to server
  - "Update Server Certificate": Issues new server certificate via CSR workflow

### 4. Template System

- **New ValueRenderType**: Added `HTML` render type for interactive content
- **Custom Template Filter**: `replace_csrf` filter to inject CSRF tokens into HTML forms
- **Template Updates**: Modified `help/help_page.html` to support HTML rendering with CSRF protection

## Workflow

### Initial Setup

1. Create OPC UA GDS Push device with:
   - IP address and port
   - OPC UA credentials (user/password)
   - Domain association

2. Issue domain credential:
   - Generates client certificate for authenticating to OPC UA server
   - Private key stays with Trustpoint

3. Associate truststore:
   - Contains server certificate for authentication
   - Can be uploaded or selected from existing truststores

### TrustList Update Workflow

1. User clicks "Update Trustlist" button
2. Service retrieves:
   - Domain credential for client authentication
   - Truststore with CA certificates and CRLs
   - Server certificate for secure connection

3. Service connects to OPC UA server:
   - Uses Basic256Sha256 security policy
   - SignAndEncrypt message security mode
   - Authenticates with domain credential

4. Service updates trustlist:
   - Opens TrustList node
   - Writes CA certificates and CRLs in chunks
   - Closes and applies changes
   - Triggers server-wide ApplyChanges if required

### Server Certificate Update Workflow

1. User clicks "Update Server Certificate" button
2. Service connects to OPC UA server (same as above)

3. CSR-based workflow:
   - Server generates CSR with new private key (CreateSigningRequest)
   - Trustpoint signs CSR with domain's issuing CA
   - Signed certificate uploaded to server (UpdateCertificate)
   - Server applies changes (ApplyChanges if required)

4. Truststore update:
   - New server certificate added to truststore
   - Old server certificates removed
   - Ensures truststore stays synchronized

## Security Considerations

### Authentication & Authorization

- Requires domain credential for client authentication
- Uses OPC UA user credentials (SecurityAdmin role required)
- All operations require POST requests with CSRF protection

### Secure Communication

- TLS/SSL with Basic256Sha256 security policy
- Message-level encryption (SignAndEncrypt)
- Certificate-based mutual authentication

### Certificate Management

- Private keys never leave their origin (server or Trustpoint)
- CSR-based workflow ensures server controls its private key
- Truststore synchronization prevents stale certificates

## Usage

### From UI

1. Navigate to device's Certificate Lifecycle Management
2. Issue domain credential if not already done
3. Associate truststore with server certificate
4. Click "Issue Application Credential" to access GDS Push page
5. Use action buttons to update trustlist or server certificate

### Troubleshooting

Common issues and solutions:

- **"No domain credential found"**: Issue a domain credential first
- **"No truststore configured"**: Associate a truststore with the device
- **"Connection failed"**: Check IP address, port, and OPC UA credentials
- **"Certificate mismatch"**: Update truststore with current server certificate
- **"Security check failed"**: Ensure server trusts the domain CA
- **"Method not supported"**: Server may not support GDS Push

## Technical Notes

### Django Models Used

- `DeviceModel`: OPC UA device configuration
- `IssuedCredentialModel`: Domain and application credentials
- `TruststoreModel`: CA certificates and server certificates
- `OnboardingConfigModel`: Device onboarding configuration

### OPC UA Integration

- Uses `opcua` Python library for client operations
- Implements standard OPC UA node IDs (ns=0;i=2253 for Server object)
- Handles certificate chain workarounds for non-compliant servers

### Dependencies

- `opcua`: OPC UA client library
- `cryptography`: Certificate and CSR handling
- Django models for data persistence

## Future Enhancements

Potential improvements:

1. **Async Operations**: Run GDS Push operations in background tasks
2. **Certificate Monitoring**: Automatic renewal before expiration
3. **Bulk Operations**: Update multiple devices simultaneously
4. **CRL Distribution**: Automatic CRL updates to servers
5. **Status Dashboard**: Real-time view of server certificate status
