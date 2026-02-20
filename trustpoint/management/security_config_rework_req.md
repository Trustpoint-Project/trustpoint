**Rename Security levels:**

- Testing env	--> Lab / Development
- Basic	--> Brownfield Compatible
- Medium	--> Industrial Standard
- High	--> Hardened Production
- Highest	--> Critical Infrastructure

**Lab / Development**

- BasicConstraints ca=True allowed --> allow CA certificate issuance
- maximum cert validity = no limit
- wildcard SAN entries allowed
- KeyUsage unrestricted
- NoOnboardingPkiProtocol allowed for CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
- OnboardingProtocol allowed all
- All RSA and ECC allowed
- Autogen PKI can be anabled
- allow self-signed CAs with credentials
- no maximum CRL validity

**Brownfield Compatible**

- BasicConstraints ca=True not allowed --> allow CA certificate issuance
- maximum cert validity = 1825 (5y)
- wildcard SAN entries allowed
- NoOnboardingPkiProtocol allowed for CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
- OnboardingProtocol allowed all
- RSA ≥ 1024
- Autogen PKI can be anabled
- allow self-signed CAs with credentials
- maximum CRL validity: 365 days

**Industrial Standard**

- BasicConstraints ca=True not allowed
- maximum cert validity = 365
- wildcard SAN entries allowed
- NoOnboardingPkiProtocol allowed for CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
- OnboardingProtocol allowed all
- ECC ≥ 256 
- RSA ≥ 3096
- do not allow self-signed CAs with credentials
- maximum CRL validity: 180 days

**Hardened Production**

- BasicConstraints ca=True not allowed
- maximum cert validity = 365
- NoOnboardingPkiProtocol allowed for CMP_SHARED_SECRET, EST_USERNAME_PASSWORD
- OnboardingProtocol allowed all but not MANUAL
- ECC ≥ 256 
- RSA ≥ 4096
- do not allow self-signed CAs with credentials
- maximum CRL validity: 90 days

**Critical Infrastructure**

- BasicConstraints ca=True not allowed
- KeyStorageConfig must be PHYSICAL_HSM
- NoOnboardingConfigModel not allowed
- maximum cert validity = 180
- NoOnboardingPkiProtocol allowed for CMP_SHARED_SECRET, EST_USERNAME_PASSWORD
- OnboardingProtocol allowed all but not MANUAL
- ECC ≥ 384
- No RSA
- do not allow self-signed CAs with credentials
- maximum CRL validity: 90 days

