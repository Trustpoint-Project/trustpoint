# Domains

Domains group devices and certificate settings in Trustpoint.

A domain is associated with one **Issuing CA**. Certificates requested inside the domain are issued by this CA.

## Access

Go to:

`PKI > Domains > select domain > Configure`

## Domain overview

The domain view shows:

- unique domain name
- URL path segment
- device counts
- assigned Issuing CA
- Issuing CA expiry date
- number of issued certificates

## Issuing CA

Each domain uses one Issuing CA for certificate issuance.

The Issuing CA defines the trust anchor used for certificates in this domain. Devices enrolled in the domain receive certificates from this CA.

## DevID registration patterns

DevID registration patterns define which device identities may be onboarded into the domain.

A pattern is linked to a truststore and matches device serial numbers. Matching devices can be onboarded using the domain configuration.

## Domain credential profile

The domain credential profile defines which certificate profile is used for the domain credential.

## Allowed certificate profiles

Allowed certificate profiles define which certificate types devices may request in this domain.

For each profile, the domain can define an alias. The alias is the name used by devices when requesting a certificate.

Profiles that are not enabled for the domain cannot be used for certificate issuance.