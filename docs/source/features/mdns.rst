.. _mdns:

=================================
Trustpoint mDNS Responder Service
=================================

The Trustpoint Docker deployment can be augmented by an additional container, which advertises the Trustpoint service to the link-local network via mDNS/zeroconf.
This allows devices to discover the Trustpoint service without prior configuration, facilitating zero-touch (AOKI) onboarding and management in local network environments.

Advertised Services
-------------------

The mDNS Responder container advertises the following services:

**_aoki._tcp.local.**
    This service type is used for the AOKI onboarding process, allowing devices to discover Trustpoint as the AOKI Owner Service on the local network.  

**_https._tcp.local.**
    This generic service type is used for the HTTPS management interface of the Trustpoint server, allowing discovery of the Admin interface and Trustpoint REST API.  

**_trustpoint._tcp.local.**
    This custom service type is used for discovering the Trustpoint instance specifically.  

Additionally, the mDNS Responder also advertises its primary IPv4 address under the hostname ``trustpoint.local``, allowing local clients to resolve the Trustpoint server's address via mDNS.
The primary IP address is determined by the default interface with public Internet connectivity, or the first non-loopback network interface as a fallback for offline environments.

Starting the mDNS Responder Container
-------------------------------------

.. admonition:: Supported environments
   :class: tip

   Due to NAT constraints, the mDNS Responder Docker container is only supported on Linux hosts. It relies on the host's network stack to broadcast mDNS advertisements, which is not feasible in Docker Desktop environments due to limitations in Docker's networking capabilities.
   If you require mDNS functionality on non-Linux hosts, consider using a standard mDNS responder implementation for your host machine.


To build and start the lightweight mDNS Responder container, use the following terminal command in the root trustpoint directory:

.. code-block:: bash

    docker compose -f docker-compose.mdns.yml up -d
