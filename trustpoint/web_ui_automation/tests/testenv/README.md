# Web UI Automation Test Setup

This setup uses **Nginx Proxy Manager** as a local test target for Trustpoint Web UI automation. It provides a browser-based login, custom certificate upload, certificate assignment, and an HTTPS endpoint for fingerprint verification.

## 1. Start Nginx Proxy Manager

Start the container:

```bash
docker compose up -d
```

Open the management interface:

```text
http://127.0.0.1:8181
```

Complete the initial account setup in the Web UI.

## 2. Start a Test Backend

Run a simple local HTTP server:

```bash
python3 -m http.server 9000
```

## 3. Configure the Test Hostname

Add the following entry to `/etc/hosts`:

```text
127.0.0.1 webui-test.local
```

## 4. Create a Proxy Host

In Nginx Proxy Manager, create a proxy host with:

```text
Domain: webui-test.local
Scheme: http
Forward hostname: host.docker.internal
Forward port: 9000
```

The HTTPS test endpoint will be:

```text
https://webui-test.local:8443
```

## 5. Upload a Trustpoint Certificate

In Nginx Proxy Manager:

1. Open **SSL Certificates**.
2. Select **Add SSL Certificate**.
3. Select **Custom**.
4. Upload the Trustpoint-issued PEM certificate.
5. Upload the matching PEM private key.
6. Save the certificate.
7. Assign it to the `webui-test.local` proxy host.

## 6. Configure Trustpoint

Create a Web UI automation device with:

```text
Base URL: https://webui-test.local:8443
Authentication: Form-based login
```

The fingerprint verification step checks the configured HTTPS base URL itself, so the base URL must point at the live certificate endpoint that is expected to serve the renewed certificate.

Assign a JSON automation profile that:

1. Logs in.
2. Opens the SSL certificate section.
3. Uploads the PEM certificate and private key.
4. Saves the certificate.
5. Assigns it to the proxy host.
6. Verifies the certificate fingerprint on the same HTTPS endpoint (`https://webui-test.local:8443`).
