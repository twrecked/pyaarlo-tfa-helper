# pyaarlo-tfa-helper

Helper web services and utilities for [pyaarlo](https://github.com/twrecked/pyaarlo) and [hass-aarlo](https://github.com/twrecked/hass-aarlo).

Hosted on Google App Engine at `https://pyaarlo-tfa.appspot.com`.

---

## Components

### 1. Log Encryption Service (`google-app-engine/default/`) — *Active*

Provides a web interface and API for users to encrypt debug logs before pasting them into public GitHub issues.

* **Web UI:** `https://pyaarlo-tfa.appspot.com/` (or `/enc`)
* **API Endpoint:** `POST https://pyaarlo-tfa.appspot.com/encrypt`
* **How It Works:**
  * Uses a hybrid encryption scheme: generates a random AES-128 key to encrypt the payload via AES-EAX (authenticated encryption), then encrypts the AES key using an RSA-2048 public key via PKCS1_OAEP.
  * Encapsulates the output in a safe `v2` JSON envelope (base64-encoded) between standard delimiters:
    ```text
    -----BEGIN PYAARLO DUMP-----
    ...
    -----END PYAARLO DUMP-----
    ```
  * Only maintainers holding the private RSA key (`rsa.private`) can decrypt the dump using `pyaarlo decrypt`.
* **CLI Utility:** `bin/pyaarlo-encrypt.in` provides a `curl` pipeline for streaming logs directly to the endpoint.

#### Local Development & Testing
```bash
cd google-app-engine/default
pip install -r requirements.txt
python main.py
```

#### Deployment to Google App Engine
Deploy to a new timestamped version without promoting:
```bash
cd google-app-engine/default
gcloud app deploy app.yaml --version v$(date +%Y%m%dt%H%M) --no-promote
```
After testing the version-specific URL (`https://<VERSION>-dot-pyaarlo-tfa.appspot.com/`), promote it:
```bash
gcloud app services set-traffic default --splits <VERSION>=1
```

---

### 2. Postfix Mail Forwarder (`postfix/`) — *Deprecated*

* **Status:** Deprecated.
* **Original Purpose:** A mail pipe script (`pyaarlo-fwd.in`) designed to accept incoming Arlo verification emails from a local Postfix MTA and POST them to the Datastore bridge (`/mail`).
* **Replacement:** Users configure `pyaarlo` / `hass-aarlo` to check TFA codes directly via IMAP using an account App Password.

---

### 3. Google OAuth Helper (`google-app-engine/google-auth/`) — *Deprecated*

* **Status:** Deprecated.
* **Original Purpose:** An App Engine microservice designed to handle Gmail OAuth 2.0 authorization codes and exchange refresh tokens without exposing client secrets in the open-source client.
* **Deprecation Reason:** Google classifies `gmail.readonly` as a Restricted Scope requiring costly annual third-party CASA security audits for public verification.
* **Replacement:** Use Gmail App Passwords with standard IMAP, or native Home Assistant Application Credentials where users supply their own developer keys directly in Home Assistant.

---

## License

See [LICENSE](LICENSE) for details.
