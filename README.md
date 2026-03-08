# Zero-Trust Access Proxy (ZTAP)

## 1. Project Overview

The **Zero-Trust Access Proxy (ZTAP)** is a security enforcement node designed to eliminate "implicit trust" within a network. In traditional setups, once an attacker breaches the perimeter, they can move laterally (East-West traffic) because internal services trust each other by default.

ZTAP solves this by implementing an **Identity-Aware Proxy (IAP)**. It intercepts all traffic to microservices, requiring every request to carry a cryptographically signed, short-lived identity token.

---

## 2. System Architecture

The architecture follows a distributed gateway pattern where the ZTAP acts as the single point of entry for a cluster of services.

* **Client:** A user or service requesting access (must support mTLS).
* **ZTAP Proxy :** The high-performance engine that handles TLS termination, authentication, and request forwarding.
* **Identity Provider (IdP) / Verification Component:** Validates JWTs or OIDC tokens.
* **Redis Store:** A high-speed cache for session blacklists, rate-limiting, and short-lived token metadata.
* **Certificate Authority (CA):** Manages the issuance of internal certificates for mTLS.
* **Internal Microservices:** Services that only listen for connections encrypted with the CA’s certificates.

---

## 3. Request Flow

Every request undergoes a rigorous verification pipeline before reaching a microservice:

1. **mTLS Handshake:** The client presents a certificate. ZTAP validates it against the internal CA.
2. **Authentication:** ZTAP extracts the `Authorization: Bearer <token>` header. It checks the token’s signature.
3. **Session Lookup:** ZTAP queries **Redis** to ensure the token hasn't been revoked or expired globally.
4. **Device Posture Check:** The proxy evaluates device signals (sent via headers or mTLS extensions) to ensure the device is compliant.
5. **RBAC Authorization:** The Policy Engine checks if the "Role" inside the token has the "Permission" for the specific `METHOD` and `PATH`.
6. **Secure Forwarding:** ZTAP initiates a new mTLS connection to the backend microservice and forwards the sanitized request.

---

## 4. Security Model

Our model relies on the **"Never Trust, Always Verify"** mantra:

* **Short-lived Tokens:** Tokens expire every 15–60 minutes to minimize the window for stolen credentials.
* **mTLS Everywhere:** Both "Client-to-Proxy" and "Proxy-to-Service" are encrypted with Mutual TLS, ensuring the identity of the machine itself.
* **Least Privilege:** Users are only granted the specific scopes (e.g., `read:intel`) required for their mission.

---

## 5. Device Posture Checking Extension

Access is not just about *who* you are, but *what* you are using. ZTAP checks:

* **Disk Encryption:** Verified via an endpoint agent signal.
* **OS Patch Level:** Rejects requests from outdated, vulnerable kernels.
* **Device Identity:** The client certificate must be stored in a hardware TPM (Trusted Platform Module).
* **Signal Integration:** If the "Compliance Header" is missing or reports `status=unhealthy`, ZTAP returns a `403 Forbidden`.

---

## 6. Implementation Roadmap

* **Phase 1: Core Proxy:** Build the Go server capable of basic HTTP forwarding and Dockerization.
* **Phase 2: Identity Validation:** Integrate JWT parsing and signature verification.
* **Phase 3: RBAC Policies:** Implement the logic to map roles to specific API endpoints.
* **Phase 4: mTLS Integration:** Configure Go's `tls.Config` to require client certificates.
* **Phase 5: Redis Integration:** Add session revocation and rate-limiting using Redis.
* **Phase 6: Device Posture:** Implement header-based posture verification and "Emergency Lockdown" triggers.

---

## 7. Deployment Architecture

ZTAP is deployed as a **Gateway** at the edge of a service cluster.

* **Networking:** The microservices reside on an isolated Docker network. They *only* accept traffic from the ZTAP container IP.
* **Service Registration:** New services are added to the ZTAP configuration file, mapping public paths (e.g., `/api/v1/mission`) to internal gRPC/HTTP addresses.

---

## 8. Future Improvements

* **SPIFFE/SPIRE:** For automated, short-lived workload identities instead of static mTLS certs.
* **Hardware-Backed Identity:** Requiring YubiKey or TPM-resident keys for all administrative access.
* **AI Anomaly Detection:** Monitoring request patterns to detect "credential stuffing" or "data exfiltration" attempts in real-time.
