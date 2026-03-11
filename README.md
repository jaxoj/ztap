# Zero-Trust Access Proxy (ZTAP)

## 1. Project Overview

The **Zero-Trust Access Proxy (ZTAP)** is a security enforcement node designed to eliminate "implicit trust" within a network. In traditional setups, once an attacker breaches the perimeter, they can move laterally (East-West traffic) because internal services trust each other by default.

ZTAP solves this by implementing an **Identity-Aware Proxy (IAP)** written in high-performance Go. It intercepts all traffic to microservices, requiring every request to carry a cryptographically signed, short-lived identity token, while dynamically routing traffic using pre-compiled Regular Expressions.

---

## 2. Getting Started & Installation

To run ZTAP locally, you will need to generate cryptographic keys, configure your routing policies, and spin up the isolated container network.

### Prerequisites

* **Docker & Docker Compose** (for the isolated network and Redis cache)
* **Go 1.24+** (to run the JWT generator tool)
* **OpenSSL** (to generate the mTLS certificates and RSA keys)

### Step 1: Clone and Prepare the Environment

```bash
git clone https://github.com/jaxoj/ztap.git
cd ztap
mkdir certs

```

### Step 2: Generate Cryptographic Materials

Because ZTAP operates on a "Zero-Trust" model, it requires rigorous cryptographic proofs. You must generate the following files and place them in the `/certs` directory:

1. **Internal CA (`ca.crt`, `ca.key`)**: To sign all internal certificates.
2. **Proxy mTLS Certs (`ztap_server.crt`, `ztap_server.key`)**: For the proxy to prove its identity to backends.
3. **IdP RSA Keys (`idp_private.pem`, `idp_public.pem`)**: To sign and verify JWT authorization tokens.

*Crucial Security Step (Linux/macOS):* Ensure the Docker container's non-root user can read these files:

```bash
chmod 644 certs/*
chmod 755 certs/

```

### Step 3: Define Routing Policies

Create a `policies.yaml` file in working directory to map RBAC roles to your backend microservices:

```yaml
rules:
  - role: "commander"
    path: "^/api/v1/launch$"
    methods: ["POST"]
    backend: "https://your-backend-service:8443"

```

### Step 4: Boot the Fortress

Start the proxy and its stateful Redis cache using Docker Compose:

```bash
docker-compose up --build -d

```

Check the logs to confirm the engine is running and successfully connected to Redis:

```bash
docker-compose logs -f proxy-gateway
# Expected Output: [Info] Proxy listening on :443

```

### Step 5: Generate a Token and Test

Use the included CLI tool to generate a cryptographically valid, short-lived session token:

```bash
go run scripts/generate_token.go -role="commander"

```

Test the mTLS connection and Layer 7 authorization (replace `<YOUR_TOKEN>` with the generated JWT):

```bash
curl -v \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -X POST https://localhost/api/v1/launch

```

---

## 3. System Architecture

The architecture follows a decoupled, distributed gateway pattern. ZTAP acts as the single, hardened point of entry for a cluster of independent microservices.

* **Client:** A user or service requesting access.
* **ZTAP Proxy:** The high-performance engine that handles TLS termination, RSA cryptographic validation, dynamic regex routing, and mTLS request forwarding.
* **Identity Provider (IdP):** Issues RSA-signed JWTs. ZTAP only holds the Public Key to mathematically verify signatures offline.
* **Redis Store:** A stateful, ultra-fast, in-memory cache used for instant session revocation (checking JWT `jti` claims against a blacklist).
* **Certificate Authority (CA):** Manages the issuance of internal certificates to ensure absolute cryptographic trust.
* **Internal Microservices:** Completely decoupled backends that *only* listen for connections encrypted with the internal CA’s certificates.

---

## 4. Request Flow & Dynamic Routing

Every request undergoes a rigorous, microsecond-optimized verification pipeline before reaching a microservice:

1. **Authentication (Layer 7):** ZTAP extracts the `Authorization: Bearer <token>` header and mathematically verifies the RSA signature using the IdP's Public Key.
2. **Stateful Session Lookup:** ZTAP queries **Redis** to ensure the specific token ID (`jti`) hasn't been revoked by an administrator.
3. **Regex-Powered RBAC Authorization:** The Policy Engine compares the token's "Role" against a YAML-defined Routing Table. It uses pre-compiled Regex state machines to match dynamic URL paths (e.g., `^/api/v1/drones/.*$`).
4. **Context Injection:** If authorized, the engine injects the target backend URL into the HTTP Context.
5. **Secure Forwarding (Layer 4 mTLS):** The Reverse Proxy Director reads the target from context, initiates a strict TLS 1.3 mTLS connection to the backend microservice, proves its identity via its own client certificate, and forwards the sanitized request.

---

## 5. Security Model

Our model relies on the **"Never Trust, Always Verify"** mantra:

* **Cryptographic Paranoia:** TLS 1.3 is strictly enforced. The proxy explicitly drops connections to backends presenting untrusted or self-signed certificates.
* **Stateless Validation:** Because JWTs are validated via RSA public keys in memory, the proxy does not need to make latent network calls to an IdP for every request.
* **Immutable Multi-Stage Containers:** Production ZTAP deployments are built using Docker multi-stage builds. The final Alpine container contains **no source code**, no Go compiler, and runs as a restricted, non-root user.
* **Separation of Concerns:** ZTAP is deployed entirely decoupled from the microservices it protects. Microservice engineering teams manage their own deployments, while Security Administrators update ZTAP's `policies.yaml` to govern access.

---

## 6. Scaling for Large Military Infrastructure

ZTAP is designed to scale horizontally to protect massive, distributed environments.

* **The Phalanx Pattern (Load Balancing):** Multiple ZTAP container replicas can sit behind a Layer 4 Network Load Balancer (NLB). Go's lightweight goroutines allow a single instance to handle tens of thousands of concurrent mTLS connections.
* **Redis Clustering:** A distributed Redis cluster ensures that if a commander revokes a compromised token, the blacklist propagates globally in milliseconds, and all ZTAP replicas instantly drop the attacker.
* **Service Mesh Evolution:** For hyper-classified environments, ZTAP can be compiled into a minimal binary and deployed as a **Sidecar Proxy**.

In this topology, East-West traffic between microservices (e.g., Intel Service to Missile Service) is routed through their respective ZTAP sidecars, ensuring Zero-Trust even if the internal network is fully compromised.

---

## 7. Implementation Roadmap

* **[DONE] Phase 1: Core Proxy:** Build the Go server capable of HTTP forwarding.
* **[DONE] Phase 2: Identity Validation:** Integrate JWT parsing and RSA-256 signature verification.
* **[DONE] Phase 3: Dynamic RBAC Policies:** Implement Regex-based path matching and dynamic backend routing via YAML.
* **[DONE] Phase 4: mTLS Integration:** Configure Go's `tls.Config` for mutual authentication and connection pooling.
* **[DONE] Phase 5: Redis Integration:** Add stateful session revocation.
* **[DONE] Phase 6: Containerization:** Implement secure, multi-stage Dockerfiles and isolated Docker Compose networks.
* **[PENDING] Phase 7: Device Posture:** Implement header-based posture verification (disk encryption, patch levels) and "Emergency Lockdown" triggers.
* **[PENDING] Phase 8: Telemetry:** Integrate Prometheus metrics to monitor denial rates and unauthorized access attempts.

---

## 8. Future Improvements

* **SPIFFE/SPIRE:** Transitioning from static `.crt` / `.key` files to automated, short-lived workload identities for the mTLS layer.
* **Hardware-Backed Identity:** Requiring YubiKey or TPM-resident keys for all `commander` level access.
* **AI Anomaly Detection:** Monitoring request frequency to detect "credential stuffing" or "data exfiltration" attempts in real-time.

---