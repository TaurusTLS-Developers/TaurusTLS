# High-Level Test Plan: State Machine Unit-Testing (SM-UT)

## 1. Objectives
The objective of this test suite is to validate the correctness of the transition logic, the robustness of the API guards, and the exception-safety boundaries of the `TTaurusTLSBaseSocket` state engine. These tests run purely in-memory, verifying the logic boundaries statically without executing actual cryptographic handshakes or network operations.

## 2. Test Scope & Exclusions
*   **In Scope**: State transition validity matrix (7x7), redundant transition guards, state-gated API guards (I/O and negotiation), and allocation-free (OOM-immune) transition execution.
*   **Out of Scope**: Cryptographic handshakes, cert validation, ECH key negotiation, and network-level transport. No raw socket bindings or `SSL_connect` loops are executed in this suite.

## 3. Test Components and Mocking Strategy

### 3.1. Mock Configuration and Context Sockets
Since we are only validating state transitions, we do not require a fully initialized OpenSSL context or physical socket descriptors.
*   **`TTaurusTLSMockSocketConfig`**: Inherits from `TTaurusTLSCustomSocketConfig`. Binds event listeners to track `OnStateChange` and `OnDebug` events.
*   **`TTaurusTLSMockSocket`**: A lightweight descendant of `TTaurusTLSBaseSocket` that overrides the abstract `DoHandshake` with a simple stub.

---

## 4. Test Methods & Scenarios

### 4.1. Transition Validity Matrix Verification
*   **Method**: Systematically loop through all 49 possible state transitions (7 current states $\times$ 7 target states).
*   **Verification**:
    1.  All valid transitions (e.g., `seIdle` $\rightarrow$ `seInitialized`) must complete successfully and fire the `OnStateChange` event with correct state parameters.
    2.  All invalid transitions (e.g., `seIdle` $\rightarrow$ `seClosing` or `seClosed` $\rightarrow$ `seHandshaking`) must fail immediately, raising an `ETaurusTLSInvalidTransition` exception.

### 4.2. Redundant Transition Guard Testing
*   **Method**: Attempt to transition the socket to the state it is already in (e.g., transitioning from `seHandshaking` to `seHandshaking`).
*   **Verification**:
    1.  The state engine must exit the transition method early without executing any state modification side effects.
    2.  The `OnDebug` event must be triggered, logging a redundant transition warning.

### 4.3. State-Gated API Guard Testing (Negative Testing)
*   **Method**: Attempt to execute standard I/O or protocol operations when the socket is in an invalid state for that operation.
*   **Verification**:
    1.  Calling `Recv` or `Send` when in any state other than `seEstablished` must immediately raise an `ETaurusTLSSocketStateError`.
    2.  Calling `ProcessSSL` when in any state other than `seHandshaking` or `seClosing` must immediately raise an `ETaurusTLSSocketStateError`.

### 4.4. Allocation-Free & OOM-Immunity Verification
*   **Method**: Execute 10,000 rapid state transitions on the mock socket and monitor the application's heap allocation profile.
*   **Verification**:
    1.  Verify that heap allocations during transitions remain at zero. This validates that transitioning states uses no dynamic memory allocation, proving the state machine is immune to Out-of-Memory (OOM) failures during transitions.
