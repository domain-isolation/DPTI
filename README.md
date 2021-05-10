# DPTI
DPTI is an approach that provides software-defined memory protection for security domains without relying on specific hardware features. It consists of two variants, one providing only read-only protection (DPTI-Freeze) while the other entirely eliminates all access to the protected domain (DPTI-Stash). We demonstrate our approach in two use cases: 
  1. extended syscall filtering, enabling deep argument filtering which is not possible with Linux Seccomp
  2. isolating a potentially malicious SGX enclave from the rest of the system, inverting the classical SGX threat model.

## Warnings
**Warning #1**: We are providing this code as-is. You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. This code may cause unexpected and undesirable behavior to occur on your machine.

**Warning #2**: This code is only a proof-of-concept and developed for testing purposes. Do not run it on any productive systems. Do not run it on any system that might be used by another person or entity.
