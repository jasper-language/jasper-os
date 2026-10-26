# Contributors

Jasper OS is directed and maintained by **Dark Magician**, with implementation,
review, verification, and integration work contributed by several coding agents.
The repository keeps each commit's original author identity.

- **Dark Magician** — project creator and maintainer; product direction,
  architecture decisions, milestone definitions, and acceptance decisions.
- **Claude** — architecture and interface design, milestone decomposition,
  concurrency/lock-order/authority/failure-path review, debugging analysis,
  and implementation review. The existing Git history does not carry a
  distinct, stable Claude author label, so this record does not invent a
  commit range for Claude or reassign another contributor's commits.
- **OpenAI Codex** — commits recorded as `chatgpt`; BM-1 integration and boot
  acceptance; KRN-1/KRN-2/KRN-3 scheduler work; FV/ENV verification;
  EVT-1/EVT-2, SHM-1, ABI-R, S-3, and RT-1/RT-2/RT-3 implementation,
  modelling, regression, and integration; and public-branch release checks.
- **DeepSeek** — commits recorded as both `DSH Agent` and `DeepSeek`; the M1
  through M5 kernel and userspace foundation; memory and object/handle models;
  Ring and IPC; multi-ISA ports; SCHED/SMP/POL scheduler mechanisms; devices,
  interrupts, hardening, and acceptance infrastructure; x86 BM-1 boot support;
  S-2 multicore syscall fuzzing and fault-path audits; and PDA/AArch64 tooling
  and validation.
- **Jasper language tooling** — commits recorded as `jasper-language`;
  specification and formal-verification support shared with the Jasper
  language project.

GitHub's Contributors page is derived from commits reachable from the default
branch and associates them with GitHub accounts by verified author email.
Several agent commits use local or service-only author addresses, so GitHub may
show them without a profile or omit them from the profile list. This file is
the project-level attribution record; the Git history remains the detailed
record of individual changes.
