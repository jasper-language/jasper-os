# LC-2 cancelable external update Agent wait

Command:

```text
ISSUE21_UEFI_MODE=update-agent \
ISSUE21_UEFI_TIMEOUT=120 \
ISSUE21_QEMU_CPUS=14-15 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=update-agent qemu_rc=33
```

The serial log records the complete cancellation path:

```text
system.async.ring.deadline.enter ret=system.async.error.timed_out
system.async.cancel ret=0
system.async.ring.enter ret=0
JSR-UPDATE-AGENT timeout=true after_timeout=true ok=true
first_program state=Some(Exited { code: 0 }) reclaimed=true
```

The external Agent client now submits Channel receive work through the async
ring. On timeout it cancels the request, reaps the cancelled completion and
closes any handles that raced with delivery. Responses that complete after the
caller has cancelled are discarded rather than returned to a later request.
The next request succeeds, proving no stale success or poisoned reply stream.
