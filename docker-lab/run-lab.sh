#!/bin/sh
printf '%s\n' '=== Linux Hardener lab image ==='
printf '%s\n' 'This container intentionally contains weak SSH settings.'
printf '%s\n' 'Run the host tool against a VM for full remediation tests.'
grep -Ei 'PermitRootLogin|PermitEmptyPasswords' /etc/ssh/sshd_config || true
