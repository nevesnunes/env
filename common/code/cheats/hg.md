# bisect

```bash
# Validation: is there any in progress?
hg log -r 'bisect(current)'

# Start
hg bisect --good 606848e8adfc
hg bisect --bad tip
# Testing changeset 192456:d2e7bd70dd95 (1663 changesets remaining, ~10 tests)
# abort: uncommitted changes
hg checkout d2e7bd70dd95

# After bisection process done
hg bisect --reset
hg checkout tip
# If required
hg unshelve
# Optional but customary
hg pull -u
```

- https://utcc.utoronto.ca/~cks/space/blog/programming/FirefoxBisectNotes
