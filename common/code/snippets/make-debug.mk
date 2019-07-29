# Usage:
# make -f ~/lib/debug.mk p-SHELL
p-%:
	@echo "$(strip $($*))" | tr ' ' \\n
