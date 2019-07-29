# Usage:
# cd /tmp; make -f ~/lib/metarule.mk P=out/%.js T=out/foo/bar.js

match: $(T)

$(P):
	@echo '$$@ == $@'
	@echo '$$* == $*'
