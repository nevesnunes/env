FILES_TO_BUILD = foo.js bar.js baz.js

# dependency list
foo.js = common.js foo-utils.js foo-http.js
bar.js = common.js bar-config.js bar-api.js
baz.js = baz-utils.js baz-auth.js

.SECONDEXPANSION:
${FILES_TO_BUILD}: %: $$(%)
	cat $^ >$@
