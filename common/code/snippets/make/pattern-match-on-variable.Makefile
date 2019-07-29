# In order to use pattern matches on sources that are variables,
# we declare a target variable to use as source of other targets, 
# but need to repeat the match pattern as a target for
# the former sources
assets-obj := $(shell find ./assets/ -type f -exec file -i {} \; | \
	grep -i image | \
	cut -d':' -f1)
assets-timestamp-obj := $(assets-obj:%=timestamps/%.timestamp)
timestamps/%.timestamp: $(assets-obj)
