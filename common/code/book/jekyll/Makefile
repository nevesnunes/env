.POSIX:

SHELL := /bin/bash

assets-obj := $(shell test -d ./assets/ && \
	find ./assets/ -type f -exec file -i {} \; | \
	grep -i image | \
	cut -d':' -f1)
assets-timestamp-obj := $(assets-obj:%=timestamps/%.timestamp)
timestamps/%.timestamp: $(assets-obj)
	mkdir -p "$(shell dirname $@)" && \
	ect \
		-6 \
		-strip \
		--allfilters \
		--mt-deflate=2 \
		--pal_sort=30 \
		--strict \
		$* && \
	touch $@

gem_dir := $(shell realpath ~/.gem)/jekyll-local
gem_bin_dir := $(shell find "$(gem_dir)" -path '*/bin' ! -path '*/gems/*')
jekyll-obj := \
	$(gem_bin_dir)/jekyll \
	$(gem_bin_dir)/kramdown \
	$(gem_bin_dir)/rougify
$(jekyll-obj):
	mkdir -p $(gem_dir)
	env BUNDLE_GEMFILE=Gemfile.local bundle install --path=$(gem_dir)
dependencies: $(jekyll-obj) $(assets-timestamp-obj)

all: dependencies
	env BUNDLE_GEMFILE=Gemfile.local bundle exec jekyll serve --port 4010

.DEFAULT_GOAL := all
.PHONY: all dependencies
