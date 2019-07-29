#!/usr/bin/env bash

artifacts=( \
    "com.sun.jersey:jersey-client:1\f19\f1" \
    "com.validatedid:ViDDelegatedSignatureAPI:1\f0\f0"
)
artifact_paths=()
for i in "${artifacts[@]}"; do
   artifact_unescaped=$(echo "$i" | sed 's/\\f/\./g')
   artifact_paths+=($(echo "$i" | tr '[.:]' '/' | sed 's/\\f/\./g'))
   mvn org.apache.maven.plugins:maven-dependency-plugin:2.1:get \
       -DrepoUrl=http://nexus.foo.com/nexus/content/groups/public/ \
       -Dartifact=$artifact_unescaped
done
7z a dependencies.zip "${artifact_paths[@]}"
