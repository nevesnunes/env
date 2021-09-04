# running

```bash
# Working directory hierarchy:
# ~/code/wip/javawip
# ├── build
# │   ├── classes
# │   │   └── java
# │   │       └── main
# │   │           └── javawip
# │   │               ├── App.class
# │   │               └── FormLargestNum.class
# [...]
# ├── build.gradle
# ├── gradlew
# ├── gradlew.bat
# ├── settings.gradle
# [...]
./gradlew -PmainClassNameProperty=javawip.FormLargestNum run
# ||
gradle -PmainClassNameProperty=javawip.FormLargestNum run
```

### ignore tasks

1. look for plugin names
    ```
    subprojects {
      apply plugin: "license"
      ...
    }
    ```
2. apply exclusion to subproject
    ```bash
    ./gradlew :foo-sub-project:build -x test -x license
    ```

# testing

```bash
# `--info`: include stdout
./gradlew :foo-sub-project:test --info --tests com.foo.TestFoo
```
