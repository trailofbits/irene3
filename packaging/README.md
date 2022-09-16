# irene3 packaging scripts

## How to generate packages

1. Configure and build irene3
2. Set the **DESTDIR** variable to a new folder
3. Run the packaging script, passing the **DESTDIR** folder

Example:

```sh
irene3_version=$(git describe --always)

cpack -D IRENE3_DATA_PATH="/path/to/install/directory" \
      -R ${irene3_version} \
      --config "packaging/main.cmake"
```
