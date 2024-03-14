# Command Line Tool Usage

Command line tools for irene can be accessed through the docker container. The easiest way to access the command line tools is through mounting an interactive docker session. 

`docker run -it --entrypoint=/bin/bash -v $(pwd)/wdir irene3` will launch an irene3 container with the current directory mounted to wdir.

After launching a docker container the follow commands should produce help output:
- `irene3-lift`
- `irene3-lower`
- `irene3-examine-spec`
-  `irene3-decompile`
-  `python -m patch_assembler.assembler`