# Running Evaluation

The syntax for `docker_runner.sh` is `./docker_runner.sh <number of test cases> <output directory> <additional flags>`

For example `./docker_runner.sh 50 $(mktemp -d)` will create a temporary directory with 50 test cases of ARM binaries. 


`./docker_runner.sh 50 $(mktemp -d) -mthumb` will instead test thumb encoded functions. The docker image for these scripts can be built from the root 
directory (../) with the command `docker build . -f eval.Dockerfile -t eval

The same command above can then be run with `docker run -v <target_out_dir>:/out eval 50 /out -mthumb` 