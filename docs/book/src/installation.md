# Installation

IRENE consists of a Ghidra plugin and docker image. 

## Installing the Docker Image 

`docker load < irene3_latest.tar` will load the image 

## Installing the Ghidra Plugin

Follow the instructions in Ghidra's [documentation for installing plugins](https://ghidra-sre.org/InstallationGuide.html#Extensions) for the file `ghidra_10.3_DEV_<date>_irene-ghidra.zip`

When opening a program you will be asked to configure the, check the box next to `AnvillPatchGraphPlugin`

If in later steps the Anvill graph button is not visible check that this plugin is enabled by selecting `File -> Configure -> Experimental`