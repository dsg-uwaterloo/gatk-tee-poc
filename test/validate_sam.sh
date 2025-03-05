#!/bin/bash

version="4.6.1.0"
if [ ! -f gatk-${version}.zip ]; then
	rm -rf gatk-${version}
	wget https://github.com/broadinstitute/gatk/releases/download/${version}/gatk-${version}.zip
fi

if [ ! -d gatk-${version} ]; then
	unzip gatk-${version}.zip
fi

cd gatk-${version}
./gatk ValidateSamFile -I ../NA12878.bam -M SUMMARY > ../results/result.txt 2>&1