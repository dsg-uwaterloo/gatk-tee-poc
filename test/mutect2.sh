#!/bin/bash

version="4.6.1.0"
if [ ! -f gatk-${version}.zip ]; then
	rm -rf gatk-${version}
	wget https://github.com/broadinstitute/gatk/releases/download/${version}/gatk-${version}.zip
fi

if [ ! -d gatk-${version} ]; then
	echo "Unzipping gatk" > ../results/out.txt
	time unzip gatk-${version}.zip > ../results/out.txt
fi

cd gatk-${version}
# ALLOW ADDITIONAL MEMORY DEPENDING ON HOW MUCH RAM VMS HAVE
./gatk --java-options "-Xmx16G" Mutect2 -R ../hg38_genomic.fasta -I ../hg38_exome_chr21.cram -O ../results/hg38_exome_chr21.vcf.gz > ../results/result.txt 2>&1
