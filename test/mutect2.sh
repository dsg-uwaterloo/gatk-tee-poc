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
./gatk Mutect2 -R ../hg38_genomic.fasta -I ../hg38_exome_chr21small.cram -O ../results/single_sample.vcf.gz > ../results/result.txt 2>&1
./gatk ValidateSamFile -I ../NA12878.bam -M SUMMARY > ../results/result.txt 2>&1