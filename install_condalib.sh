#!/bin/bash

# enter conda env
source ~/miniconda3/etc/profile.d/conda.sh
conda activate edr

# force install libs in requirements.txt
for i in $(cat requirements.txt); do conda install $i -y; done;