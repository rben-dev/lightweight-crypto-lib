#!/bin/bash

main_dir="./"

clean_dirs=($main_dir)

echo "Cleaning the project ..."
make clean &> /dev/null
echo "Cleaning AUTOCONF files ..."
rm -rf autom4te.cache config.log config.status configure 
echo "Cleaning Makefiles ..."
for (( i = 0 ; i < ${#clean_dirs[*]} ; i++ ))
do
  rm -f ${clean_dirs[i]}/Makefile
done
