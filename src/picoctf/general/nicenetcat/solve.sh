nc mercury.picoctf.net 22902 > data

# loop through the file, convert each line to ascii and print it out
while read ln; do printf " $(printf %x $ln)"; done < data
