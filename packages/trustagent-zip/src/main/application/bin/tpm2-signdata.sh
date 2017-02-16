#!/bin/bash
# WARNING:
# *** do NOT use TABS for indentation, use SPACES
# *** TABS will cause errors in some linux distributions

if [[ $# != 5 ]]; then 
    echo "Usage: tpm2-signdata.sh <parenthandle> <in.pub> <in.priv> <in.hash> <out.sig>"
    exit -1
fi

parenthandle=$1
inpub=$2
inpriv=$3
ihash=$4
outsig=$5

tpm2_load -H $parenthandle -u $inpub -r $inpriv -C /tmp/object.context -n /tmp/outputfilename.tmp > /dev/null

if [[ $? != 0 ]]; then 
    echo "Failed to load key"
    exit 1
fi


tpm2_hash -H e -g 0x00B -I $ihash -o /tmp/hash.bin -t /tmp/ticket.bin > /dev/null

if [[ $? != 0 ]]; then 
    echo "Failed to obtain hashed input"
    exit 1
fi


tpm2_sign -c /tmp/object.context -g 0x000b -m $ihash -s $outsig -t /tmp/ticket.bin -X > /dev/null

if [[ $? != 0 ]]; then 
    echo "Failed sign data"
    exit 1
fi

# Here we remove temporal files


exit $?