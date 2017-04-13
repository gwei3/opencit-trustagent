#!/bin/bash
# WARNING:
# *** do NOT use TABS for indentation, use SPACES
# *** TABS will cause errors in some linux distributions

if [[ $# != 5 ]]; then
    echo "Usage: tpm2-signdata.sh <parenthandle> <in.pub> <in.priv> <in.contentfile> <out.sig>"
    exit -1
fi

parenthandle=$1
inpub=$2
inpriv=$3
icontent=$4
outsig=$5

if [ -f /tmp/object.context ]; then
  rm /tmp/object.context
fi
if [ -f /tmp/outputfilename.tmp ]; then
  rm /tmp/outputfilename.tmp
fi
tpm2_load -H $parenthandle -u $inpub -r $inpriv -C /tmp/object.context -n /tmp/outputfilename.tmp > /dev/null
if [[ $? != 0 ]]; then
    echo "Failed to load key"
    exit 1
fi

if [ -f $outsig ]; then
  rm $outsig
fi
if [ -f /tmp/signdata.out ]; then
  rm /tmp/signdata.out
fi
tpm2_sign -c /tmp/object.context -g 0x000B -m $icontent -s /tmp/signdata.out -X > /dev/null
if [[ $? != 0 ]]; then
    echo "Failed to sign data"
    exit 1
fi
#parse tcg structure to obtain signature with length 256
dd bs=1 skip=6 if=/tmp/signdata.out of=$outsig
if [[ $? != 0 ]]; then
    echo "Failed to read signature"
    exit 1
fi

exit $?
