#!/bin/bash
# WARNING:
# *** do NOT use TABS for indentation, use SPACES
# *** TABS will cause errors in some linux distributions

if [[ $# < 3 || $# > 4 ]]; then
  echo -e "usage: \n  $0 <ownerpasswd> <ektype> <ekfile>\n or\n  $0 <ownerpasswd> <ektype> <ekfile> verbose"
  exit 2
fi

ownerPasswd=$1
endorsePasswd=$1
ekType=$2 #RSA, ECC
ekFile=$3
verbose=$4 #verbose
ekTypeHex=unknown
tmpFile=/tmp/persistentobject
ekHandle=

case $ekType in
  "RSA") ekTypeHex=0x1;;
  "ECC") ekTypeHex=0x23;;
esac

echo -n "Create EK ($ekType:$ekTypeHex): "
if [[ $ekTypeHex == unknown ]]; then
  echo "failed: unknown type"
  exit 1
fi

function get_next_usable_persistent_handle()
{
  rm -rf $tmpFile
  tpm2_listpersistent > $tmpFile
  if [[ $? != 0 ]];then
    echo "failed: unable to list persistent handles"
    return 1
  fi

  #if [[ $verbose == "verbose" ]]; then
  #  echo
  #  cat $tmpFile
  #fi

  result=`grep -o "0x810100.." $tmpFile`
  #echo $result

  for ((i=0; i<=255; i++))
  do
    j=`printf '%02x\n' $i`
    if [ -z `echo $result | grep -o "0x810100$j"` ]; then
      echo "0x810100$j"
      return 0
    fi
  done

  echo "no usable persistent handle"
  return 1
}

ekHandle=`get_next_usable_persistent_handle`
if [[ $? != 0 ]]; then
  echo "failed: no usable persistent handle"
  exit 1
fi

if [[ $verbose == "verbose" ]]; then
  echo "ekHandle = $ekHandle"
  tpm2_getpubek -e $endorsePasswd -o $ownerPasswd -H $ekHandle -g $ekTypeHex -f $ekFile -X
else
  tpm2_getpubek -e $endorsePasswd -o $ownerPasswd -H $ekHandle -g $ekTypeHex -f $ekFile -X > /dev/null
fi

if [[ $? != 0 ]]; then
  echo "failed"
  exit 1
fi

echo "done. Created @ $ekHandle"
