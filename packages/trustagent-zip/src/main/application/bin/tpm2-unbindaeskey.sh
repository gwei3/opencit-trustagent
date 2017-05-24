#!/bin/bash
# WARNING:
# *** do NOT use TABS for indentation, use SPACES
# *** TABS will cause errors in some linux distributions


if [[ $# > 2 || $# < 1 ]]; then
  echo -e "usage: \n  $0 <encryptedInFile> <plainTextOutFile>\n"
  exit 2
fi

#These are always generated with tpm2_load
loadOutput=/tmp/binding.tmp
loadContext=/tmp/binding.context
inFile=$1
outFile=$2
tmpOutFile=/tmp/unbind.tmp
pubFile=/opt/trustagent/configuration/bindingkey.pub
privFile=/opt/trustagent/configuration/bindingkey.blob

if [ -f "$loadContext" ];then
  rm -f $loadContext
fi 
if [ -f "$loadOutput" ];then
  rm -f $loadOutput
fi 
if [ -f "$tmpOutFile" ]; then
  rm -f $tmpOutFile
fi
#Binding key needed to decrypt needs to be loaded to the TPM first.
#echo "Loading Binding key to TPM..."
#ToDo:Change Handle to parameter instead of being hardcoded
tpm2_load -H 0x81000000 -u $pubFile -r $privFile -C $loadContext -n $loadOutput > /dev/null

#echo "Decrypting secret key..."
if [ -f "$outFile" ];then
  rm -f $outFile
fi 
#outFile contains the decrypted key in plain text
if [ -z $outFile ]; then
  tpm2_rsadecrypt -c $loadContext -I $inFile -o $tmpOutFile > /dev/null
  errCode=$?
  if [ $errCode -eq 0 ]; then
    cat $tmpOutFile 
  fi
  exit $errCode
else
  tpm2_rsadecrypt -c $loadContext -I $inFile -o $outFile > /dev/null
fi
