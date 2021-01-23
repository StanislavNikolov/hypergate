#!/bin/bash

# handshake packet. prot_ver=754, next_state=1, hostlen=9, hostname=localhost
data="\x10\x00\xf2\x05\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01"

#printf "$data" | nc localhost 25565 -N
printf "$data" | pv -L 5 -q | nc localhost 25565 -N
#printf "$data" | pv -L 2
#printf "this is sloow" | pv -L 5 -q
