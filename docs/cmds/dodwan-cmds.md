## Lancement d'instance DoDWAN

cd src/network/tools/dodwan
export DODWAN_HOME="$PWD"

node_id=DODWAN_TEST ./bin/dodwan.sh start

cat /run/shm/$USER/dodwan/var/node/DODWAN_TEST/ports
node_id=DODWAN_TEST ./bin/dodwan.sh console 

node_id=N00 ./bin/dodwan.sh console 
"d g st" pour afficher les peers connus

node_id=DODWAN_TEST ./bin/dodwan.sh stop 

## Lancement d'instance DoDWAN-NAPI puis commandes de base

cd src/network/tools/dodwan
export DODWAN_HOME="$PWD"

node_id=DODWAN_NAPI \
dodwan_plugins=dodwan-napi,dodwan-napi-ws \
jvm_opts="-Ddodwan_napi_ws.port=18090 -Ddodwan_napi_ws.serial_method=json" \
./bin/dodwan.sh start

cat /run/shm/$USER/dodwan/var/node/DODWAN_NAPI/ports 
--> affiche 18090

tail -f /run/shm/$USER/dodwan/var/node/DODWAN_NAPI/log/DODWAN_NAPI_202
6-05-05-15-31.log

websocat -b ws://127.0.0.1:18090/dodwan-cli

{"name":"ping","tkn":"t1"}

{"name":"add_sub","tkn":"t2","key":"sub-d3cs","desc":{"topic":"d3cs"}}

{"name":"publish","tkn":"t3","desc":{"topic":"d3cs","src":"cli2"},"dummy":1}



node_id=DODWAN_NAPI ./bin/dodwan.sh stop 


websocat -b ws://127.0.0.1:18090/cli1

{"name":"add_sub","tkn":"t2a","key":"sub-d3cs-cli1","desc":{"topic":"tm1"}}

websocat -b ws://127.0.0.1:18090/cli2

{"name":"add_sub","tkn":"t2b","key":"sub-d3cs-cli2","desc":{"topic":"tm2"}}



{"name":"publish","tkn":"t4","desc":{"topic":"tm1","src":"cli"},"dummy":1}

{"name":"publish","tkn":"t4","desc":{"topic":"tm2","src":"cli"},"dummy":1}



