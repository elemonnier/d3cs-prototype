--> A adapter, vu le changement d'architecture vers dodwan-napi


A présent, j'ai besoin de relier le fonctionnement de mon IHM à Lepton. 
La liste de connected nodes à droite de l'IHM ne vont dépendre uniquement de Lepton.
J'ai besoin in fine que je puisse lancer un nouveau script "cargo run -- lepton" qui me lance lepton via la commande "src/network/tools/lepton/bin/lepton.sh start" et qui me récupère la liste de tous les noeuds connectés au noeud courant. Le noeud courant est l'identité issue du sign up, le mapping ci-dessous permet 
Pour récupérer les noeuds connectés, on se servira de OppNet.getNeighbors(currentNodeId, null, null).
La fréquence de refresh des noeuds sera de 1 seconde. 
Le script démarre également le cluster applicatif.
On vérifiera qu'il n'y a pas d'instance de Lepton qui tourne, et l'arrêt du script assure le bon arrêt de Lepton.
De plus, lorsque l'on lance ce script, on ne pourra plus switcher Net1-Net2 comme avant, c'est seulement Lepton qui va indiquer les noeuds connectés. Les boutons Net1-Net2 seront invisibles (les boutons sont masqués). L'endpoint de changement de Network (Net1-Net2) ne sera pas appelé dans ce mode.
Net1-Net2 restera fonctionnel avec network-all.

Le mapping est le suivant (process <-> Lepton) : 
Authority (127.0.0.1:18080) <-> Authority
u1 (127.0.0.1:18081) <-> U1|FR-DR:M1
u2 (:18082) <-> U2|FR-S:M1
u3 (:18083) <-> U3|FR-DR:M2
u4 (:18084) <-> U4|FR-S:M2
u5 (:18085) <-> U5|FR-DR:M1
u6 (:18086) <-> U6|FR-S:M1
u7 (:18087) <-> U7|FR-DR:M2
u8 (:18088) <-> U8|FR-S:M2
u9 (:18089) <-> U9|FR-DR:M1



De plus, j'aimerais que le noeud sur Lepton n'apparaisse seulement si on a fait Sign up depuis l'IHM. Cela implique que lorsque l'on va démarrer le programme, on n'aura que l'autorité de présente.



