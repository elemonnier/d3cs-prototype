Les trames dodwan-napi client -> DoDWAN sont :
publish : permet de publier une trame/message composée de descriptor + payload
add_sub : permet d'ajouter à la liste des abonnements un pattern de descriptor (pour une destination tm2 donnée, ne renseigner que "topic":d3cs et "dst":tm2)
remove_sub : permet de retirer un abonnement de la liste
get_desc : renvoie le descripteur complet en fonction d'un mid (message id), d'un message du cache
get_payload : renvoie le champ data en fonction d'un mid provenant du cache
get_matching : renvoie les mid présents dans le cache de dodwan en fonction de souscriptions (utile lorsqu'un message est resté dans le cache avant que 2 noeuds se rencontrent)
get_peers : renvoie la liste des voisins du noeud courant
get_my_peer : permet de renvoyer le pid (peer id) du noeud courant
ping : permet de savoir si la connexion entre le backend Rust et NAPI est fonctionnelle

Les réponses DoDWAN -> client sont :
recv_desc : envoie le descripteur, soit suite à un get_desc, soit en cas de réception d'un message correspondant à l'abonnement
recv_payload : renvoie une payload suite à un get_payload
recv_mids : renvoie les mids des messages dans le cache
recv_pids : renvoie les pids des noeuds voisins
recv_my_pid : renvoie le pid du noeud courant
add_peer : notification envoyée par DoDWAN lorsqu'un nouveau voisin apparaît
remove_peer : notification envoyée par DoDWAN lorsqu'un nouveau voisin disparaît
clear_peers : réinitialise la liste des voisins
ok : réponse générique d'acceptation
error : réponse générique de refus

