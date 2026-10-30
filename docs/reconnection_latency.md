# Expérience de déconnexion temporaire et de livraison après reconnexion

Le script `scripts/reconnection_latency.py` orchestre une topologie réelle à
deux nœuds : `U1` (N01) et `Authority` (N00). LEPTON est démarré avec un
scénario DGS dynamique qui supprime (`de`) puis recrée (`ae`, statut
`CONNECTED`) l’arête `N00-N01`; DoDWAN et les processus Rust D3CS restent
actifs pendant la coupure.

Le message est produit par le workflow réel `POST /api/encrypt` de `U1`.
Après le chiffrement, l'API appelle `NetworkRuntime::ask_for_sharing`, qui
émet une trame `CT_SHARE` vers le topic `TM`. La réception n'est considérée
réussie qu'après l'événement Rust `receive` et la présence du ciphertext et de
la signature dans le stockage de `Authority`. Le contenu et la signature
stockés sont comparés à ceux de la source. Aucune requête d'émission n'est
faite après la reconnexion.

La métrique principale est :

`delivery_ms = t_receive_observed - t_reconnect_confirmed`

Les deux instants de calcul sont mesurés avec `time.monotonic_ns()` dans
l'orchestrateur. `t_disconnect` est l’instant où les deux vues de voisinage
DoDWAN ne contiennent plus l’autre nœud. `t_reconnect_confirmed` est l’instant
d’observation par l’orchestrateur de l’événement LEPTON `EDGE_ADDED`; la
présence des deux voisins DoDWAN est ensuite vérifiée séparément. Les
horodatages UTC sont conservés pour la traçabilité. La console TCP LEPTON
accepte une connexion dans l’environnement inspecté mais ne traite pas
correctement les commandes; elle n’est donc pas utilisée.

Par défaut, la campagne effectue 10 répétitions, avec une coupure de 30 s et
un timeout de 60 s après reconnexion. Le calendrier DGS ajoute une marge de
garde de 2 s entre la durée demandée et la recréation de l’arête, afin de
compenser le délai d’observation de la coupure par les vues DoDWAN; la durée
effective mesurée est toujours celle exportée dans le CSV. Le message clair
fixe contient 1 KiB de `D`, mais le délai mesuré commence après la confirmation
de reconnexion et ne comprend donc pas le chiffrement ni l’indisponibilité.

Commandes :

```bash
python3 scripts/test_reconnection_latency.py
python3 scripts/reconnection_latency.py --short
python3 scripts/reconnection_latency.py --repetitions 10 --outage-seconds 30 --timeout-seconds 60
```

Les résultats sont écrits dans `benchmark_results/reconnection_latency/` :

- `reconnection_raw.csv` : une ligne par répétition, avec les états, les
  horodatages UTC, les compteurs monotones et le statut ;
- `reconnection_summary.csv` : statistiques des seuls succès, avec écart-type
  empirique (`n-1`) et P95 par rang le plus proche ;
- `reconnection_errors.csv` : échecs et motifs ;
- `reconnection_delivery.svg` : graphique SVG des succès et de leur médiane.

Cette expérience est distincte de la campagne multi-sauts : elle mesure la
livraison différée après restauration d'une liaison unique. Elle ne démontre
pas à elle seule le transport store-carry-forward multi-sauts. Dans
l'implémentation actuelle, `CT_SHARE` est une diffusion vers le topic `TM` et
non une adresse applicative arbitraire `U1 -> U2`; `Authority` est donc le
second nœud observé dans ce scénario.

La validation courte a réussi (1/1) dans l’environnement courant. La campagne
complète a également réussi (10/10) et est conservée dans
`benchmark_results/reconnection_latency/`. Pour cette campagne, la durée
effective de coupure observée est comprise entre 30 368,1 et 31 248,4 ms; le
délai de livraison après l’événement LEPTON a une moyenne de 1 462,596 ms,
une médiane de 1 419,926 ms et un écart-type empirique de 150,127 ms. Les
répertoires `reconnection_latency_short*` antérieurs sont des journaux de
diagnostic et ne constituent pas des résultats scientifiques.
