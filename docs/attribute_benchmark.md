# Campagne cryptographique par nombre d'attributs

Le binaire `bench_attributes` est autonome : il importe directement
`src/crypto/abs.rs` et `src/crypto/cpabe.rs`, sans démarrer LEPTON, DoDWAN,
WebSocket, serveur HTTP ou autre composant réseau.

## Exécution

```bash
cargo run --release --bin bench_attributes
cargo run --release --bin bench_attributes -- --quick
cargo run --release --bin bench_attributes -- --only abs-user-set --warmups 10 --measurements 100
```

Les valeurs par défaut sont 10 échauffements et 100 mesures. `--quick` utilise
1 échauffement et 3 mesures pour une validation rapide. Les paramètres peuvent
être changés avec `--warmups` et `--measurements` sans modifier le code.

La sortie CP-ABE par défaut est `results/cpabe/attribute_benchmark/` :

- `timings_raw.csv` conserve chaque mesure valide en nanosecondes ;
- `timings_summary.csv` contient moyenne, médiane, écart-type, minimum,
  maximum et P95 en millisecondes ;
- `sizes.csv` contient les tailles JSON UTF-8 sérialisées en octets ;
- `errors.csv` contient les configurations non représentables et les erreurs,
  sans mesure remplacée par zéro ;
- `metadata.json` enregistre le protocole, Rust, la cible et la révision Git ;
- `timings_medians.svg` et `sizes.svg` sont générés en Rust.

L'écart-type est l'écart-type empirique avec dénominateur `n-1`. Le P95 est le
percentile nearest-rank de rang `ceil(0.95 * n)`. Les préparations, la
sérialisation des exports, les écritures de fichiers et les communications ne
sont jamais dans les chronométrages. `std::hint::black_box` protège les
résultats retournés par les appels répétés.

## Variables contrôlées

Les cardinalités demandées sont toujours `[1, 2, 5, 10, 20, 50]`. Les
paramètres publics sont générés une fois par primitive et réutilisés. Le
message CP-ABE est une chaîne UTF-8 fixe de 1024 octets ; le message ABS et la
clé ABS restent fixes dans les configurations compatibles.

- Expérience A : `extract`, `sign`, `verify` pour un ensemble utilisateur ABS.
- Expérience B : `sign`, `verify` pour un prédicat ABS mobilisant N attributs.
- Expérience C : `encrypt`, `decrypt` pour la politique CP-ABE à deux feuilles.
- Expérience D : `keygen`, `delegate`, `tm_delegate`, `decrypt` et
  `tm_decrypt` pour les clés CP-ABE.

Les CSV CP-ABE ajoutent explicitement `user_attributes`, `delegated_attributes` et
`policy_leaves`. Dans C, la politique possède toujours deux feuilles. Dans D,
`keygen` varie le nombre d'attributs utilisateur, `delegate` et `tm_delegate`
varient le nombre d'attributs délégués à partir d'une clé source de 50
attributs, et `decrypt`/`tm_decrypt` utilisent la politique `A1 AND A1`.

## Limites démontrées par les API

L'ABS actuel fixe `d=1`. `extract` accepte un seul attribut, la clé
`AbsUserKeyV1` porte un seul attribut, et `sign` ne construit pas de prédicat
multi-attribut. A et B sont donc mesurables uniquement pour `N=1`; les autres
configurations sont inscrites dans `errors.csv`.

Le CP-ABE actuel accepte une `DocumentLabel` à deux feuilles et `decrypt`
reconstruit explicitement les feuilles d'indices 1 et 2. C est donc compatible
uniquement avec `N=2` (`A1 AND A2`). Pour D, le test d'une politique fixe à un
seul attribut distinct utilise `A1 AND A1`, représentation compatible de
l'API : deux feuilles sont présentes, mais une seule valeur d'attribut est
requise. Cette convention permet de mesurer aussi `N=1` pour `decrypt`.

`tm_delegate` reçoit seulement `PSKA` et `TK`, et `tm_decrypt` reçoit
`Ciphertext` et `PSKA`; aucune de ces fonctions ne parcourt un ensemble
d'attributs. Dans D, N décrit donc la préparation par `keygen`/`delegate`.
`PSKA`, `TK`, `tm_delegate` et `tm_decrypt` restent structurellement constants
en taille et leur coût propre ne doit pas être interprété comme une dépendance
cryptographique directe à N.

Les autres exports CP-ABE sont produits par :

- `cpabe_timings` : `results/cpabe/cpabe_timings/` ;
- `tm_storage_sizes` : `results/cpabe/tm_storage/` ;
- `network_sizes` : `results/cpabe/network_sizes/`.

Les résultats historiques sous `results/` et `results/attribute_benchmark/`
ne sont pas écrasés. Les tailles d'objets distinguent la taille JSON UTF-8
effectivement stockée/transmise de la somme des champs cryptographiques
Base64 décodés. Cette seconde valeur exclut les métadonnées telles que
`system_id`, les versions et les noms d'attributs.
