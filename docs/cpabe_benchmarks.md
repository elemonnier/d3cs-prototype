# Campagnes cryptographiques CP-ABE

Les campagnes CP-ABE sont séparées des mesures historiques :

- `results/cpabe/cpabe_timings/` : temps des primitives CP-ABE ;
- `results/cpabe/attribute_benchmark/` : cardinalités `[1, 2, 5, 10, 20, 50]` ;
- `results/cpabe/tm_storage/` : tailles des objets et état TM ;
- `results/cpabe/network_sizes/` : tailles sérialisées des messages, sans exécution réseau.

Les commandes de campagne sont exécutées en release :

```bash
cargo test --all-targets
cargo build --release --bins
cargo run --release --bin cpabe_timings
cargo run --release --bin bench_attributes -- --no-plots
cargo run --release --bin tm_storage_sizes
cargo run --release --bin network_sizes
```

`cpabe_timings` conserve 100 warmups et 500 mesures par opération. Les
campagnes par cardinalité utilisent 10 warmups et 100 mesures par défaut.
Les mesures brutes sont conservées, avec moyenne, médiane, écart-type
échantillonal, minimum, maximum et P95 nearest-rank.

Les opérations CP-ABE mesurées sont `Setup`, `KeyGen`, `Delegate`,
`TM_Delegate`, `Encrypt`, `TM_Decrypt` et `Decrypt`. Les objets de référence
utilisés par une même campagne sont générés avec un PP/MSK unique et portent
le même `system_id`.

La politique de l'API possède deux feuilles. Les scénarios `A1 AND A1`
utilisent deux feuilles mais une seule valeur d'attribut distincte ; ils ne
constituent donc pas une mesure de complexité de politique à une feuille.
Les résultats `Encrypt` et `Decrypt` ne doivent pas être interprétés comme une
scalabilité de la politique lorsque le nombre de feuilles reste égal à deux.

Les fichiers de tailles distinguent les octets JSON UTF-8 effectivement
stockés/transmis des octets des champs cryptographiques après décodage Base64.
Les métadonnées de chaque campagne enregistrent le commit Git, l'état du
working tree, le mode release, les dépendances, la plateforme, le processeur,
les warmups, les répétitions, la courbe, la version CP-ABE et le `system_id`.

Les résultats V1 existants ne sont ni supprimés ni écrasés et ne sont pas
comparables directement sans vérifier l'équivalence des paramètres
expérimentaux.
