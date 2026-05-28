J'aimerais que tu me crées un nouveau fichier dans src/bin appelé timings.rs qui permet de mesurer le temps d'exécution de certaines fonctions crypto. Le temps d'exécution sera mesuré directement dans le script. On devra pouvoir le lancer avec cargo run --bin timings --release.
L'objectif est que, lorsque je lance ce script, tu me mesure le temps d'exécution de certaines fonctions crypto d'abs.rs, cpabe.rs et mod.rs.
Fonctions où le temps doit être mesuré :
- abs : setup() -> pas de donnée d'entrée
- abs : extract() -> tester avec l'output de setup() et l'attribut "FR-DR"
- abs : sign() -> tester avec l'output d'extract() et le message "test"
- abs : verify_with_attr() -> tester avec l'output de sign() avec l'attribut "FR-DR"
- cpabe : setup() -> pas de donnée d'entrée
- cpabe : keygen() -> prendre outputs précédents et les attributs "FR-DR" et "M1"
- cpabe : delegate() -> prendre outputs précédents et les attributs "FR-DR" et "M1"
- cpabe : tm_delegate() -> a besoin de pska_in venant du keygen et de tk venant du delegate
- cpabe : encrypt() -> prendre outputs précédents, label.classification à "FR-DR" et label.mission à "M1", message "test" 
- cpabe : tm_decrypt() -> prends les outputs précédents (la PSKA du keygen)
- cpabe : decrypt() -> prends l'output précédent (la PSKS du keygen)
- mod.rs : revoke_missions(), devant être mesuré de bout en bout -> prendre la mission "M1" en input, et l'AppState suivant :
  - host : D3CS_HOST
  - port : 8080
  - config_dir : D3CS_CONFIG_DIR
  - users_dir : D3CS_USERS_DIR
  - tm_dir : D3CS_TM_DIR
  - authority_dir : D3CS_AUTHORITY_DIR
  - ihm_dir : D3CS_IHM_DIR
  - mode : Local
  - user_db : authority (voir s'il faut préciser authority / FR-S/M1 / is_authority_user=true)
  - sessions : map vide
  - pending_revocations : liste vide
  - network_runtime : None
Pour cette fonction, l'ARL doit être présente dans tm_dir

J'ai besoin d'avoir une seule itération, avec le temps en microsecondes

Forme du résultat : nom_fonction : executed in X us

Les mesures doivent être faites en mode release