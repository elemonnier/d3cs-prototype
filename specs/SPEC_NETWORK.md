Récit implémentation D3CS en réseau


Prompt : 
You must implement the network mode of the D3CS prototype.

The implementation must follow the specifications contained in the following files:

- specs/SPEC_NETWORK.md (main specification to implement)
- specs/SPEC_LOCAL.md (previous specification, the new implementation must remain compatible with it)
- specs/SLIDES_LAYOUT.md (contains acceptance criteria for the demo)
- the 8 sequence diagrams describing protocol flows (in diagrams/)

The system already contains a cryptographic implementation.
You must NOT reimplement the crypto primitives.
Instead, adapt the protocol requests so they correctly call the existing crypto code.

The project also relies on DoDWAN for opportunistic networking.
You must integrate with the existing DoDWAN code and respect its API and behavior.

Important constraints:

1. Do not break existing functionality implemented for SPEC_LOCAL.
2. Reuse the existing crypto modules instead of rewriting them.
3. Implement the protocol messages defined in SPEC_NETWORK:
   KEY_REQUEST
   DELEGATE_ACCEPT
   ASK_DELEGATION
   KEY_RESPONSE
   CT_SHARE
   REVOKE
   ARL_UPDATE
   SYNCHRONIZE
   PSKA_SYNC
4. Respect the message format defined in the spec:
   D3CS | src | dst | request | args...
5. Integrate the Network Manager functions:
   join
   subscribe
   send
   sendSecured
   publish
   publishSecured
   onRcv
6. Respect the opportunistic connectivity model (Net1/Net2 groups).
7. Ensure the acceptance criteria described in SLIDES_LAYOUT.md are satisfied.

Before writing code:
- analyze the repository structure
- identify existing crypto modules
- identify DoDWAN integration points
- determine which components are missing

Then implement only the missing parts required for network mode.

Do not simplify the architecture.
Do not remove existing code.
Only extend the system to support the new specification.



Arborescence
Reprendre l'arborescence actuelle et ajouter dans le dossier racine : 
network/
- main.rs : intÃ¨gre les fonctions
- frames.rs : intÃ¨gre les requÃªtes protocolaires
- netmanager.rs : intÃ¨gre les fonctions du network manager
- dodwan/ : dossier recopiant tous les fichiers dodwan depuis le lien de téléchargement https://casa-irisa.univ-ubs.fr/dodwan/download.html 




Changements majeurs : 
- Utiliser pubsub via Dodwan : utile si tous les nÅ“uds ne sont pas intéressés par tout (par exemple, TM1 n'a pas besoin de la PSKA de TM3 / un TM n'a pas besoin d'un chiffré non accessible par l'utilisateur correspondant â€“ il y a juste l'ARL Ã  correctement répliquer)
- Un processus = un acteur complet et indépendant. 10 processus applicatifs, runnant une IHM sur son port. Autorité = port 18080, U1 = 18081, U2 = 18082, U3 = 18083, U4 = 18084, U5 = 18085, U6 = 18086, U7 = 18087, U8 = 18088, U9 = 18089. Toutes les instances tournent en localhost sur la mÃªme machine. 1 démon DoDWAN global.
- L'autorité est relié Ã  TM0, l'utilisateur 1 Ã  TM1, et caetera jusqu'Ã  l'utilisateur 9 et TM9
- Possibilité aux utilisateurs et Ã  l'autorité d'aller dans des Â« groupes » d'interconnexion Net1 & Net2.

Changements mineurs Ã  réaliser sur le projet : 
- Changer les fonctions Rust de démarrage de programme. SPEC1.md (déjÃ  codé) en "cargo run -- local" et SPEC2.md en "cargo run -- network" 
- Pour les 4 objectifs, rendre l'affichage de l'IHM plus Â« grand » pour un enregistrement vidéo (je suis sur un navigateur 1920x1080. 
- Enlever l'interface de révocation pour l'objectif 2 sur le panel admin : l'admin recevra une notification de délégation 
- Dans tout le code, refactor le Â« LK11 » en Â« LK10 » pour le papier de Li-Kim car je m'étais trompé d'année.
- Changer le mot de passe admin en Â« minad » 
- Renommer ihm/ par gui/
- Renommer le projet racine en d3cs-prototype
- Déplacer le fichier d3cs-prototype/src/authority/mod.rs dans d3cs-prototype/authority/. Supprimer le dossier d3cs-prototype/src/authority/ également.




Trames D3CS (de la forme 1|2|3|4|5...) : 
- 1er champ : protocole (D3CS)
- 2e champ : émetteur (TM, user ou autorité)
- 3e champ : topic destinataire (e.g., TM pour l'ensemble des TMs, TMx pour TM précis, Ux pour utilisateur précis)
- 4e champ : requÃªte
- 5e Ã  niÃ¨me champs : arguments de la requÃªte (facultatif en fonction des requÃªtes)
- Encapsulation possible dans une trame TLS


Liste des fonctions protocolaires ou "messages", Ã  coder dans network/frames.rs : 
- KEY_REQUEST. Input: liste d'attributs de classification et de mission. Est émis d'un nouvel utilisateur souhaitant récupérer ses clés, et Ã  destination de l'autorité ou d'un autre tuple TM-user en cas de délégation.
- DELEGATE_ACCEPT. Input: aucun. Est émis d'un TM acceptant d'émettre une délégation (delegator) vers un TM souhaitant recevoir une délégation (delegatee). 
- ASK_DELEGATION. Input: attributs. Est émis du nouvel utilisateur/TM vers l'utilisateur/TM délégateurs. 
- KEY_RESPONSE. Input: dépend du destinataire et de la fonction utilisée. A destination d'un TM, les clés transmises sont la clé privée PM23 cÃ´té autorité (PSKA) et les paramÃ¨tres publics ABS (params). A destination d'un utilisateur lors de KeyGen, la clé privée PM23 utilisateur (PSKS), le paramÃ¨tre public PM23 (PP) et la clé privée ABS (skw) sont transmises. Lors d'une délégation, skw n'est pas transmise.
- CT_SHARE. Input: chiffré CT. Emis par un TM Ã  destination de tous les autres TMs accessibles (dans le mÃªme réseau de connectivité)
- REVOKE. Input: attribut de mission. Emis par un TM vers TM0.
- ARL_UPDATE. Input: ARL. Emis par TM0 Ã  destination de tous les TMs accessibles.
- SYNCHRONIZE. Input: liste de PSKA et liste de CT. Emis d'un TM vers l'ensemble des autres TMs, dans le but de synchroniser les deux listes.
- PSKA_SYNC. Input: PSKA_diff. Emis d'un TM possédant une liste de PSKA différente de celle transmise dans le SYNCHRONIZE. Le destinataire est l'émetteur du SYNCHRONIZE.


Fonctions de TM/utilisateur/autorité, Ã  coder dans network/main.rs : 
- checkARL(attribute) -> bool. Vérification de l'ARL avant chiffrement/déchiffrement. Envoie True si l'attribut figure l'ARL (et envoyer message d'erreur Ã  l'utilisateur), sinon renvoyer False et continuer le process.
- delegationCheck(PSKA[], attributes) -> bool. Vérification si les attributs demandés constituent un subset de ce qu'il y a dans les PSKA[].
- store(data) -> void. Stockage sécurisé de la donnée. Dans la démo, stocker simplement la data dans le répertoire correspondant selon SPEC_LOCAL (e.g., clé, chiffré, etc.).
- write() -> message. Ecriture d'un message (String) par l'utilisateur. 
- chooseLabel() -> label. Choix d'un label (attribut de classification et de mission) par l'utilisateur.
- bind(message, label) -> bind. Concaténation sécurisée du message avec le label associé. Dans la démo, faire une simple concaténation du String.
- appendARL(ARL, mission) -> void. Mise Ã  jour de l'ARL (ajout d'une ligne), selon l'attribut de mission correspondant.
- updateARL(newARL) -> void. Remplacement de l'ancienne ARL par newARL.
- setupARL() -> void. Initialisation de la structure de l'ARL.
- setupStorage() -> void. Initialisation du stockage du TM (structure pour accueillir PSKA, ARL, chiffrés).
- setupPresets() -> void. Initialisation des 4 presets Bell-LaPadula et Biba.
- updatePSKA(PSKA_diff, storage) -> void. Mise Ã  jour du stockage des PSKA en fonction de PSKA_diff.
- getClassificationAttribute(PSKA) -> attribute. Récupération de l'attribut de classification en fonction d'une PSKA associée.


Fonctions de transfert utilisées dans les diagrammes. Il n'y a pas de description car ce n'est que du transfert. A coder dans network/main.rs :
- askForDecryption(CT) -> void
- transfer(^CT) -> void
- newUser(clearance) -> void
- askUserDelegate() -> void
- send(TK) -> void
- askForSharing(CT) -> void
- askRevocation(mission) -> void
- newUserAlert(PSKA) -> void


Fonctions crypto : déjÃ  implémentées par le biais de SPEC_LOCAL



Fonctions réseau autour du Network Manager, Ã  coder dans main/netmanager.rs :
- join() : équivalent du connect(), qui est nécessaire avant de démarrer un abonnement
- subscribe(topic) : abonnement Ã  un topic (e.g., TM) ou sous-topic spécifique relatif Ã  une entité (e.g., TM1, U5, Authority)
- send(frame) : envoi d'un utilisateur, autorité ou d'un TM un message au NM signalant qu'un publish doit Ãªtre fait. Format : send(A, B, C-Z), A étant le destinataire, B la requÃªte et C-Z les différents arguments, étant facultatifs en fonction de la requÃªte, concaténés Ã  la future trame.
- sendSecured(frame) : équivalent sécurisé de send, pour indiquer au NM le transport d'éléments sensibles (e.g., clés, ARL)
- publish(frame) : publication d'un message ainsi que ses arguments sur le DTN opportuniste. Forme: publish(D3CS, A, B, C, D-Z) pour A l'émetteur, B destinataire, C requÃªte, et D-Z les arguments (facultatifs en fonction de la requÃªte)
- publishSecured(frame) : équivalent sécurisé de publish via utilisation de D3CS over TLS pour la génération de la trame
- onRcv(frame) : transmission du message reÃ§u du NM vers le noeud de destination présent dans la trame (e.g., si TM alors envoi au TM associé, si Ux alors envoi Ã  l'utilisateur associé). Forme : onRcv(A, B, C-Z) avec A émetteur de la requÃªte, B nom de la requÃªte et C-Z arguments facultatifs en fonction de la requÃªte.







CritÃ¨res d'acceptation :
- Doit respecter le fichier SLIDES_LAYOUT.md dans le répertoire courant
- on peut voir son espace de connectivité Net1/Net2 sur son panel (admin ou user) et on peut le changer avec un bouton directement sur le panel

## CritÃ¨res d'acceptation â€” mode `network`

> Interprétation de `SLIDES_LAYOUT.md` : l'acceptation porte sur les capacités démontrées et les comportements observables, pas sur l'identité exacte des acteurs utilisés pendant la démo.
>
> Méthode de validation : chaque item doit Ãªtre vérifiable par effet observable cÃ´té IHM et/ou par observation des trames D3CS, sans dépendre de logs applicatifs.
>
> Hors périmÃ¨tre de cette checklist : renommages internes, mot de passe admin, refactors de nommage, déplacements de fichiers purement structurels.

### Compatibilité et lancement

- [ ] Le projet démarre toujours en mode local via `cargo run -- local`.
- [ ] Le projet démarre en mode réseau via `cargo run -- network`.
- [ ] Le mode `network` reste compatible avec les comportements crypto et de stockage déjÃ  couverts par `SPEC_LOCAL`.

### Topologie réseau et exécution

- [ ] Le mode `network` exécute 10 processus applicatifs indépendants : `Authority`, `U1`, `U2`, `U3`, `U4`, `U5`, `U6`, `U7`, `U8`, `U9`.
- [ ] Les ports exposés sont fixés ainsi : `Authority=18080`, `U1=18081`, `U2=18082`, `U3=18083`, `U4=18084`, `U5=18085`, `U6=18086`, `U7=18087`, `U8=18088`, `U9=18089`.
- [ ] Un unique démon DoDWAN global est utilisé pour l'ensemble des processus.
- [ ] Le couplage logique est respecté : `Authority <-> TM0`, `Ux <-> TMx`.

### IHM et ergonomie de démo

- [ ] Sur une fenÃªtre navigateur en `1920x1080`, les écrans utiles Ã  la démo sont lisibles sans scroll vertical ni horizontal.
- [ ] L'IHM maximise la surface utile visible pour permettre de suivre clairement les actions pendant l'enregistrement.
- [ ] Le groupe de connectivité courant (`Net1` ou `Net2`) est visible directement sur le panel utilisateur et sur le panel admin.
- [ ] Le changement de groupe de connectivité est possible directement depuis le panel, sans manipulation externe.
- [ ] Les éléments non autorisés ou révoqués peuvent Ãªtre simplement non visibles ; un affichage grisé n'est pas exigé sauf cas explicitement demandé.
- [ ] Aucun texte d'erreur exact n'est imposé ; seul le refus backend effectif est obligatoire.

### Connectivité opportuniste

- [ ] Tout utilisateur et l'autorité peuvent basculer entre `Net1` et `Net2`.
- [ ] Aucun groupe de connectivité initial n'est figé comme critÃ¨re d'acceptation.
- [ ] Une bascule de `Net1` vers `Net2` ou inversement prend effet immédiatement.
- [ ] Aucun message applicatif ne peut traverser `Net1 -> Net2` ou `Net2 -> Net1`.
- [ ] Une autorité est considérée comme joignable si elle appartient au mÃªme groupe de connectivité que le requÃªteur d'accÃ¨s.

### Network Manager

- [ ] `join()` connecte un nÅ“ud au démon DoDWAN avant tout abonnement ou échange.
- [ ] `subscribe(topic)` permet l'abonnement Ã  un topic global (`TM`) ou Ã  un sous-topic d'entité (`TMx`, `Ux`, `Authority`).
- [ ] `send(frame)` transmet au Network Manager une demande de publication D3CS non sécurisée.
- [ ] `sendSecured(frame)` transmet au Network Manager une demande de publication D3CS sécurisée.
- [ ] `publish(frame)` publie une trame D3CS correctement formée sur le réseau opportuniste.
- [ ] `publishSecured(frame)` publie l'équivalent sécurisé de `publish(frame)` via transport protégé.
- [ ] `onRcv(frame)` route correctement la requÃªte vers le bon destinataire applicatif (`TM`, `Ux`, `Authority`).
- [ ] Les échanges D3CS restent suffisamment distincts et structurés pour Ãªtre inspectables ultérieurement au niveau réseau.

### Format des trames D3CS

- [ ] Toute trame D3CS respecte l'ordre des champs : `protocole | émetteur | topic destinataire | requÃªte | arguments...`.
- [ ] Le premier champ vaut `D3CS`.
- [ ] Le troisiÃ¨me champ permet l'adressage par topic global ou spécifique (`TM`, `TMx`, `Ux`, `Authority`).
- [ ] Les arguments sont facultatifs et présents uniquement si requis par la requÃªte.
- [ ] Toute trame transportant des données sensibles passe par le chemin sécurisé (`sendSecured` / `publishSecured`).

### Messages protocolaires

- [ ] `KEY_REQUEST` est implémenté et transporte la liste d'attributs demandés.
- [ ] `DELEGATE_ACCEPT` est implémenté sans argument.
- [ ] `ASK_DELEGATION` est implémenté et transporte les attributs demandés.
- [ ] `KEY_RESPONSE` est implémenté avec contenu variable selon le destinataire :
  - vers un utilisateur lors d'un `KeyGen` : `PP`, `PSKS`, `skw`
  - vers un utilisateur lors d'une délégation : `PP`, `PSKS`
  - vers un TM : `params`, `PSKA`
  - vers un utilisateur lors d'une resynchronisation autorité : `skw` seul
- [ ] `CT_SHARE` est implémenté et transporte un chiffré `CT`.
- [ ] `REVOKE` est implémenté et transporte un attribut de mission.
- [ ] `ARL_UPDATE` est implémenté et transporte l'ARL courante.
- [ ] `SYNCHRONIZE` est implémenté ; pour la démo, l'acceptation explicite porte au minimum sur la convergence des `PSKA`.
- [ ] `PSKA_SYNC` est implémenté et retourne le différentiel de `PSKA` Ã  l'émetteur du `SYNCHRONIZE`.

### RÃ¨gles de sécurisation des échanges

- [ ] Tout échange contenant des clés, dérivés de clés, `PSKA`, `PSKS`, `PP`, `params`, `skw`, `ARL`, `TK`, ou toute donnée sensible équivalente passe par le transport sécurisé.
- [ ] Les requÃªtes `KEY_REQUEST`, `DELEGATE_ACCEPT`, `ASK_DELEGATION`, `KEY_RESPONSE`, `REVOKE`, `ARL_UPDATE`, `SYNCHRONIZE` et `PSKA_SYNC` utilisent un transport sécurisé dÃ¨s lors qu'elles embarquent des données sensibles.
- [ ] `CT_SHARE` peut rester non sécurisé si le chiffré est considéré publiable dans la démo.

### Fonctions métier â€” validation unitaire observable

- [ ] `checkARL(attribute)` bloque le chiffrement ou le déchiffrement si l'attribut de mission figure dans l'ARL.
- [ ] `delegationCheck(PSKA[], attributes)` n'accepte qu'une demande dont les attributs sont un sous-ensemble des attributs disponibles cÃ´té délégateur.
- [ ] `store(data)` stocke les artefacts attendus ; la simple présence des données au bon endroit suffit comme preuve d'acceptation.
- [ ] `write()` permet Ã  l'utilisateur de saisir un message Ã  chiffrer.
- [ ] `chooseLabel()` permet Ã  l'utilisateur de choisir un label autorisé.
- [ ] `bind(message, label)` concatÃ¨ne correctement le message et son label pour la démo.
- [ ] `appendARL(ARL, mission)` ajoute l'attribut révoqué Ã  l'ARL.
- [ ] `updateARL(newARL)` remplace l'ARL locale par la nouvelle.
- [ ] `setupARL()` initialise correctement la structure d'ARL.
- [ ] `setupStorage()` initialise correctement le stockage local.
- [ ] `setupPresets()` initialise correctement les presets Bell-LaPadula et Biba.
- [ ] `updatePSKA(PSKA_diff, storage)` intÃ¨gre correctement les `PSKA` manquantes au stockage.
- [ ] `getClassificationAttribute(PSKA)` permet Ã  l'autorité de retrouver l'attribut de classification nécessaire Ã  la dérivation de `skw`.

### Fonctions de transfert et d'orchestration

- [ ] `askForDecryption(CT)` déclenche la chaÃ®ne de déchiffrement cÃ´té TM.
- [ ] `transfer(^CT)` transfÃ¨re au client le résultat intermédiaire de déchiffrement produit par le TM.
- [ ] `newUser(clearance)` déclenche le processus d'inscription réseau.
- [ ] `askUserDelegate()` permet au délégateur d'accepter ou non une délégation.
- [ ] `send(TK)` transmet le token de délégation nécessaire Ã  la construction de la `PSKA` cÃ´té TM délégataire.
- [ ] `askForSharing(CT)` déclenche le partage réseau d'un chiffré vers les TMs accessibles.
- [ ] `askRevocation(mission)` déclenche le processus de révocation.
- [ ] `newUserAlert(PSKA)` notifie l'autorité qu'un nouvel utilisateur synchronisé nécessite une dérivation de `skw`.

### Priorité autorité vs délégation

- [ ] Si l'autorité est joignable et qu'un TM émet aussi `DELEGATE_ACCEPT`, la voie autorité reste prioritaire.
- [ ] Dans un réseau intermittent, la voie autorité et la voie délégation peuvent néanmoins se terminer indépendamment l'une de l'autre.
- [ ] L'arbitrage final entre réponse autorité et réponse délégation est assuré par le TM du nouvel utilisateur.
- [ ] Une délégation peut donc réussir cÃ´té `PSKS` / `PSKA` mÃªme si `skw` n'est pas encore disponible.
- [ ] Tant que `skw` n'est pas disponible, le panel utilisateur reflÃ¨te cet état partiel sans débloquer le chiffrement.
- [ ] DÃ¨s réception ultérieure de `skw`, l'activation du chiffrement est immédiate, sans reconnexion manuelle.

### Setup initial et synchronisation

- [ ] Le setup autorité produit `PP`, `MSK`, `params`, `sk`, `ARL`, `storage`, `presets`.
- [ ] Le setup transmet l'état initial nécessaire Ã  `TM0`.
- [ ] Chaque TM accessible stocke les chiffrés reÃ§us via `CT_SHARE`.
- [ ] `ARL_UPDATE` met Ã  jour l'ARL de tous les TMs accessibles dans le mÃªme espace de connectivité.
- [ ] Pour la démo, `SYNCHRONIZE` / `PSKA_SYNC` doivent permettre au minimum la convergence des `PSKA`.
- [ ] Lorsqu'un TM synchronisé apporte une `PSKA` inconnue de l'autorité, le flux `newUserAlert -> getClassificationAttribute -> dérivation de skw -> KEY_RESPONSE(skw)` est opérationnel.

### Ã‰tats du panel utilisateur aprÃ¨s réception de clés

- [ ] AprÃ¨s un `KEY_RESPONSE` complet de `KeyGen`, l'utilisateur est connecté automatiquement.
- [ ] AprÃ¨s connexion automatique, le panel connecté affiche immédiatement les clés effectivement reÃ§ues.
- [ ] Si l'utilisateur ne possÃ¨de que `PP` et `PSKS` sans `skw`, le panel reste connecté mais l'onglet de chiffrement est grisé et non cliquable.
- [ ] Si `skw` arrive plus tard, le panel connecté se met Ã  jour immédiatement et rend le chiffrement disponible.

### Scénarios de démo issus de `SLIDES_LAYOUT.md`

- [ ] Le panel admin permet de montrer les presets.
- [ ] Lors d'un `Sign up`, l'utilisateur voit un état d'attente du type `waiting for key generation or delegation process`.
- [ ] Un `Sign up` déclenche un `KEY_REQUEST` sur le réseau.
- [ ] Le panel admin reÃ§oit une notification lorsqu'un nouvel utilisateur attend une génération de clés ou une décision associée.
- [ ] AprÃ¨s acceptation cÃ´té admin, le transfert de clés vers l'utilisateur concerné s'effectue correctement.
- [ ] L'utilisateur issu d'un `KeyGen` voit ses clés directement sur son panel connecté.

### Scénario U1 / U5 avec connectivité intermittente

- [ ] Si `U1` est en `Net2` et l'autorité reste en `Net1`, `U5` peut tout de mÃªme faire un `Sign up`.
- [ ] Dans ce cas, `U5` peut atteindre un panel connecté avec des clés partielles issues d'une délégation.
- [ ] Tant que `skw` n'a pas été obtenue depuis l'autorité, l'onglet de chiffrement de `U5` est grisé et non cliquable.
- [ ] Lorsque l'autorité redevient joignable et que `skw` est reÃ§ue, l'onglet de chiffrement de `U5` s'active immédiatement.

### Scénario de chiffrement

- [ ] `U1` peut chiffrer depuis le panel de labelling lorsqu'il possÃ¨de les clés requises.
- [ ] `U1` voit les attributs autorisés, dont `FR-DR`.
- [ ] `U1` ne voit pas `M2` si cet attribut ne relÃ¨ve pas de son besoin d'en connaÃ®tre.
- [ ] Un chiffrement valide produit un `CT` partageable via le réseau.
- [ ] AprÃ¨s `CT_SHARE`, chaque TM accessible stocke le chiffré.

### Scénario de refus de chiffrement sur attribut interdit

- [ ] `U5` ne voit pas `FR-S` si cet attribut n'est pas autorisé.
- [ ] Une tentative de contournement cÃ´té client ne permet pas de forcer un chiffrement sur `FR-S`.
- [ ] Le backend refuse effectivement l'opération si les attributs soumis sont interdits.
- [ ] Le refus fonctionnel est cohérent avec les contraintes crypto attendues.

### Scénario de déchiffrement

- [ ] Un utilisateur autorisé peut lancer une tentative de déchiffrement via `Consulter`.
- [ ] Avant tout déchiffrement, le TM vérifie l'ARL de l'attribut de mission concerné.
- [ ] Le TM effectue le déchiffrement partiel puis transfÃ¨re `^CT` Ã  l'utilisateur.
- [ ] L'utilisateur effectue le déchiffrement final local si ses clés le permettent.

### Visibilité des documents

- [ ] Un utilisateur qui ne doit pas accéder Ã  un document ne le voit pas dans la liste.
- [ ] `U5` ne voit pas `1.ct` dans le scénario de démo prévu.
- [ ] L'absence de visibilité suffit comme critÃ¨re d'acceptation pour les documents inaccessibles.

### Révocation

- [ ] L'interface de révocation disparaÃ®t du panel admin pour l'objectif 2.
- [ ] La révocation cÃ´té admin apparaÃ®t uniquement sous forme de popup.
- [ ] Le contenu minimal de la popup est de la forme : `U1 veut révoquer M2 - oui/non`.
- [ ] Le chemin de révocation retenu est : `Ux -> TMx -> Authority -> TM0 -> ARL_UPDATE vers les TMs accessibles`.
- [ ] `TM0` met Ã  jour l'ARL aprÃ¨s décision de révocation.
- [ ] Les TMs accessibles reÃ§oivent et appliquent `ARL_UPDATE`.

### Blocages séparés autour de `M2`

- [ ] Création de compte : un `Sign up` demandant `M2` est bloqué si `M2` est révoqué.
- [ ] Chiffrement : une tentative de chiffrement avec `M2` est bloquée si `M2` est révoqué.
- [ ] Déchiffrement / consultation : une tentative d'accÃ¨s Ã  un document portant `M2` est bloquée si `M2` est révoqué.

### Scénarios finaux de la démo autour de `M2`

- [ ] AprÃ¨s révocation, `U9` ne peut pas créer de compte avec l'attribut `M2`.
- [ ] AprÃ¨s retour en connectivité adéquate, `U7` ne peut pas chiffrer avec `M2`.
- [ ] AprÃ¨s révocation, `M2` n'est plus visible dans l'arborescence de labelling.
- [ ] AprÃ¨s révocation, `U7` ne peut pas consulter un document associé Ã  `M2`.
- [ ] AprÃ¨s révocation, les documents associés Ã  `M2` peuvent Ãªtre simplement non visibles.
