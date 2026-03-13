Récit implémentation D3CS en local


Récit :
Langages :
-	Implémentation crypto CP-ABE/ABS : Rust
-	IHM : HTML/bootstrap
Ne dépendre d’aucun repo github/gitlab pouvant disparaître à tout instant. 
Ne pas générer de commentaires dans le code.
Pas de nouveau fichier hors de l’arborescence, sauf si tu me convaincs d’en ajouter un.
Tout coder en anglais, même les affichages de l’IHM
Lien github où modifier le projet (actuellement vide) : https://github.com/elemonnier/d3cs-local 

CP-ABE : Porwal et Mittal 2023 – PM23 (ci-joint). 
Choisir l’univers U={FR-S, FR-DR, M1, M2}. Hiérarchie délégation/déchiffrement : FR-S > FR-DR. Le label n’est composé que de « AND » (du 2-of-2 dans notre cas).
Fermeture descendante de l’attribut de classification : FR-S → {FR-S, FR-DR} et FR-DR → {FR-DR}

ABS : Li et Kim 2010 – LK10 (ci-joint). 
Prendre la construction avec random oracle (section 3), c’est-à-dire modéliser H comme boîte noire parfaitement aléatoire. H(String) = point sur la courbe elliptique (hash-to-curve). Cette méthode est plus simple pour le démonstrateur que sans RO (modèle standard), cette dernière étant mieux « théoriquement » (car le hash peut plus facilement se casser avec RO). 
Choisir d=1 car on ne signe qu’avec l’attribut de classification. 
Fixer l’univers ABS à U = {FR-S, FR-DR}. Si on veut treilliser davantage (e.g., avec les missions) il faudra relancer le Setup. 
Courbe BLS12-381
Stack arkworks

ABE & ABS : 
Seed non fixe lors du Setup pour éviter la génération déterministe de clés (notamment en prod)
G1 / G2 → utiliser la sérialisation canonique compressée de la lib (arkworks) (reconstruire les 2 points de la courbe – car pour x on a y et -y – au lieu de concaténer le x et le y)
Scalars (objet : Fr) : élément de corps fini spécifique – bigint est « mal » borné, avec une structure interne optimisée pour les corps finis : 32 bytes big-endian 
Structures → JSON déterministe (pas d’espace inutile, encodage standard etc) (ne jamais sérialiser des HashMap en JSON ; utiliser des structs à champs fixes (ordre stable) ou des maps ordonnées ; les tableaux sont triés si l’ordre n’a pas de sens)
Tous les objets stockés avec champ version 
G1 → hash-to-curve (méthode RFC 9380, expand XMD:SHA-256, DST "D3CS-ABS-H1" et "D3CS-ABS-H2" – avoir des noms différents pour H1/H2 pour éviter les collusions de points)
G2 → pairing (type différent de G1 car on travaille sur un twist de la première courbe – i.e. sur corps fini Fq^2 au lieu de Fq)
GT → résultat pairing (ce qui permet d’avoir un problème difficile CDH/DBDH)

Arborescence : 
d3cs-demo/
.
•	Cargo.toml → fichier obligatoire en Rust : package actuel et dépendances
•	Cargo.lock → fichier généré par Rust pour l’endroit exact des dépendances
•	.env → chemins relatifs vers les autres dossiers (crypto, users, tm, ihm, …)
•	.gitignore → nécessaire car Rust génère des artefacts lourds à ne pas versionner (notamment dans .cargo), ne pas pousser les clés
config/
•	blpbiba.toml → presets BLP et Biba
•	attributes.json → treillis pour chaque attribut de classif (FR-S ou FR-DR), et les attributs de mission (M1/M2). Représenté par une liste, et faisant apparaître la hiérarchisation FR-S > FR-DR. 
src/
•	main.rs → script principal du démonstrateur, qui appelle le reste. Lance également un serveur http Rust local pour lancer les pages HTML. 
•	api.rs : Exemples de routes : POST /keygen ; POST /encrypt ; POST /decrypt ; POST /revoke ; GET /documents, Toutes en JSON (contient les fonctions des routes, appelle crypto/mod.rs)
crypto/
•	mod.rs : agrégat de cpabe et abs
•	cpabe.rs
•	abs.rs
users/
•	[Ux]/ → toutes les clés d’un utilisateur : clés publiques ABE/ABS, privées ABE/ABS, tk.bin (clés en .bin) ainsi que les token de clearance
tm/
•	ct/ → chiffrés (.ct)
•	s/ : signatures (.sign)
•	ct_intermediate/ → prédéchiffrés (.cti)
•	arl.json → liste de révocation
•	pska/ → clés publiques/privées (.bin)
•	pp.bin : clé publique CP-ABE
•	params.bin : clé publique ABS
authority/
•	mod.rs
•	msk.bin → secret maître CP-ABE 
•	sk.bin : secret maître ABS
ihm/
•	index.html
•	main.js → bootstrap

Attributs utilisés :
-	Classification (SPIF France) : FR-S (secret) > FR-DR (diffusion restreinte)
-	Mission : M1 ou M2
Un utilisateur devra posséder un attribut de classification ainsi qu’un attribut de mission.


A -	Primitives crypto ABE utilisant les maths PM23 : à coder dans crypto/cpabe.rs
Setup 
Input : U
Fonction : maths de PM23
Output : PP, MSK, ARL. Stocker MSK dans authority/ sous la forme msk.bin, PP dans tm/ sous la forme pp.bin et ARL dans tm/ sous la forme arl.json. L’ARL a cette forme : attributeType (ici mission car y’a rien d’autre) et attributeValue (M1 ou M2). L’ARL est vide en ce moment.
Ne pas générer TL, CL, IRL.

Keygen
Input : PP, MSK, S. Ne pas prendre Ii en input.
Fonction : maths de PM23
Output : SKSi1 et SKSi2. Appeler SKSi1 « PSKA » et SKSi2 « PSKS ». Lors de la démo, si c’est U1 qui appelle la fonction, on aura PSKA1 et PSKS1 de généré. Pour U2, PSKA2/PSKS2 etc. Pas de stockage TL, pas de stockage ALL dans CL. Stocker PSKA dans tm/pska/ sous la forme pskax.bin et PSKS sous la forme psksx.bin dans users/[Ux]/ avec x pour l’utilisateur en question. 


Delegate
Input : PSKS_in, ^S. Ne pas prendre Ii et Ij en input. PSKS_in correspond une délégation Utilisateur_in->Utilisateur_out (delegator->delegatee)
Fonction : maths de PM23
Output : PSKS_out et Ss->^s, à renommer « TK ». PSKS_out correspond une délégation Utilisateur_in->Utilisateur_out. Pas de modification M, CTR, CL, TL (car ces paramètres n’existent pas du tout dans notre démonstrateur) et pas d’envoi Ii, SIi’’ et Ij au TM. Mettre PSKS dans users/[Ux]/ avec x pour l’utilisateur délégué/delegatee en question, sous la forme psksx.bin. TK est stocké dans le même dossier sous la forme tkx.bin, x pour le numéro utilisateur délégant/delegator.

TM_Delegate
Input : PSKA_in, TK, ^S. Ne pas input Ii, Ij, M et tous les Ctr/CTR. PSKA_in correspond une délégation Utilisateur_in->Utilisateur_out (Delegator->delegatee)
Fonction : maths de PM23
Output : PSKA_out. PSKA_out correspond une délégation Utilisateur_in->Utilisateur_out. Mettre PSKA dans tm/pska/ sous la forme pskax.bin selon le numéro x d’utilisateur délégué/delegatee.

Encrypt
Input : { "policy": [ "classification", "mission" ] } (pas de tree structure A), PP, m. Ne pas input KEY.
Fonction : maths de PM23
Output : CT (ciphertext). Le stocker dans tm/ct/ sous la forme i.ct, i étant le numéro du message (incrément/serial).

TM_Decrypt
Input : CT, ^S, PSKA. Ne pas input access_mode et m.
Fonction : maths de PM23
Output : ^CT. Le stocker dans tm/ct_intermediate/ sous la forme i.cti, i étant le numéro du message (incrément/serial).


Decrypt
Input : ^CT, PSKS
Fonction : maths de PM23
Output : m directement, pas KEY. Stocker message dans users/Ux selon l’utilisateur x correspondant sous la forme i.txt.

B -	Primitives crypto ABS utilisant les maths LK10 : à coder dans crypto/abs.rs

Setup
Input : 1^lambda
Fonction : maths de LK10
Output : params, sk. Stocker params.bin dans tm/, et sk.bin dans authority/.
 
Extract
Input : w (normalement un set d’attributs, mais dans notre démonstrateur, w ne contient qu’un seul attribut de classification), sk
Fonction : maths de LK10
Output : skw, stocker dans users/Ux/, sous la forme skwx.bin

Sign
Input : skw, m
Fonction : maths de LK10
Output : o : stocker x.sign avec x numéro du message


Verify
Input : o, w’, params
Fonction : maths de LK10
Output : 1 ou 0.


C -	Agrégat de primitives cryptographiques (CP-ABE-PM23 et ABS) : à coder dans crypto/mod.rs
Setup (indépendant de l’IHM, à exécuter dès le lancement)
Input : U, 1^lambda
Fonction :
Appeler CPABE.Setup 
Appeler ABS.Setup
Preset la config Bell-LaPadula et Biba sur config/blpbiba.toml en nowriteup = true, noreadup = true, nowritedown=false et noreaddown=false
Outputs : PP, MSK, ARL, params, sk. Indications plus haut sur leur stockage.



KeyGen
Input : PP, MSK, S, w, sk, token de clearance
Fonction : 
Vérification token de clearance avec un if. Ici, cela vaut True car la vérification est HS pour ce démonstrateur.
Appeler CPABE.KeyGen
Appeler ABS.Extract
Output : PSKA, PSKS, skw


Delegate (non appelé dans cette démo)
Input : PSKA_in, ^S, PSKS_in
Fonction : 
Vérification token de clearance avec un if. Ici, cela vaut True car la vérification est HS pour ce démonstrateur.
Vérification s’il y a un attribut de ^S qui serait révoqué. Si oui : end la fonction.
Appeler CPABE.Delegate
Appeler CPABE.TM_Delegate
Output : PSKA_out, PSKS_out

ExtractABS (non appelé dans cette démo) (envoi d’accès à la suite d’une délégation CPABE, lorsque l’autorité est re-up)
Input : w, sk
Fonction : 
Vérification token de clearance avec un if. Ici, cela vaut True car la vérification est HS pour ce démonstrateur.
ABS.Extract
Output : skw, stocker dans users/Ux/, sous la forme skwx.bin


Encrypt
Input : { "policy": [ "classification", "mission" ] } (pas de tree structure A), PP, m, skw
Fonction : 
Vérification que l’utilisateur possède bien une clé de signature sk : sinon, on abandonne Encrypt
Choix du label : 2 attributs (classification et mission) pour la prochaine instruction.
Vérifier si les attributs de classification du label ne violent ni nowriteup ni nowritedown (si True) dans config/blpbiba.toml
Vérification si l’attribut de mission n’est pas présent sur l’ARL
Appeler CPABE.Encrypt
Appeler ABS.Sign : prendre CT en entrée pour la signature et pas m
Appeler ABS.Verify : si output valide on stocke le fichier, sinon on ne fait rien (abandon Encrypt)
Output : CT, o ou rien


Decrypt
Input : CT, ^S, PSKA, PSKS
Fonction : 
Vérification token de clearance avec un if. Ici, cela vaut True car la vérification est HS pour ce démonstrateur.
Vérifier si les attributs de classification du label ne violent ni noreadup ni noreaddown (si True) dans config/blpbiba.toml 
Vérification si l’attribut de mission n’est pas présent sur l’ARL
Appeler CPABE.TM_Decrypt 
Appeler CPABE.Decrypt
Output : m


Revoke
Input : ARL
Fonction : Ajouter une ligne dans le fichier ARL, avec le type d’attribut et sa valeur.
Output : ARL’, la remplacer





D -	Fenêtres IHM : coder dans ihm/
Fenêtres style sobre (bootstrap), avec un nav en haut pour sélectionner une de ces catégories : 

Sign in et Sign up à droite du nav pour se connecter. Si on est connecté, on voit son login en haut de la page, du style « Hello, u1! »


Sign in (visible si non connecté)
Fenêtre login / mot de passe (points noirs) / bouton « sign in »
Pour les utilisateurs : 
Login u1 / mdp u1 – il possède la clearance FR-S M1 (document format json possédant ces deux valeurs)
Login u2 / mdp u2 – il possède la clearance FR-DR M1
Login u3 / mdp u3 – il possède la clearance FR-S M2
Login u4 / mdp u4 – il possède la clearance FR-DR M2 
Login admin / mdp admin
Osef de stocker les mdp en dur, ce n’est pas le but de la démo de faire ça bien.

Sign up (visible si non connecté)
Fenêtre login / mot de passe (points noirs) / clearance / bouton « sign in »
Fournir une clearance au format JSON 
Lors de l’appui sur le bouton « sign in », si login/mdp/clearance ont été renseignés, on appelle KeyGen dans crypto/mod.rs. L’utilisateur pourra accéder au panel utilisateur.

Labelling (visible admin/user)
Fenêtre avec un textarea pour écrire le message (String), avec 2 menus déroulants (un pour la classification, un autre pour la mission). Les valeurs affichées correspondent à la clearance de l’utilisateur et en fonction des presets dans config/blpbiba.toml. Si c’est l’admin qui est connecté, il voit tout.
Juste après, il y a un bouton « chiffrer » qui permet de lancer la fonction Encrypt dans crypto/mod.rs. Si la fonction cryptographique réussit, le document chiffré se stocke dans les tm/ct/. Sinon, un message rouge pop en dessous du bouton : « encryption failed ». 


Documents (visible admin/user)
Fenêtre qui affiche l’ensemble des chiffrés situés dans tm/ct/. En fonction de la clearance de l’utilisateur, il ne pourra voir que les messages au niveau de son habilitation et des presets config/blpbiba.toml. Si c’est l’admin qui est connecté, il voit tout.
Sur chaque document, l’utilisateur peut cliquer sur « consulter », ce qui appellera « Decrypt » de crypto/mod.rs. Le résultat de Decrypt (le contenu du fichier) s’affichera sous le nom du fichier. 

Revocation (visible admin seulement)
Fenêtre d’admin, qui pourra cocher soit M1 ou M2 (via checkboxes), puis appuyer sur « revoke ». Une alerte s’ouvre (en anglais) « do you want to revoke this/these mission(s)? ». Faire oui viendra appeler Revoke de crypto/mod.rs.

Presets (visible admin seulement)
Fenêtre d’admin, où l’on peut cocher les 4 presets BLP/Biba (checkboxes). Un appui sur le bouton « Update » mettra directement à jour le fichier config/blpbiba.toml.
Par défaut NRU/NWU sont cochés.

Log out si on est connecté pour se déconnecter, tout à droite du nav


 
Critères d’acceptation
A Initialisation (Setup)
1.	Si les fichiers pp.bin, msk.bin, params.bin ou sk.bin n’existent pas au lancement du serveur Rust, le Setup doit être exécuté automatiquement.
2.	Si ces fichiers existent déjà, le Setup ne doit pas être relancé et le système doit utiliser les fichiers existants.

B KeyGen / Sign up
1.	Lors du Sign up, si une erreur survient (clé invalide, clearance invalide, problème d’écriture fichier), un message d’erreur doit être affiché à l’utilisateur.
2.	La gestion fine des erreurs de login existant ou de clearance mal formée n’est pas prioritaire dans ce démonstrateur.
3.	La modification ultérieure de la clearance d’un utilisateur n’est pas requise.

C Encrypt
1.	Si un utilisateur tente de chiffrer un document avec une classification supérieure à la sienne, un message d’erreur explicite doit être affiché.
2.	Si la mission choisie est présente dans l’ARL, l’encryption doit être bloquée avec message d’erreur.
3.	Si ABS.Sign réussit mais que ABS.Verify échoue, l’encryption doit être abandonnée et un message précis doit être affiché.
4.	L’admin peut chiffrer avec n’importe quel label, sauf si les presets dans blpbiba.toml l’en empêchent.
5.	En cas d’échec, aucun fichier partiellement chiffré ne doit rester dans tm/ct/.

D Affichage des documents
1.	Un utilisateur FR-S peut voir les documents FR-DR uniquement si NRD=false.
2.	Un utilisateur FR-DR peut voir les documents FR-S uniquement si NRU=false.
3.	Si un document est inaccessible en raison des presets BLP/Biba, il ne doit pas apparaître dans la liste.
4.	L’admin voit tous les documents sauf si les presets BLP/Biba l’en empêchent explicitement.

E Decrypt
1.	Si CPABE.TM_Decrypt échoue, un message d’erreur doit être affiché.
2.	Si la signature ABS associée au ciphertext est invalide, la lecture doit être bloquée avec message explicite.
3.	Si une mission est révoquée après chiffrement :
o	Les documents déjà chiffrés restent lisibles.
o	Seuls les nouveaux documents utilisant cette mission deviennent inaccessibles.

F Revocation
1.	Lorsqu’un admin révoque une mission :
o	Tous les documents utilisant cette mission deviennent invisibles immédiatement.
2.	La dé-révocation n’est plus supportée.
3.	La gestion d’un ARL corrompu est hors scope du démonstrateur.

G Cohérence crypto
1.	Si le fichier PSKS d’un utilisateur est supprimé :
o	Encrypt reste possible.
o	Decrypt devient impossible avec message d’erreur.
2.	Si PSKA côté TM est supprimé :
o	Decrypt devient impossible avec message explicite.
3.	Aucune erreur ne doit provoquer un crash du serveur ; l’application doit continuer à fonctionner.

H Délégation
1.	Un utilisateur FR-S peut déléguer FR-DR (hiérarchie descendante).
2.	Un utilisateur FR-DR ne peut pas déléguer FR-S.
3.	Si un attribut est présent dans l’ARL, toute tentative de délégation utilisant cet attribut doit être bloquée.

I UX & Robustesse
1.	Toutes les erreurs doivent être visibles à l’utilisateur via message clair.
2.	Aucun système de log serveur n’est requis.
3.	En cas d’erreur, l’application continue de fonctionner sans interruption.

J Modèle simplifié des policies
1.	Les policies CP-ABE sont strictement limitées à une conjonction fixe 2-of-2 :
o	classification AND mission.
2.	Aucun OR, seuil générique ou moteur d’arbre arbitraire n’est implémenté.
3.	La hiérarchie de classification est appliquée via fermeture descendante au KeyGen.

