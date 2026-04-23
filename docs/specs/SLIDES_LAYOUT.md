Maquettage démo. L'indexage de la forme « n/28 » correspond à une slide correspondante, non présente et non utile pour la spec.
1-4/28
Screen démonstrateur sur les presets depuis le panel admin
5/28
U1 fait Sign up avec login / mdp / clearance : temps de chargement « waiting for key generation or delegation process »
Cela appelle un keyrequest sur le réseau
Cela déclenche un transfert de clés pour U1
Cela le connecte automatiquement et il peut voir ses clés directement sur son panel connecté
6-10/28
U1 entre dans l'espace de connectivité Net2 (l'autorité reste dans l'espace de connectivité Net1) 
U5 fait Sign up avec login / mdp / clearance : temps de chargement « waiting for key generation or delegation process »
Puis U5 accède à son panel : on voit qu'il ne peut pas chiffrer car il n'a pas de clé ABS (l'onglet n'est pas dispo dans le nav), il la recevra lorsque il retournera dans l'espace de connectivité de l'admin
11-15/28
U1 rejoint l'espace de connectivité Net1
Montrer un chiffrement de la part de U1 sur le panel Labelling. Montrer que U1 a accès à FR-DR aussi, mais pas à M2 (besoin d'en connaître). 
16/28
Montrer un chiffrement de la part de U5 FR-S : 
-	N'a pas accès à l'attribut FR-S dans le label ;
-	Si on tente de bypass via F12 y'a le message d'erreur ;
-	Et expliquer que Ã§a bloquera aussi au niveau crypto via un treillis.
17/28
Tentative de déchiffrement de 1.ct via « Consulter ». 
18/28
U5 ne voit pas 1.ct, et s'il voulait le voir il ne pourrait pas à cause de sa clé ABE.
19/28
U5 et U7 rejoignent l'espace de connectivité Net2.
20/28
TM1 fait un askRevocation à TM0 pour l'attribut M2
TM0 informe l'admin, une alerte apparaît sur son panel respectif
21-22/28
U9 tente de créer un compte avec l'attribut M2 : blocage car attribut révoqué
23-26/28
U5-U7-U8 rejoignent l'espace de connectivité Net1
U7 tente de chiffrer avec l'attribut M2 : blocage car attribut révoqué (non visible dans l'arborescence)
27/28
U7 tente de déchiffrer un document avec l'attribut M2 : blocage car attribut révoqué (non visible dans l'arborescence)
