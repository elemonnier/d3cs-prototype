Les noeuds utilisateurs ont le format Ux|clearance|state.
Authority est un noeud spécial sans état.

États possibles : CONNECTED, ABE, ABE+ABS.
État initial des utilisateurs : CONNECTED.

Lorsqu'une arête apparaît entre Authority et un utilisateur :
- si l'utilisateur est CONNECTED ou ABE, il passe à ABE+ABS.

Lorsqu'une arête apparaît entre deux utilisateurs A et B :
- si A et B ont la même clearance,
- alors tout noeud en CONNECTED dont l'autre endpoint est ABE ou ABE+ABS passe à ABE.

Les transitions sont monotones :
CONNECTED -> ABE -> ABE+ABS.
Aucun retour en arrière.

Les transitions d'état sont calculées à partir des états figés au début du step, puis appliquées à la fin du step : un changement d'état ne peut donc pas déclencher une autre transition pendant ce même step.