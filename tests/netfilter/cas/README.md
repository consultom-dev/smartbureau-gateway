# `cas/` — un fichier par invariant

Vide au lot 0 : l'entrypoint de l'image `wg` et `wg-agent` n'existent pas
encore. Se remplit au **lot 4**, avec les cas **P-01 à P-20** catalogués
dans le README du répertoire parent.

Nommage : `<Id>-<slug>.cas` — par exemple `P-06-ordre-fail-closed.cas`.

Forme d'un cas : `preparer()` monte le banc « passerelle » (kitA, kitB,
serveur, interface publique), `agir()` exécute l'entrypoint sous test,
`verifier()` évalue les assertions, `fin_cas` déroule et détruit le banc.
La **référence normative est obligatoire**.

Pour démarrer, partir des cas de démonstration du gabarit — ils couvrent
déjà la pose d'un `DROP`, l'absence d'une règle, le verrou v6 et le
hub-and-spoke sur paquets réels.
