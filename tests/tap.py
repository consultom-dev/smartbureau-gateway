#!/usr/bin/env python3
# =============================================================================
# tap.py — le petit rapporteur commun aux recettes Python du dépôt
#
# Même sortie que le gabarit netfilter du lot 0 (TAP, cadres `┌─ … └─`) :
# une seule lecture pour toutes les recettes du kit, et une intégration
# unique côté CI.
#
# Deux règles héritées du gabarit, et qui font toute sa valeur :
#
#   - un cas SAUTÉ se dit sauté, jamais vert. Une capacité manquante
#     (docker absent, par exemple) doit se voir dans le bilan — sinon la
#     recette rapporte « tout va bien » sur ce qu'elle n'a pas exécuté ;
#   - chaque cas CITE SA SOURCE normative. Un cas rouge doit dire quelle
#     ligne du corpus n'est plus vraie.
# =============================================================================

import sys


class Recette:
    def __init__(self, lot=1):
        self.lot = lot
        self.numero = 0
        self.echecs = 0
        self.sautes = 0
        self.assertions = 0
        self._ok_courant = True

    # --- cycle d'un cas ------------------------------------------------------
    def cas(self, titre, source, lot=None):
        # `lot` par cas : une même recette peut porter des cas de lots
        # différents (la famille configuration tient D-01…D-07 au lot 1 et
        # D-08 au lot 5b). À défaut, le lot de la recette.
        print("# ┌─ %s" % titre)
        print("# │  source : %s   lot : %s" % (source, self.lot if lot is None else lot))
        self._ok_courant = True

    def fin(self, nom):
        self.numero += 1
        if self._ok_courant:
            print("# └─ %s réussi" % nom)
            print("ok %d - %s" % (self.numero, nom))
        else:
            print("# └─ %s ÉCHOUÉ" % nom)
            print("not ok %d - %s" % (self.numero, nom))
            self.echecs += 1

    def sauter(self, nom, motif):
        self.numero += 1
        self.sautes += 1
        print("# └─ %s sauté — %s" % (nom, motif))
        print("ok %d - %s # SKIP %s" % (self.numero, nom, motif))

    # --- assertions ----------------------------------------------------------
    def verifier(self, condition, libelle, detail=""):
        self.assertions += 1
        if condition:
            print("#     ✓ %s" % libelle)
            return True
        print("#     ✗ %s" % libelle)
        if detail:
            for ligne in str(detail).splitlines():
                print("#       %s" % ligne)
        self._ok_courant = False
        return False

    def tracer(self, message):
        print("# │  %s" % message)

    # --- bilan ---------------------------------------------------------------
    def bilan(self):
        print("1..%d" % self.numero)
        print("#")
        print(
            "# Bilan : %d réussi(s), %d échoué(s), %d sauté(s) — %d assertions"
            % (self.numero - self.echecs - self.sautes, self.echecs,
               self.sautes, self.assertions)
        )
        return 1 if self.echecs else 0


def sortir(recette):
    sys.exit(recette.bilan())
