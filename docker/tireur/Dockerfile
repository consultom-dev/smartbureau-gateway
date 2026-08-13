# =============================================================================
# Image `tireur` (annexe 5 §5.3) — partagée par les passerelles et la VM
# usine. Elle embarque le CLI Vault (le binaire `vault` fait office d'agent) ;
# le tireur, lui, est un petit script qui s'authentifie en AppRole, compare la
# version du coffre à la locale et écrit le certificat atomiquement.
#
# Base = l'image Vault épinglée (elle porte le CLI et rien de superflu). Pas
# de tag mobile (annexe 7 §8). Le groupe `smartbureau-lecture` (GID 3000 figé,
# annexe 2 §3.2) est celui que le Traefik de la machine partage pour LIRE le
# certificat en 640 — jamais l'écrire.
# =============================================================================
FROM hashicorp/vault:1.15.6

# GID 3000 figé (annexe 2 §3.2) : le certificat sort en root:smartbureau-lecture.
RUN addgroup -g 3000 smartbureau-lecture 2>/dev/null || true

COPY tireur.sh /usr/local/bin/tireur.sh
RUN chmod +x /usr/local/bin/tireur.sh

# root : le tireur pose root:smartbureau-lecture 640 (il écrit, Traefik lit).
USER root
ENTRYPOINT ["/usr/local/bin/tireur.sh"]
