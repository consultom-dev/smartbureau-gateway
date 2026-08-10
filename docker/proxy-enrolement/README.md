# `proxy-enrolement` — deux routes, et rien d'autre

**Lot 4.** Fait foi : **annexe 3 §5**, durcissement en arch. §11.2. Seul
service exposé publiquement en TCP.

| Route | Vers | Consommateur |
|---|---|---|
| `POST /enroler` | `https://api.server.<domaine>.tld/enroler` (par wg-core) | agent d'enrôlement d'un kit neuf |
| `GET /config-kit` | `https://api.server.<domaine>.tld/config-kit` (par wg-core) | re-poll de tous les kits |

Côté kit, ces deux routes sont adressées par un **nom public** —
`https://gw-NN.gateway.<domaine>.tld` : l'étage `gateway` a de vrais
enregistrements A publics, statiques, et **aucune surcharge dnsmasq** côté
kit. C'est ce qui permet à un kit sans tunnel de s'enrôler et de
re-poller.

## Ce qui ne se négocie pas

- **Pas de troisième route.** Plus de route ACME : le certificat vient de
  Vault, aucun challenge ne s'exécute ici, et **le port 80 est fermé**.
  Tout autre chemin ou méthode répond **404**.
- **Il ne dépend pas des tunnels** (invariant 9) : il sert précisément les
  kits qui n'en ont pas. Il doit fonctionner même wg-core mort — d'où son
  indépendance vis-à-vis des deux autres conteneurs.
- **Durcissement** : TLS obligatoire sur 443, corps **borné à 32 Ko**,
  limitation de débit par IP source et globale. L'enrôlement est rare, le
  re-poll est lent (~0,5 req/s pour toute la flotte) — **tout dépassement
  franc est un signal, pas une charge**.
- **Aucune journalisation de corps** : les secrets y transitent. Les échecs
  remontent à l'app de gestion pour la vue sécurité.
- **Le certificat est le wildcard `*.gateway`**, tiré de Vault au
  provisionnement **et à chaque renouvellement** (invariant 10) : l'oublier
  le laisse expirer et ferme l'enrôlement **comme le re-poll** de toute la
  flotte servie par ce nœud. Contrepartie assumée : la clé est partagée
  par les N passerelles.
- **La surcharge `api.` vit dans le compose** (`extra_hosts`) — ce
  conteneur en a besoin comme l'agent de passerelle.

Recette : cas **P-17** (deux routes, tout le reste en 404, corps borné) et
**P-18** (wg-core abattue → le proxy répond toujours).
