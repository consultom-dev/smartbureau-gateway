# `wg-agent` — l'agent de passerelle

**Lot 4.** Fait foi : **annexe 3 §4**. C'est lui qui rend les passerelles
sans état.

Toutes les 30 s, dans cet ordre :

```
1. GET /peers (Bearer secret d'agent, X-Gw-Id, X-Version)
   ├─ 304 → rien à faire
   ├─ 200 → diff avec `wg show wg-kits dump` : ajouts / retraits,
   │         puis synchronisation de l'ipset internet_ok par ÉCART,
   │         puis mémorisation de la version
   └─ 401 → alerte, backoff — et SURTOUT : ne rien purger
2. POST /etat-tunnels : delta des handshakes et compteurs
```

## Ce qui ne se négocie pas

- **Un agent de passerelle sans plan de contrôle ne purge rien**
  (invariant 6) : un `401` ou une API injoignable laisse les peers en
  place, la passerelle continue de servir ses kits. L'inverse ferait d'une
  panne du serveur une **panne de flotte**.
- **Le diff porte sur `wg show`**, jamais sur une liste mémorisée
  (invariant 8) : c'est ce qui rend équivalents le redémarrage du
  conteneur, la pose manuelle d'un peer et un `wg-quick` rejoué à la main.
- **Il ne détient aucune clé** (invariant 7), ne pose **aucune règle** de
  pare-feu et ne relaie **rien** du trafic des kits. Son seul pouvoir est
  d'ajouter ou retirer des peers — d'appliquer une décision prise ailleurs.
- **Tous les peers sur toutes les passerelles** (invariant 5) : une table
  partielle fait échouer les bascules — le kit arrive et se fait jeter en
  silence.
- **La surcharge `api.` vit dans le compose** (`extra_hosts`, invariant 3),
  sur chaque conteneur qui parle au plan machine : celui-ci en fait
  partie. Sans elle, l'agent de passerelle ne résout rien et le nœud naît
  muet.
- **Pas de `depends_on`** vis-à-vis de `wireguard` : si l'interface
  n'existe pas encore, le `wg set` échoue et l'agent de passerelle
  réessaie 30 s plus tard.

Recette : `tests/agent-passerelle/` (cas **P-12 à P-15**).
