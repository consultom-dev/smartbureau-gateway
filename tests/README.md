# `tests/` — la recette des passerelles et de l'image `wg`

**Les invariants sont des tests** (règle de travail 3 du `CLAUDE.md`).

| Répertoire | Contenu | Lot | Fait foi |
|---|---|---|---|
| `netfilter/` | les cas **P-01 … P-20** sur le gabarit partagé | 4 | annexe 3 §8 |
| `agent-enrolement/` | la machine à états rejouée **contre le mock** | 2 | annexe 2 §3.3 |
| `agent-passerelle/` | la boucle : diff, 401, ipset | 4 | annexe 3 §4 |

Ce dépôt porte **deux critères de fini** :

- **lot 2** — les trois rôles montent leurs interfaces en maquette
  minimale ; la machine à états de l'agent d'enrôlement est rejouée contre
  le mock (USINE → NOMINAL, 304/200/403, SUSPENDU et reprise), **avec des
  coupures simulées à chaque étape et une reprise idempotente** ; le
  watchdog bascule en ≤ 60 s, **et il bascule encore une fois
  l'agent d'enrôlement tué** ; les fichiers d'état sont conformes (modes,
  propriétaires, GID 3000, `registre/auth.json` en `600 root`) ;
- **lot 4** — les **douze invariants de l'annexe 3 §8** sont testés, dont :
  deux kits enrôlés ne se joignent pas à travers une passerelle ; un kit
  hors ipset ne sort pas vers Internet ; API coupée → les peers restent
  posés ; `wg-quick` rejoué à la main → l'agent de passerelle reconverge
  **sans doublon**.

## Règle

Chaque cas **cite sa source normative** — un test rouge doit dire quelle
ligne du corpus n'est plus vraie. Un invariant cassé ne se contourne pas :
il rouvre la discussion d'architecture.
