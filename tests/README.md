# `tests/` — la recette des passerelles et de l'image `wg`

**Les invariants sont des tests** (règle de travail 3 du `CLAUDE.md`).

| Répertoire | Contenu | Lot | Fait foi |
|---|---|---|---|
| `roles/` | les cas **R-01 … R-06** — les trois rôles montent leurs interfaces (**sudo + module noyau `wireguard`**) | 2 | annexe 7 §1, arch. §6.2 |
| `agent-enrolement/` | les cas **A-01 … A-17** — la machine à états rejouée **contre le mock** (ni Docker ni module noyau) | 2 | annexe 2 §3.2 et §3.3 |
| `watchdog/` | les cas **W-01 … W-12** — la bascule d'endpoint et la boucle de marqueurs (ni root, ni Docker, ni réseau) | 2 | annexe 2 §3.4 et §3.4 bis |
| `netfilter/` | les cas **P-01 … P-05** sur le gabarit partagé (**root + netns**) | 4 | annexe 3 §3.2 et §8 |
| `agent-passerelle/` | les cas **G-01 … G-10** — la boucle contre le mock : diff, 401, ipset | 4 | annexe 3 §4 |
| `configuration/` | les cas **C-01 … C-08** — compose, proxy d'enrôlement, provisionnement | 4 | annexe 3 §2, §5, §7 |

`tap.py` est le rapporteur commun aux recettes Python du projet (TAP, cas
sautés **jamais verts**, chaque cas cite sa source) — même fichier que
dans `smartbureau-edge`.

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
