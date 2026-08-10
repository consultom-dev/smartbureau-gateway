# `tireur` — comment un certificat traverse les machines

**Lot 5a** — le lot est piloté depuis `smartbureau-server` (il veut Vault),
mais **le code vit ici** : le `tireur` est partagé par les passerelles et
la VM usine (annexe 7 §1). Un lot qui traverse deux dépôts : réserve
**R6** de `docs/arborescences.md`, à refléter dans les jalons.

Fait foi : **annexe 5 §5.3** (le mécanisme, décrit une fois pour toutes),
annexe 3 §2.4 (passerelles), annexe 9 §2.4 (VM usine).

```
tireur (sur la passerelle ou la VM usine)
  │  s'authentifie auprès de vault.server.<domaine>.tld (par wg-core)
  │    → AppRole : role_id dans sa configuration, secret_id remis UNE fois
  │      au provisionnement, renouvelé ensuite seul
  │  policy : LECTURE SEULE sur son unique chemin
  │           (kv/tls/gateway ou kv/tls/factory) — rien d'autre
  ▼
toutes les heures : comparer la version du coffre à la version locale
  ├─ identique  → ne rien faire
  └─ différente → écrire cert + clé de façon ATOMIQUE
                  (640 root:smartbureau-lecture), puis recharger
```

## Ce qui ne se négocie pas

- **La machine va chercher ; le central ne pousse jamais** — il ne connaît
  ni n'atteint ces machines. C'est la doctrine, pas une commodité.
- **Un secret par machine, un chemin par machine** : une passerelle ne
  peut pas lire `kv/tls/factory`, et réciproquement.
- **La panne est inerte** : un coffre scellé ou injoignable **laisse le
  certificat en place** — la machine continue de servir, le tireur
  réessaie. Ce qui alerte, c'est l'**approche de l'expiration**
  (`smartbureau_certificat_expire_dans_secondes`), pas l'échec d'un tirage.
- **L'écriture est atomique et suivie d'un rechargement** : un fichier de
  certificat à moitié écrit produirait une panne TLS plus longue que le
  renouvellement lui-même.
- **Amorçage ordonné** sur une machine neuve : raccordement wg-core, puis
  identité Vault, puis tirage, puis démarrage du service TLS. Tant que le
  certificat n'est pas là, la machine ne sert rien — **c'est une étape de
  provisionnement, pas une panne**.
