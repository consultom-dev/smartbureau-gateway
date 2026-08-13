# `wg-core-ctl` — la surface de contrôle du peer wg-core

Le « comment » de la pose du peer wg-core (arbitrages **Q17** puis **Q20**,
corpus `smartbureau-server`). L'app de gestion pose et retire le peer d'une
passerelle sur `wg0` du serveur ; mais `wg0` vit dans `wg-core`
(`network_mode: host`), hors d'atteinte de l'app, et `wg set` exige le netns
où vit l'interface. Un seul processus ne peut être **à la fois** joignable
par un nom Docker (bridgé) **et** dans le netns hôte. D'où deux processus,
une **frontière de fichier** — le motif `parefeu-console`/`parefeu`.

```
   gestion / gestion-worker           wg-core-ctl                 wg-core (rôle serveur, image wg)
   ────────────────────────           ───────────                ─────────────────────────────────
   POST /peers   {gw_id,      ─HTTP→  valide, écrit    ─fichier→  reconcilier_peers wg0 :
     cle_publique, allowed_ips}        l'état désiré      (volume    wg set wg0 peer … allowed-ips  (ajout)
   DELETE /peers/{gw_id}      ─HTTP→   (peers.json)       partagé)   wg set wg0 peer … remove       (retrait)
                                       BRIDGÉ, SANS CAP             NETNS HÔTE, NET_ADMIN
```

## Le contrat HTTP (ce dont l'app dépend)

- `POST /peers` — corps `{gw_id, cle_publique, allowed_ips}`. Valide, puis
  insère/met à jour l'état désiré. **204**. `400` si `gw_id`, clé publique
  (base64 de 32 octets) ou `allowed_ips` (/32 dans le plan wg-core) est
  invalide — **rien de non vérifié ne s'approche d'un `wg set`**.
- `DELETE /peers/{gw_id}` — retire le peer de l'état désiré. **204**,
  **idempotent** (retirer un absent réussit : l'outbox peut rejouer).
- `GET /peers` — l'état désiré courant (introspection, banc). `GET /sante`.

Aucune authentification : le conteneur est bridgé, joignable seulement par
le réseau interne du compose (comme `db`, `keycloak`, `/metrics`).

## Le contrat de fichier (entre wg-core-ctl et wg-core)

`peers.json` sur le volume partagé `wg-core-peers`, écrit **atomiquement**,
**trié** (stable) :

```json
{ "peers": [ { "gw_id": "gw-01", "cle_publique": "…=", "allowed_ips": "10.100.0.2/32" } ] }
```

`wg-core` (rôle serveur, `serveur-peers.sh`) réconcilie ce fichier sur `wg0`
en diffant l'état **réel** (`wg show`) — idempotent, comme l'agent de
passerelle (annexe 3 §4.1). Les peers **statiques** du `wg0.conf`
provisionné (la VM d'usine) sont lus depuis ce conf et **jamais touchés** :
seul le delta dynamique est réconcilié. Un `wg-core` redémarré retrouve ses
peers de passerelle depuis le fichier, sans intervention.

## Ce que ce conteneur n'est pas

Sans privilège (`cap_drop: [ALL]` au compose), il **ne voit jamais `wg0`**,
ne route rien, ne détient aucune clé privée. Sa seule arme est d'écrire un
fichier — « appliquer une décision prise ailleurs » (annexe 3 §4.2).

## Banc

- `tests/wg-core-ctl/` — la surface, avec le `python3` de l'hôte (comme
  `parefeu-console`) : validation, écriture atomique, idempotence.
- `tests/wg-core-applier/` — l'applicateur, contre un vrai `wg0` (root +
  module noyau wireguard) : ajouts/retraits, peer statique préservé,
  convergence après redémarrage.
