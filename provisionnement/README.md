# `provisionnement/` — d'une VM neuve à une passerelle

**Lot 4.** Fait foi : **annexe 3 §2**. Trois actions, une seule fois,
automatisables (cloud-init ou Ansible). **Rien d'autre ne touche l'hôte.**

Critère de fini du lot 4 : *une VM neuve devient une passerelle
opérationnelle par une procédure automatisable, et son retrait ne laisse
rien derrière*.

## 1. Système et sysctls

`net.ipv4.ip_forward = 1`, **`net.ipv6.conf.all.forwarding = 0`** (doctrine
v4 seul), `net.netfilter.nf_conntrack_max = 1048576` — un routeur qui NAT
des milliers de clients **sature conntrack avant le CPU**. Module
WireGuard chargé et persisté, Docker CE + compose v2.

## 2. Pare-feu public de l'hôte

| Port | Source | Usage |
|---|---|---|
| 51820/udp | **toute l'Internet** | wg-kits — les kits arrivent de n'importe quelle IP 4G |
| 443/tcp | toute l'Internet | proxy d'enrôlement et re-poll |
| 22/tcp | administration seule | exploitation |
| tout le reste | — | fermé, **v4 et v6** |

**Rien n'est ouvert vers wg-core** : c'est la passerelle qui initie ce
tunnel vers le serveur (51821/udp sortant).

## 3. Secrets et identité

Tirage de Vault avec un **jeton court** (chemin froid) : la clé privée
partagée `wg-kits` (600 root) et le secret d'agent de **ce** nœud. La
paire **wg-core est générée localement** — elle n'est partagée avec
personne ; sa clé publique est remise à l'app de gestion à la déclaration.
Le wildcard `*.gateway` n'est pas tiré une fois pour toutes : c'est le
`tireur` qui le maintient.

## Ce qui ne se négocie pas

- **Aucune surcharge pour `registry.factory`** : il est public depuis la
  rév. 22, résolu par le DNS ordinaire — c'est ce qui permet à un nœud neuf
  de tirer ses images **avant d'avoir monté wg-core**. Seul `api.` demande
  une surcharge, et elle se pose en `extra_hosts` dans le compose, jamais
  par un joker.
- **Ordre impératif au retrait** : endpoints d'abord, tunnels ensuite,
  machine en dernier (annexe 3 §6.2). Et **une IP publique retirée reste
  en quarantaine** tant que des listes d'endpoints peuvent la porter.
- **Dimensionner à ~150 % de la charge nominale** : en cas de panne d'un
  nœud, ses kits se répartissent sur les autres (arch. §5.4).
