# =============================================================================
# Image `wg` — UNIQUE pour les trois rôles (annexe 7 §1 : une seule chaîne
# de construction multi-arch, un condensat identique partout ; jamais
# re-fragmentée en images par rôle).
#
# Le rôle est une VARIABLE (WG_ROLE=serveur|passerelle|kit), pas une image :
# l'entrypoint aiguille. L'image embarque donc l'UNION des besoins :
#   - passerelle (annexe 3 §3.1) : iptables (nf_tables), ipset, conntrack ;
#   - kit (annexe 2 §3.1) : iputils-ping (watchdog), curl + jq (agent
#     d'enrôlement) — et « pas d'iptables » y est une absence d'USAGE, pas
#     de binaire (arbitrage Q1 du lot 2) : le rôle kit n'invoque jamais
#     netfilter, le NAT et le pare-feu appartiennent à reseau-hote/parefeu.
#
# Backend netfilter : nf_tables OBLIGATOIRE (piège 9) — en legacy les règles
# seraient muettes et les tests faussement verts. L'alternative est posée
# ici ; l'entrypoint REFUSE de démarrer si elle a bougé.
#
# Base Debian slim épinglée — sa définition canonique arrive avec
# smartbureau-factory (annexe 7 §5) ; d'ici là, l'ARG la fige au compose.
# Aucun secret, aucun tag mobile (annexe 7 §8, invariants 1 et 4).
# =============================================================================
ARG BASE=debian:12-slim
FROM ${BASE}

RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      wireguard-tools iproute2 iputils-ping curl jq \
      iptables ipset conntrack procps \
 && rm -rf /var/lib/apt/lists/* \
 && update-alternatives --set iptables /usr/sbin/iptables-nft \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-nft

# wg-quick exige un resolvconf quand la conf porte du DNS — les nôtres n'en
# portent JAMAIS (endpoints en IP brutes, piège 4) : rien à installer.

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY roles/ /usr/local/lib/wg/roles/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/lib/wg/roles/*.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
