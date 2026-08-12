# =============================================================================
# `wg-agent` — l'agent de passerelle (annexe 3 §4).
#
# Image SÉPARÉE de `wg`, et c'est le cloisonnement lui-même : celui qui
# détient les clés (`wireguard`) n'a aucun canal sortant ; celui qui a un
# canal sortant (ici) ne détient aucune clé. Les fusionner « pour
# simplifier » ferait disparaître la propriété (annexe 3, invariant 7).
#
# `NET_ADMIN` sans plus : `wg set` et `ipset` sur des objets créés par
# d'autres. Aucun `iptables` — il ne pose aucune règle (§4.2).
#
# Base Debian slim épinglée ; sa définition canonique arrive avec
# smartbureau-factory (annexe 7 §5).
# =============================================================================
ARG BASE=debian:12-slim
FROM ${BASE}

# `ca-certificates` EXPLICITE : il n'est qu'un `Recommends` de libcurl, que
# `--no-install-recommends` laisse dehors. Sans lui, tout appel HTTPS au
# plan de contrôle tombe en `curl 60` — cet agent de passerelle tournerait
# sans jamais poser un peer, en ayant l'air de travailler.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      ca-certificates wireguard-tools ipset curl jq \
 && rm -rf /var/lib/apt/lists/*

COPY agent.sh /usr/local/bin/agent.sh
RUN chmod +x /usr/local/bin/agent.sh

ENTRYPOINT ["/usr/local/bin/agent.sh"]
