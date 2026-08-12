# =============================================================================
# `proxy-enrolement` — la SEULE exposition TCP publique d'une passerelle
# (annexe 3 §5). Deux routes, tout le reste en 404 (invariant 9).
#
# nginx sur base Debian épinglée, comme les autres images du projet — la
# définition canonique de la base arrive avec smartbureau-factory.
# =============================================================================
ARG BASE=debian:12-slim
FROM ${BASE}

RUN apt-get update \
 && apt-get install --no-install-recommends -y nginx-light ca-certificates gettext-base \
 && rm -rf /var/lib/apt/lists/*

COPY nginx.conf.modele /etc/nginx/nginx.conf.modele
COPY relais.conf       /etc/nginx/relais.conf.modele
COPY entrypoint.sh     /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
