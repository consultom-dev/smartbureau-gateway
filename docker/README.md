# `docker/` — les sources des images

Cinq images vivent ici (annexe 7 §1) :

| Répertoire | Image | Lot | Fait foi |
|---|---|---|---|
| `wg/` | **l'image unique des trois rôles** | 2 (image), 4 (règles passerelle) | annexe 3 §3 ; arch. §6.2 ; annexe 2 §3 |
| `wg-agent/` | l'agent de passerelle | 4 | annexe 3 §4 |
| `proxy-enrolement/` | le proxy d'enrôlement | 4 | annexe 3 §5 |
| `tireur/` | Vault Agent, partagé avec la VM usine | 5a | annexe 5 §5.3 |
| `wg-core-ctl/` | la surface de contrôle du peer wg-core (rôle serveur) | 2 étendu | annexe 1 §6.4 ; arbitrages Q17, Q20 |

## Deux conteneurs, deux plans

C'est la doctrine de l'annexe 3, et elle gouverne ce répertoire :
`wireguard` tient le plan de **données** — il termine les tunnels, détient
les clés, pose les règles, mais n'a aucun interlocuteur applicatif et ne
décide de rien. L'agent de passerelle tient le plan de **contrôle** — il
est le seul à ouvrir une connexion vers l'app de gestion, et **il ne
détient aucune clé**.

**Celui qui détient les clés n'a pas de canal vers l'extérieur ; celui qui
a un canal ne détient pas les clés.** Un agent de passerelle compromis ne
donne pas les tunnels. Ne jamais fusionner les deux « pour simplifier ».

## Règles de construction

- **Aucun tag mobile**, base Debian **épinglée** (définie dans
  `smartbureau-factory`) — annexe 7, invariant 1.
- **Aucun secret dans une image** (invariant 4).
- **Backend netfilter nf_tables obligatoire** : les scripts refusent de
  poser sinon (piège 9). Un `iptables` legacy pose des règles muettes.
- **Architectures** : ce dépôt construit **amd64**, sauf `wg` qui est la
  **seule** image multi-arch du système (deux tâches natives, puis un
  assemblage de manifeste — annexe 9 §4.2). Jamais d'émulation.
- **Pas de `depends_on`** : couplage lâche, chaque conteneur retente.
