# `tests/agent-enrolement/` — la machine à états, contre le mock

**Lot 2.** Fait foi : **annexe 2 §3.3** ; critère de fini au plan §4. Le
mock du plan de contrôle vit dans `smartbureau-server/contrats/mock/` et
s'épingle **par commit**.

```
USINE     POST /enroler en boucle (backoff 1→15 min)
  ├─ 200 → secret_api, config wg0, endpoints.txt ; SUPPRIMER usine.json → NOMINAL
  └─ 403 → alerte locale, ET ON CONTINUE D'ESSAYER
NOMINAL   GET /config-kit toutes les 6 h (et au boot), X-Version
  ├─ 304 → rien   ├─ 200 → réécritures atomiques   └─ 403 → SUSPENDU
SUSPENDU  re-poll ralenti à 24 h ; 200 → NOMINAL ; 403 → rester
```

## Ce que les cas doivent prouver

- **l'idempotence de `/enroler`** : même secret + même clé → même 200 ;
  clé différente → 403 ;
- **`usine.json` est supprimé** à l'enrôlement réussi (invariant 2) : le
  secret est consommé côté serveur, le fichier n'a plus de valeur que pour
  un voleur ;
- **le re-poll ne s'arrête jamais** (invariant 4) : ralenti en suspendu,
  mais vivant — c'est lui qui détecte la reprise. **Un kit ne se débranche
  jamais tout seul** ;
- **coupure à chaque étape, reprise idempotente** — y compris le cas dur :
  la réponse perdue **après** traitement côté serveur ;
- **les modes et propriétaires des fichiers d'état** (annexe 2 §3.2) :
  `secret_api` et `tls/local.key` en **640 `root:smartbureau-lecture`**
  (GID 3000 figé), `registre/auth.json` en **600 `root`** ;
- **`endpoints.txt` ne contient que des IP** (invariant 5) ;
- **l'agent d'enrôlement n'applique jamais `release_cible`**
  (invariant 6) : il écrit le marqueur, l'updater exécute. Mélanger les
  deux mettrait une mise à jour logicielle dans la boucle de survie du
  tunnel ;
- **le watchdog bascule même l'agent d'enrôlement tué**, et il ne lit
  qu'`endpoints.txt`.

Le mock sait simuler les 304, les 403 de suspension, la règle de survie du
bloc `registre` et les coupures : voir son README.
