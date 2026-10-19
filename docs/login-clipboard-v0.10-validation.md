# Validation du portage clipboard sur v0.10

Base : `0ed6e5ea2d64b999bd6ddf6bbceabd42a4d33e4f`, version annoncée 0.10.6.1,
branche distante `ValentinM4RS/xrdp:v0.10`. Campagne du 19 octobre 2026,
Debian 13 amd64. Le code provient du gestionnaire audité du commit `8bbfc2ee`,
adapté au formulaire et aux interfaces stables de cette branche.

## Adaptations vérifiées

- API clavier `device_flags`/scancode v0.10 : modificateurs stockés dans
  `keys[29/56]`, touches Shift, Ctrl droit, Insert étendu et NumLock.
- Initialisation et option dans le chargeur de configuration natif ; absence de
  configuration équivalente à `ls_clipboard=false`.
- Acheminement WM et callback `intptr_t` de v0.10 ; test passant par une vraie
  socket UNIX représentant le transport de chansrv.
- Handoff dans la machine de connexion stable, avant négociation des canaux de
  session et au succès du module, sans transfert des anciennes réponses.
- Nettoyage utilisant la capacité réelle des edits, des caractères secrets
  supprimés et des valeurs abandonnées ; correction du mode de validation sans
  destination de `chansrvport` également nécessaire sur cette branche.
- Helper de millisecondes monotones, bornes réseau et état de requête conservés.
  Le délai clipboard est appliqué après les délais du module, avec une régression
  qui vérifie qu'un module ne repousse pas l'expiration d'un fragment incomplet.
- Liaison explicite avec OpenSSL déjà présent et sous-modules épinglés de v0.10.

La branche conserve son interface native et ses fichiers de configuration clavier
`.ini`. Le portage n'importe pas les API scancode, le format clavier TOML ou le
sous-système graphique LVGL de devel.

## Vérifications exécutées

Les preuves, commandes détaillées et captures masquées de la machine cloud sont
conservées dans `/workspace/artifacts/v0.10-clipboard/`.

```sh
source /workspace/.xrdp-env/activate.sh
autoreconf -fvi
# Dans /workspace/.xrdp-env/v0.10-build :
CONFIG_SHELL=/bin/bash /bin/bash /workspace/xrdp/configure \
  --prefix=/workspace/.xrdp-env/v0.10-local --enable-strict-locations \
  --with-socketdir=/workspace/.xrdp-env/v0.10-run \
  --with-systemdsystemunitdir=no --enable-tests --enable-pixman
make -j4
make check -j4
make install
```

L'installation ci-dessus concerne seulement le préfixe isolé de test dans
`/workspace/.xrdp-env/v0.10-local`, pour les assets et binaires nécessaires aux
essais. Aucun service existant ni configuration de production n'a été modifié.

| Vérification | Résultat |
| --- | --- |
| Compilation native GCC `-Wall -Wwrite-strings -Werror` | **PASS** |
| Suite complète `make check` sur la base v0.10 | **PASS**, 256 tests, 0 échec, 0 saut |
| Suite clipboard ASan + UBSan, fuites activées | **PASS**, 26 tests, 0 échec, aucun diagnostic sanitizer |
| Échec d'allocation du nouveau gestionnaire | **PASS**, désactivation sans envoi réseau ni déréférencement de son état absent |
| Clavier stable et lecture réelle de configuration | **PASS**, défaut désactivé, activation, Ctrl droit, AltGr, Insert et NumLock |
| Entrées malformées et nettoyage | **PASS**, corpus déterministe de 4 096 PDUs et bornes de taille/entiers/Unicode |
| Textes volumineux et cycle de vie | **PASS**, 256 refus atomiques de 3 000 caractères, 100 cycles de réinitialisation, champ détruit et connexions indépendantes |
| Composition du délai clipboard avec le module | **PASS**, un délai module de 60 s ne repousse pas une échéance clipboard atteinte |
| Route WM vers transport de session | **PASS**, socket UNIX, framing IPC et contenu vérifiés |
| Client FreeRDP 3.15, TLS avec empreinte du certificat épinglée | **PASS**, trois connexions/déconnexions, Ctrl+V dans Username et Maj+Inser dans Password |
| libFuzzer + ASan/UBSan sur les parseurs et la machine à états | **PASS**, 3 315 970 exécutions en 61 s, aucun crash, timeout ou diagnostic sanitizer |
| Clang Static Analyzer 19 | **PASS exécution**, sept unités C ; six affectations inutilisées préexistantes, sans sortie sans avertissement revendiquée |
| Cppcheck 2.17.1, seuil zéro alerte | **FAIL du seuil**, 70 diagnostics d'allocations non vérifiées, comparés aux 69 de la base ; détails ci-dessous |
| Masquage et logs | **PASS**, captures examinées et mot de passe généré absent des logs serveur/daemon en UTF-8 et UTF-16LE ; valeur non imprimée |

Le build instrumenté utilise `-g -O1 -fsanitize=address,undefined
-fno-sanitize=alignment -fno-omit-frame-pointer`, avec `CK_FORK=no`,
`ASAN_OPTIONS=detect_leaks=1` et `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
L'exception d'alignement correspond à la configuration sanitizer du projet.
Les bibliothèques système ne sont pas toutes instrumentées. Le wrapper de
nettoyage vérifie la plage passée à libcrypto, dont l'assembleur peut échapper
à l'instrumentation habituelle.

Les essais natifs utilisent une instance séparée sur `127.0.0.1:3393`, Xvfb et
les outils X11 uniquement pour piloter le client. Le mot de passe de test est
généré en mémoire ; le serveur ne journalise pas sa valeur. Les processus de test
sont terminés à la fin, sans redémarrer les démons présents avant cette campagne.

## Analyses statiques et avertissements de la base

Les pilotes `run-static.py` et `compare-static-base.py` ainsi que les commandes
et logs sont conservés avec les preuves. Le second analyse une archive propre du
commit de base avec les mêmes en-têtes de configuration et options de compilation.
Aucune alerte n'a été supprimée pour atteindre un seuil artificiel de zéro.

Les six alertes Clang concernent des affectations inutilisées dans la navigation
de focus, le choix H.264 et le nom d'état ; les instructions sont inchangées.
Cppcheck signale 69 diagnostics de déréférencement possible après échec d'allocation
sur la base stable et 70 après portage. La différence est un diagnostic interunités
sur l'appel ajouté de `xrdp_login_clipboard_cancel` depuis le setter d'état :
`xrdp_wm_create` possède déjà des déréférencements de `self` non vérifiés entre son
allocation et ce setter. Le diagnostic supplémentaire prolonge ce même chemin
préexistant, qui échoue avant d'atteindre le nouveau gestionnaire.

Contrairement à devel, `g_malloc/g_new0` de v0.10 peuvent retourner NULL ; ces
avertissements ne sont donc pas présentés comme de simples faux positifs fondés
sur des allocations qui termineraient systématiquement le processus. La correction
de toutes les allocations historiques dépasse ce portage. Les diagnostics
préexistants restent ouverts et un épuisement mémoire peut provoquer un crash
dans le code existant. La nouvelle allocation clipboard est vérifiée et un test
injecte son échec pour vérifier sa désactivation propre. Le parseur ajouté ne
produit pas d'alerte locale dans ces analyses.

Le fuzzing est une campagne finie de fonctions : maximum 16 384 octets par entrée,
64 opérations, timeout de 5 s et limite RSS de 512 Mio, seed 816862. Le harnais
remplace les transports et le dessin ; `libcommon` lié au fuzzer n'est pas
instrumenté, tandis que le build sanitizer séparé instrumente les sources du
projet. La campagne ne couvre pas toute la pile TLS/RDP sur le réseau. Pour
reproduire celle de cette machine, après activation de l'environnement :

```sh
export LD_LIBRARY_PATH="/workspace/.xrdp-env/audit-tools/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
CLANG=/workspace/.xrdp-env/audit-tools/usr/bin/clang-19 \
  XRDP_BUILD_DIR=/workspace/.xrdp-env/v0.10-build \
  XRDP_FUZZ_DIR=/workspace/scratch/xrdp-v0.10/fuzz \
  XRDP_FUZZ_SECONDS=60 bash tests/xrdp/run_login_clipboard_fuzz.sh
```

## Limites de compatibilité

- **BLOCKED** : login PAM réussi, bureau Xorg/xorgxrdp et collage de bout en bout
  après authentification ; le compte cloud est refusé par les contrôles PAM.
- **NOT RUN** : Windows mstsc, Remmina, architectures 32 bits, autres OS et tous
  les autres tags ou paquets XRDP 0.10.x.
- **NOT RUN** : redémarrage réel de sesman/chansrv avec une session authentifiée,
  test de charge multiutilisateur prolongé et ThreadSanitizer.

La compatibilité vérifiée porte sur cette révision v0.10/0.10.6.1 et sur les
chemins exécutés. Elle ne constitue pas une garantie d'absence de vulnérabilité
ni une certification de toutes les configurations XRDP 0.10.x. Avant production,
valider PAM/Xorg, le collage bidirectionnel dans le bureau, les reconnexions et
les clients utilisés, avec l'option activée puis désactivée.
