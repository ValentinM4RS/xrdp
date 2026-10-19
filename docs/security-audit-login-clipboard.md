# Audit de sécurité du collage dans le formulaire XRDP

Date : 19 octobre 2026. Dépôt : `ValentinM4RS/xrdp`, branche fournie `devel`.
Base : `5943357a546a24f3dc3781ccfd853e5dd24d6fcc`, version 0.10.80.
L'audit porte sur le diff local, fichiers nouveaux et non commités compris,
et ses interactions avec le code existant. La PR GitHub #3862 n'a pas servi de
source à cet audit. Les correctifs restent locaux, sans commit ni déploiement.

Les preuves et lanceurs de cette campagne sont conservés dans
`/workspace/artifacts/security-audit/`. Le patch complet est
`/workspace/artifacts/xrdp-login-clipboard.patch`. Les chemins absolus ci-dessous
décrivent cette machine ; les sources des tests et du fuzzer sont distribuées
avec le projet.

## A. Modifications auditées

### Surface d'attaque et responsabilités

Un client RDP non authentifié est considéré malveillant. Avec `ls_clipboard=true`,
il peut envoyer des capacités, listes de formats, réponses, messages inconnus
et fragments sur le canal statique `cliprdr`. Les événements clavier et souris
peuvent s'intercaler avec ces données et les transitions du formulaire.

Le nouveau gestionnaire appartient à un seul `xrdp_wm`. Il ne possède ni cache
partagé, ni service X11, ni transport supplémentaire, ni fichier de contenu.
Ses seuls messages sortants sont de petites structures protocolaires sans
valeur de champ. Il ne demande du texte qu'après Ctrl+V ou Shift+Insert avec une
destination active. Les requêtes de lecture des champs serveur échouent.
L'authentification conserve le chemin habituel vers sesman/PAM et le backend
configuré ; le collage ne décide jamais du succès de l'authentification.

Le réassemblage réserve environ 8 Kio par connexion activée, sans allocation
proportionnelle aux longueurs réseau. Chaque PDU est limité à 8 192 octets,
en-tête compris. Les longueurs effectives viennent du stream libxrdp
(`xrdp_channel_call_callback`), et non de la longueur annoncée par le client.
L'adaptateur valide séparément cette dernière. La destination et les fragments
incomplets expirent après 5 000 ms. Les champs sont limités à 255 octets UTF-8,
texte existant compris ; les rejets sont atomiques.

Le passage à chansrv intervient avant sa négociation et au succès du module.
Une ancienne réponse préauthentification est absorbée et effacée. Tant qu'elle
reste attendue, les nouvelles requêtes de texte de session échouent localement,
y compris si leur en-tête est fragmenté. Ensuite, les données suivent la route
antérieure. Cette précaution est nécessaire car cliprdr ne fournit pas
l'identifiant d'une requête de texte dans sa réponse.

Les callbacks de connexion utilisent la boucle d'événements XRDP ; les accès
au toolkit suivent son mutex existant. Aucun envoi RDP n'est ajouté sous le
verrou LVGL. Les tests de cycles concurrents LVGL existants ont été conservés.
Il n'y a pas eu de campagne ThreadSanitizer.

### Fichiers et points contrôlés

| Fichier | Nécessité, fonctions et hypothèses vérifiées |
| --- | --- |
| `README.md` | Lien de configuration ; caractère optionnel et défaut désactivé explicites. |
| `common/xrdp_scancode_defs.h` | Constantes V, Insert et pavé numérique ; distinction des scancodes étendus. |
| `docs/Makefile.am` | Distribution de la documentation et du présent rapport ; aucun effet runtime. |
| `docs/man/xrdp.ini.5.in` | Option, limites, sens unique et surface préauthentification documentés. |
| `docs/login-clipboard.md` | Architecture, activation, nettoyage, staging et limites des vérifications. |
| `docs/security-audit-login-clipboard.md` | Présent rapport ; preuves, alertes et vérifications manquantes. |
| `tests/xrdp/Makefile.am` | Enregistrement des tests/fuzzer et wrapper de nettoyage, uniquement dans le binaire de test. |
| `tests/xrdp/test_login.c` | Défaut désactivé, masque sans secret, saisie/suppression Unicode, soumission, focus, cycle LVGL et coordonnées signées. |
| `tests/xrdp/test_login_clipboard.c` | 22 cas : transport simulé, clavier réel, socket IPC, tailles, états, destruction, isolation, nettoyage et travail borné. |
| `tests/xrdp/fuzz_login_clipboard.c` | Parseurs de production et machine à états ; transports/UI/horloge remplacés ; 64 opérations maximum par entrée. |
| `tests/xrdp/run_login_clipboard_fuzz.sh` | Compilation libFuzzer/ASan/UBSan, seed, limites de temps/taille/RSS ; aucune dépendance ajoutée au serveur. |
| `tests/xrdp/test_xrdp.h` | Déclaration de la suite. |
| `tests/xrdp/test_xrdp_main.c` | Exécution de la suite par `make check`. |
| `xrdp/Makefile.am` | Compilation du gestionnaire et distribution de son en-tête. |
| `xrdp/xrdp.h` | Déclaration de `xrdp_bitmap_edit_remove_char`, partagée par Backspace/Delete. |
| `xrdp/xrdp.ini.in` | `ls_clipboard=false` ; aucune activation rétroactive. |
| `xrdp/xrdp_bitmap.c` | Capacité réelle lors de la saisie ; suppression des caractères secrets et effacement de la queue. |
| `xrdp/xrdp_bitmap_common.c` | `xrdp_bitmap_delete` : annulation de destination, focus parent, effacement borné, valeurs de module et ordre de libération. |
| `xrdp/xrdp_login.h` | Déclaration du nettoyage central des listes de valeurs possédées. |
| `xrdp/xrdp_login_clipboard.c` | Tous les nouveaux chemins : init/delete/cancel/key/data, capacités/formats/UTF-16, insertion, timeout, handoff et filtrage sortant. |
| `xrdp/xrdp_login_clipboard.h` | Contrat de consommation des fragments et propriété par WM. |
| `xrdp/xrdp_login_lvgl.c` | `field_value`, `secret_display`, `insert_field`, suppression, création/destruction, focus, paste, clavier, action et mutex ; repli legacy. |
| `xrdp/xrdp_login_lvgl.h` | API opaque de destination ; le jeton n'est pas déréférencé après une attente réseau. |
| `xrdp/xrdp_login_wnd.c` | Config, capacité des edits, `xrdp_login_submit/clear_values`, copies nécessaires et annulation via changement d'état. |
| `xrdp/xrdp_mm.c` | Destruction des valeurs, sortie chansrv/module, handoff et contrat du parseur `chansrvport`. |
| `xrdp/xrdp_mm.h` | Prototype du parseur interne testable, sans changement du protocole IPC. |
| `xrdp/xrdp_types.h` | État par WM, capacité d'allocation d'edit et option de configuration ; structures internes recompilées ensemble. |
| `xrdp/xrdp_wm.c` | Init/delete, clavier scancode/Unicode, souris, réception de canal, boucle d'attente et transitions de connexion. |

Revue complémentaire en lecture : acheminement et canaux désactivés de libxrdp,
constantes `MS-RDPECLIP`, fonctions UTF-8 de `common/string_calls.c`, allocations
`g_malloc/g_new0`, propriété des listes et transport `xrdp_mm_process_channel_data`.
Le protocole utilisé est un sous-ensemble texte de MS-RDPECLIP, sans fichiers,
images, propriété serveur ou verrouillage. Les messages non pris en charge sont
ignorés ou reçoivent un échec pour une demande de données. Aucune suite officielle
de certification de conformité RDP n'a été exécutée.

## B. Problèmes découverts et corrections

Les niveaux ci-dessous évaluent le contexte observé. Une faiblesse de nettoyage
ne démontre pas à elle seule une capacité de lecture distante du tas. Aucun
exploit critique ou élevé accessible à un client non authentifié n'a été démontré
dans les chemins audités ; cela n'établit pas leur absence.

### B1. Copies secrètes laissées à LVGL — moyenne

**Cause/conditions :** l'ancien adaptateur donnait le vrai mot de passe à
`lv_textarea_set_text/add_text`. Effacer le pointeur actuellement retourné par le
toolkit ne maîtrise pas ses anciennes allocations lors des modifications.
L'exploitation suppose une autre primitive de lecture mémoire, un dump ou un
accès au processus. Aucun lecteur distant de ces copies n'a été démontré.

**Impact :** rémanence de secrets au-delà de la durée utile du champ.
**Correction :** tampon canonique fixe de 256 octets par paramètre ; seuls les
astérisques entrent dans LVGL. Saisie, curseur Unicode, Backspace/Delete et collage
modifient le tampon canonique. Soumission de sa vraie valeur puis effacement.
**Validation :** régression masque-seul en échec avant correction
(`before-lvgl.log`), puis tests d'édition/soumission et suite LVGL sous ASan/UBSan.
Les autres assertions du premier essai sans fork étaient des cascades après
l'échec de fixture initial, pas des vulnérabilités indépendantes.

### B2. Effacement de 256 octets sans connaître l'allocation — moyenne

**Cause/conditions :** le premier patch nettoyait systématiquement 256 octets
pour un edit legacy. Un objet dont `caption1` possède une allocation plus petite
sortait de ses limites à la destruction. Les constructeurs normaux du formulaire
allouent 256 octets : aucune façon de fabriquer l'allocation courte à distance
par ces constructeurs n'a été établie.

**Impact :** écriture hors allocation lors d'un usage interne différent.
**Correction :** capacité mémorisée lors de l'allocation ; effacement de cette
capacité, ou de la longueur de chaîne lorsque la capacité est inconnue. La saisie
et le collage utilisent aussi la capacité réelle.
**Validation :** petit edit alloué par `g_strdup`, échec avant correction et succès
après. Le test vérifie la plage de `OPENSSL_cleanse` avec l'API ASan, car le code
assembleur non instrumenté de libcrypto ne signalait pas lui-même ce débordement.
`before-asan.log` est donc un échec de contrôle de plage utilisant ASan, pas un
rapport natif ASan de heap-buffer-overflow.

### B3. Destination de collage sans échéance avant le premier fragment — moyenne

**Cause/conditions :** l'ancien délai ne commençait qu'à la réception d'un
fragment ; un client pouvait attendre arbitrairement avant sa première réponse.
**Impact :** insertion très tardive dans un formulaire resté actif, rétention
d'une destination et indisponibilité du collage sur cette connexion.
**Correction :** échéance de 5 s dès la requête ; annulation de la destination
mais conservation de la requête en attente jusqu'au drainage de sa réponse.
**Validation :** `test_clip_request_deadline`, horloge avancée sans attente réelle,
réponse tardive ignorée et nouvelle demande explicite fonctionnelle après drainage.

### B4. Durée de vie/focus des champs insuffisamment explicités — moyenne

**Cause/conditions :** une destination conservée par adresse doit être annulée
avant destruction/reconstruction et avant toute perte de focus, même programmatique.
Une comparaison d'adresse seule ne protège pas du recyclage d'une allocation.
**Impact potentiel :** insertion dans un nouveau champ reprenant cette adresse ;
les gardes de focus existantes empêchaient plusieurs autres chemins. Aucun
use-after-free exploitable n'a été reproduit.
**Correction :** annulation à la destruction d'edit/fenêtre, reconstruction LVGL,
actions et événement DEFOCUSED ; remise à NULL du focus parent legacy.
**Validation :** champ détruit avant réponse, changement de focus/aide/soumission,
isolation entre deux WM et cycles de destruction sous sanitizers.

### B5. Requête de session fragmentée pendant le drainage — moyenne, conditionnelle

**Cause/conditions :** un message sortant dont le type n'était pas entièrement
dans le premier fragment pouvait contourner une décision fondée sur ce seul
fragment. La réponse prélogin pouvait aussi arriver entre deux fragments.
Le chansrv standard envoie sa petite requête en un bloc ; le cas vise notamment
un module qui fragmente plus finement.
**Impact potentiel :** ambiguïté entre ancienne réponse prélogin et requête de
session, avec risque de transfert de l'ancien contenu à la session.
**Correction :** quarantaine de tout le message, suivi des deux octets du type et
un seul échec local, même si l'ancienne réponse arrive entre les fragments.
**Validation :** `test_clip_fragmented_outbound_request` et tests de drainage,
passage pendant une réponse fragmentée, puis reprise de la route normale.

### B6. Amplification du travail d'effacement — moyenne

**Cause/conditions :** deux effacements de 8 Kio par minuscule PDU, plus des
ré-effacements du corps déjà traité sur une réponse annulée fragmentée ; client
préauthentifié envoyant beaucoup de petits messages, option activée.
**Impact potentiel :** consommation CPU et trafic mémoire disproportionnés ;
aucune mesure de saturation globale multiutilisateur n'a été réalisée.
**Correction :** effacement de la zone réellement reçue, reste maintenu à zéro ;
chaque nouveau morceau annulé est effacé une fois, sans retraiter tout le préfixe.
**Validation :** compteur du wrapper de nettoyage : 1 024 PDUs de 8 octets doivent
entraîner au plus 32 Kio d'effacement, contre environ 16 Mio auparavant ; invariants
zéro et fuzzing conservés. Ce test mesure du travail mémoire, pas un débit réseau.

### B7. Valeurs abandonnées et queues de champs secrets — moyenne

**Cause/conditions :** des copies du modèle étaient libérées sans effacement ;
le helper UTF-8 legacy déplace le terminateur sans nettoyer les anciens octets
au-delà. Conditions d'exploitation comparables à B1. Ces comportements existent
dans la base et deviennent aussi des chemins de vie des secrets collés.
**Impact :** rémanence de valeurs remplacées ou de caractères supprimés.
**Correction :** `xrdp_login_clear_values` avant remplacement/destruction des listes
possédées ; `xrdp_bitmap_edit_remove_char` commun à Backspace/Delete efface la queue
secrète selon sa capacité connue. Le helper LVGL efface également la queue.
**Validation :** reproduction directe du helper préexistant conservant des octets
(`before-deleted-tail.log`), puis test de suppressions Unicode et contrôle de toute
la queue ; cycles de soumission, destruction et ASan/UBSan. Les copies encore
nécessaires au backend sont conservées jusqu'à leur nettoyage normal.

### B8. Destination NULL dans la validation de chansrvport — faible, préexistant

**Cause/conditions :** le mode documenté de validation seule appelait
`strlcpy(NULL, value, 0)` pour un chemin littéral. Clang a relevé cette violation
du contrat de destination. Il s'agit de configuration serveur, pas de contenu
clipboard distant ; aucun crash exploitable à distance n'a été démontré.
**Correction :** copie seulement avec destination et taille positives ; le mode
`DISPLAY(...)` conserve son formatage de taille zéro autorisé par snprintf.
**Validation :** requêtes sans destination pour chemin et DISPLAY, et copie réelle
avec destination ; disparition de l'alerte Clang concernée.

### B9. Conversion non signée des offsets LVGL — faible, robustesse préexistante

Cppcheck a trouvé `value * ui->dpi / 96` avec `value` négatif et DPI non signé.
Cela transforme des coordonnées décoratives négatives en grandes valeurs positives.
Aucun accès mémoire interdit n'a été démontré. La multiplication reste maintenant
signée ; le DPI est déjà borné à 96..384. Une assertion sur un offset négatif est
incluse dans le test LVGL d'édition/soumission ; rendu et suites ont été relancés.
Ce constat est un défaut de coordonnées, pas une élévation de privilèges.

## C. Tests réellement exécutés

### Commandes et résultats

Les commandes de cette machine utilisent les dépendances isolées de
`/workspace/.xrdp-env`, sans installation sur les services existants.

```sh
source /workspace/.xrdp-env/activate.sh
bash /workspace/scratch/xrdp-clipboard/final_checks.sh
bash /workspace/scratch/xrdp-audit/asan_lvgl.sh
python3 /workspace/artifacts/security-audit/run-static.py
python3 /workspace/scratch/xrdp-audit/native_audit.py
```

Les deux scripts de build, copiés en `run-checks.sh` et `run-asan-lvgl.sh` dans les
preuves, contiennent notamment les commandes effectivement exécutées :

```sh
make -C /workspace/.xrdp-env/build -j4
make -C /workspace/.xrdp-env/build check -j4
make -C /workspace/.xrdp-env/build distdir
make -C /workspace/.xrdp-env/clipboard-asan -j4
make -C /workspace/.xrdp-env/clipboard-asan/tests/xrdp test_xrdp
# Dans clipboard-asan/tests/xrdp :
CK_RUN_SUITE=login_clipboard CK_FORK=no ASAN_OPTIONS=detect_leaks=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./test_xrdp
# Avec les chemins LVGL/Fontconfig des scripts :
make -C /workspace/.xrdp-env/clipboard-lvgl -j4
make -C /workspace/.xrdp-env/clipboard-lvgl check -j4
# Dans audit-asan-lvgl/tests/xrdp, après compilation instrumentée :
CK_RUN_SUITE=login CK_FORK=no ASAN_OPTIONS=detect_leaks=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./test_xrdp
```

| Vérification | Statut et résultat constaté |
| --- | --- |
| Compilation GCC avec avertissements du projet traités comme erreurs, legacy et LVGL 9.3 | **PASS**. |
| Répertoire de distribution Autotools (`make distdir`) | **PASS**, nouveaux fichiers de documentation/tests/gestionnaire présents. |
| Suite complète legacy | **PASS**, 273 tests, 0 échec, 0 saut. |
| Suite complète LVGL | **PASS**, 282 tests, 0 échec, 0 saut. |
| Suite clipboard ASan + UBSan + détection de fuites | **PASS**, 22 tests, aucun diagnostic sanitizer. |
| Suite formulaire/modèle LVGL ASan + UBSan + détection de fuites | **PASS**, 10 tests, aucun diagnostic sanitizer. |
| Régressions avant correction | **FAIL**, masque LVGL et plage de nettoyage d'edit court ; défauts corrigés. Reproduction séparée des octets supprimés rémanents. |
| Corpus déterministe dans les tests | **PASS**, 4 096 PDUs malformés ; pas de crash/insertion inattendue, nettoyage contrôlé. |
| Socket IPC réelle WM → route chansrv | **PASS**, en-tête IPC et données vérifiés ; ce n'est pas un vrai bureau. |
| libFuzzer final | **PASS**, 2 919 456 exécutions en 61 s ; pas de crash, timeout ou diagnostic sanitizer ; 516 points de couverture signalés par l'outil, sans pourcentage de couverture revendiqué. |
| Clang Static Analyzer 19 | **PASS exécution**, sept fichiers C, codes retour 0 ; six alertes de dead stores préexistantes, analysées manuellement. Ce n'est pas une sortie sans avertissement. |
| Cppcheck 2.17.1, seuil zéro alerte | **FAIL du seuil**, sortie 1 : cinq alertes restantes, qualifiées ci-dessous ; aucune alerte supprimée pour obtenir zéro. |
| FreeRDP 3.15 natif, TLS avec empreinte vérifiée | **PASS**, trois connexions/déconnexions sur serveur isolé ; collage utilisateur accentué et mot de passe masqué sous LVGL ; captures examinées. |
| Recherche du mot de passe généré dans les logs serveur/daemon | **PASS**, absent en UTF-8 et UTF-16LE ; valeur jamais imprimée ni écrite par le pilote. |
| Login réel réussi/PAM, ouverture Xorg, clipboard dans le bureau authentifié | **BLOCKED**, compte cloud refusé par les contrôles PAM du système. |
| Windows mstsc et Remmina | **NOT RUN**, clients absents de cette campagne. |
| Redémarrage réel de sesman/chansrv avec session ouverte | **NOT RUN** ; aucune session authentifiée disponible et aucun service existant redémarré. |
| ThreadSanitizer, Valgrind, 32 bits, autres OS, campagne réseau multiutilisateur prolongée | **NOT RUN**. |

La suite LVGL produit des avertissements Fontconfig sur le cache non inscriptible
et des avertissements attendus de repli/DPI ; les polices se chargent et les tests
passent. Ils restent dans les logs. Ils ne sont pas des diagnostics ASan.

Le build instrumenté utilise `-fsanitize=address,undefined
-fno-sanitize=alignment -fno-omit-frame-pointer`, avec les symboles de debug.
L'exception d'alignement correspond à la configuration UBSan existante du projet :
ce contrôle particulier n'est donc pas couvert. Les bibliothèques système,
OpenSSL et la bibliothèque LVGL installée ne sont pas intégralement recompilées
avec les sanitizers. Le wrapper de nettoyage des tests vérifie la plage d'écriture
libcrypto ; le fuzzer ajoute une écriture instrumentée de cette plage. Aucune
prétention de détection de toutes les copies internes de ces bibliothèques.

### Fuzzing reproductible

Commande finale réellement utilisée, environnement activé :

```sh
export LD_LIBRARY_PATH="/workspace/.xrdp-env/audit-tools/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
CLANG=/workspace/.xrdp-env/audit-tools/usr/bin/clang-19 \
  XRDP_BUILD_DIR=/workspace/.xrdp-env/build \
  XRDP_FUZZ_DIR=/workspace/scratch/xrdp-audit/fuzz-final \
  XRDP_FUZZ_SECONDS=60 bash tests/xrdp/run_login_clipboard_fuzz.sh
```

Limites : seed 816862, entrée 16 384 octets, RSS 512 Mio, timeout par entrée 5 s,
64 opérations maximum. Le corpus final est archivé dans `fuzz-corpus.tar.gz`.
Le harnais exerce directement UTF-16, capacités, formats courts/longs, réception,
requêtes explicites, annulation, changement de focus, échéance, handoff, sortie et
suppression/réinitialisation. Le gestionnaire inclus est le fichier de production.
Les interfaces réseau et UI sont remplacées ; les helpers de `libcommon` liés
par ce harnais ne sont pas instrumentés. Les suites ASan séparées instrumentent
le code du projet concerné. Ce fuzzing de fonctions n'est pas un fuzzer de toute
la pile TLS/RDP sur le réseau et une minute ne constitue pas une campagne longue.

### Qualification des analyses statiques

`clang-static-commands.json` conserve chaque commande. Les six dead stores
restants sont dans `xrdp_bitmap.c` (navigation de focus), `xrdp_mm.c` (quatre
assignations de choix H.264) et `xrdp_wm.c` (initialisation du nom d'état). Les
lignes correspondantes sont inchangées par le patch ; aucun impact sécurité
associé n'a été établi. Elles ne sont pas présentées comme corrigées.

Cppcheck a été exécuté sur les sept unités modifiées prétraitées avec les vrais
en-têtes/configurations, dont LVGL actif pour son adaptateur. Le pilote conserve
`preprocess-commands.json`, les fichiers prétraités et sa commande finale.
Quatre alertes restantes concernent les streams `s` de
`dynamic_monitor_open_response` et `fs` de `xrdp_wm_load_pointer`. Le contrôle
conditionnel générique de `free_stream` trompe l'analyse locale : `make_stream`
utilise `g_malloc`, qui appelle ici `g_calloc_nofail/g_malloc_nofail` et termine le
processus en cas d'échec, sans retourner NULL. Ces alertes sont donc des faux
positifs de NULL sur ces chemins, pas des vérifications d'allocation retirées.
La cinquième alerte est une conversion non signée signalée malgré le cast
explicite `(int)ui->dpi` corrigé en B9. Elle a été reproduite dans un programme
minimal (`signed-scale.c`, `cppcheck-signed-cast.log`) : compilation avec
`-Wsign-conversion -Werror`, exécution vérifiant le résultat négatif et régression
LVGL passent. C'est un faux positif de cette version de Cppcheck après correction.
Les numéros de ligne de Cppcheck sur fichiers prétraités sont parfois attribués
au dernier en-tête inclus ; les fonctions ont été retrouvées dans la source.

Deux essais d'outillage ne constituent pas des analyses réussies : un balayage
Cppcheck de toutes les combinaisons de macros a été interrompu car trop coûteux ;
l'import de compilation database a perdu les guillemets des macros de chemins
et produit des erreurs de prétraitement. Le passage par le préprocesseur du
compilateur corrige cette configuration sans masquer d'alerte du code.

### Matrice des scénarios demandés

| Scénario | Preuve / limite |
| --- | --- |
| 1. Longueur zéro | **PASS**, `test_clip_extreme_framing`, NULL/0 sans accès au contenu. |
| 2. Paquet tronqué | **PASS**, réassemblage incomplet/échéance, corpus et fuzzing. |
| 3. Dépassement du maximum | **PASS**, total > 8 192 et refus du texte trop grand. |
| 4. Longueurs incohérentes | **PASS**, tests de framing et longueur de corps annoncée. |
| 5. Entiers extrêmes | **PASS**, INT_MIN, INT_MAX, négatifs et UINT32 dans les en-têtes. |
| 6. UTF-16 incorrect | **PASS**, surrogates isolés, NUL intégré, contrôles et fuzzing. |
| 7. Sans terminateur | **PASS**, refus sans insertion ni troncature. |
| 8. Hors ordre | **PASS au niveau fonctions**, réponse non sollicitée ignorée, continuation orpheline/corpus/fuzzing ; pas de campagne d'injection réseau exhaustive. |
| 9. Après déconnexion | **PASS au niveau callback**, WM détaché ignoré et état détruit ; pas de simulation de segments TCP à tous les niveaux. |
| 10. Connexions/déconnexions rapides | **PASS**, 100 cycles locaux ; trois connexions TLS natives séquentielles, sans revendication de test de charge. |
| 11. Focus pendant collage | **PASS**, clavier, focus alternatif, aide, destruction, annulation ; ancien texte jamais inséré dans le nouveau champ testé. |
| 12. Authentifications refusées répétées | **PASS pour les transitions simulées**, dont 100 cycles et erreur LVGL existante ; **NOT RUN pour une boucle de refus PAM réelle** pendant cet audit. |
| 13. Redémarrage de composant de session | **NOT RUN réel** ; tests de handoff et transport seuls. |
| 14. Collages répétés de milliers de caractères | **PASS**, 256 réponses de 3 000 caractères, fragmentées et refusées en entier, état/buffers contrôlés. |
| 15. Champ détruit | **PASS**, réponse après destruction sans invalidation/insertion ; sanitizers. |

## D. Risques résiduels

- Activer `ls_clipboard` ajoute une surface préauthentification. Le défaut reste
  désactivé ; les canaux et l'autologin existants gardent leur politique. Les
  bornes locales ne remplacent pas les protections d'admission des connexions.
- Un client peut toujours consommer le CPU de sa connexion par du trafic continu.
  Le travail mémoire disproportionné identifié a été corrigé, mais aucune limite
  globale de connexions ni politique de débit n'a été ajoutée ou modifiée.
- Sans réponse à une requête annulée, le collage reste indisponible pour cette
  connexion jusqu'au drainage ou à la reconnexion. L'état conservé est fixe,
  la destination n'est plus utilisable après expiration et les données partielles
  sont effacées. Ce choix évite de réassocier une réponse sans identifiant.
- Pendant cette quarantaine seulement, un message sortant dont le premier fragment
  ne contient pas les deux octets du type peut être abandonné entièrement, même
  s'il s'avère d'un autre type. Le chansrv standard construit son en-tête complet ;
  un module fragmentant autrement nécessite une validation spécifique.
- Le client contrôle le texte qu'il fournit et les événements d'entrée de sa
  propre connexion. Le serveur ne peut pas garantir que ce texte correspond à
  ce que l'utilisateur croyait avoir dans le presse-papiers d'un client compromis.
- Les valeurs de connexion sont nécessairement transmises au flux d'authentification
  et au backend configuré. Le nouveau gestionnaire ne les exporte pas par cliprdr
  et ne les envoie à aucun autre destinataire. TLS, le client, les copies des
  bibliothèques, le swap et les cores restent hors de cette garantie d'effacement.
- Les résultats ne prouvent pas l'absence de vulnérabilité, de fuite ou de course.
  Fuzzing fini, dépendances partiellement instrumentées, UBSan sans alignement et
  absence de session authentifiée limitent la conclusion. Pas de test à long terme
  de l'épuisement mémoire global ni de preuve formelle de conformité protocolaire.

## E. Compatibilité et validations restantes

**Vérifié :** ce fork devel 0.10.80 sur Debian 13 amd64, GCC strict, configuration
legacy sans dépendance toolkit obligatoire, configuration LVGL 9.3, saisie et
suppression manuelles/Unicode, masquage, Ctrl+V/Shift+Insert, clavier spécial,
repli legacy, option désactivée, WM indépendants et route IPC de session.
FreeRDP 3.15 fonctionne avant authentification avec TLS et certificat épinglé.
Les tests antérieurs du même développement avaient aussi exercé le formulaire
legacy natif ; la campagne native de cet audit vise LVGL et les déconnexions.

**Non établi :** tous les autres tags XRDP 0.10.x, Windows mstsc, Remmina,
architectures 32 bits, configurations complètes de codecs/FUSE et comportement
réel du presse-papiers après authentification. La compilation d'un fork devel ne
vaut pas validation de tous les paquets 0.10.x distribués.

Sur une machine de préproduction avec compte PAM et xorgxrdp utilisables :

1. Compiler/installer le paquet dans un staging revu, puis lancer une instance de
   validation isolée avec le certificat prévu, clipboard activé et désactivé.
2. Pour mstsc, Remmina et FreeRDP, essayer ASCII/Unicode, saisie manuelle, Ctrl+V,
   Shift+Insert, absence de canal clipboard, texte long et changement de focus.
3. Refuser plusieurs authentifications puis réussir la suivante ; vérifier PAM,
   ouverture Xorg, collage bidirectionnel dans le bureau et reconnexion à la session.
4. Soumettre pendant une réponse lente ; vérifier qu'aucun ancien secret de login
   ne devient le clipboard du bureau. Exercer plusieurs utilisateurs simultanés.
5. Sur cette instance de validation uniquement, tester l'arrêt/reprise de chansrv
   et de sesman, déconnexions pendant fragments et reconnexion. Contrôler les logs
   avec des secrets générés en mémoire, jamais affichés ou inclus aux commandes.

Aucun PAM, certificat, clé, politique d'authentification ou service existant n'a été
modifié pendant l'audit. Les instances de test ont leur propre port loopback,
configuration et cycle de vie. Les processus xrdp/sesman présents au début ont
conservé leurs PID et leur date de démarrage.

## F. Décision de sécurité

Les problèmes identifiés dans les chemins ajoutés ont été corrigés et accompagnés
de régressions. Les deux variantes compilent ; 273/282 tests complets, 22 tests
clipboard et 10 tests du formulaire instrumentés passent. Le fuzzing n'a pas
signalé d'incident sur sa campagne finie et l'essai TLS natif confirme le collage
masqué avant authentification. Les alertes statiques restantes sont documentées
et qualifiées ; aucun défaut critique/élevé exploitable n'a été démontré dans le
périmètre vérifié.

Ce résultat autorise l'étape de validation sur une préproduction disposant des
clients et sessions manquants. La mise en production reste conditionnée aux
vérifications de la section E, particulièrement PAM/Xorg et clipboard après login.
Il ne s'agit pas d'une garantie d'absence de vulnérabilité.

**PRÊT POUR VALIDATION EN PRÉPRODUCTION.**
