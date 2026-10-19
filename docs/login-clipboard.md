# Collage dans le formulaire de connexion

Cette modification cible le dépôt `ValentinM4RS/xrdp`, branche `devel`, à partir
du commit `5943357a546a24f3dc3781ccfd853e5dd24d6fcc` (version annoncée 0.10.80).
Elle ajoute le collage **avant authentification**, dans les champs éditables
du formulaire legacy et de l'interface LVGL optionnelle. Un portage sur une
autre révision 0.10.x demande une compilation et des tests sur cette révision.

## Diagnostic et architecture

Les issues amont [#816](https://github.com/neutrinolabs/xrdp/issues/816) et
[#862](https://github.com/neutrinolabs/xrdp/issues/862), consultées pendant le
développement, décrivent ce même manque. #862 renvoie à #816. Les discussions
mentionnent le démarrage tardif de chansrv, le coût de l'implémentation et la
surface d'attaque supplémentaire avant authentification ; elles évoquent aussi
la possibilité de ne recevoir que `CF_UNICODETEXT` dans un seul sens.

Le code de cette révision confirme ce diagnostic :

- `xrdp_wm_key()` distribue les événements aux widgets legacy ou à LVGL. Le champ
  legacy, dans `xrdp_bitmap_def_proc()`, insère les caractères imprimables, mais
  ne possède pas de commande pour récupérer le presse-papiers local. Ctrl+V
  peut donc se traduire par la saisie d'un simple `v`.
- `xrdp_wm_process_channel_data()` transmet habituellement les canaux au module
  ou à `xrdp_mm_process_channel_data()`, qui les envoie au transport de chansrv.
  Ce transport n'est pas disponible sur le formulaire initial.
- `xrdp_mm_chansrv_connect()` n'est appelé qu'après l'authentification et la
  connexion au serveur d'affichage. Le chansrv de la session, dont
  `clipboard_init()` utilise X11 et les sélections du bureau, négocie alors
  `cliprdr`. Changer `sesman.ini` ne fournit pas ce gestionnaire au formulaire.

`xrdp_login_clipboard.c` fournit maintenant un gestionnaire par connexion,
propriété de `struct xrdp_wm`. Il réutilise le canal statique `cliprdr` déjà
négocié par libxrdp, sans démarrer chansrv ni un serveur X supplémentaire :

1. Envoi des capacités minimales et de `CB_MONITOR_READY`.
2. Réception et acquittement des formats courts ou longs annoncés par le client.
   Aucun contenu n'est demandé à ce stade.
3. Sur Ctrl+V ou Shift+Insert, si un champ est actif et si `CF_UNICODETEXT` est
   disponible, envoi d'une seule requête `CB_FORMAT_DATA_REQUEST`.
4. Réassemblage borné, validation UTF-16LE, conversion UTF-8, puis insertion
   atomique au curseur. Le mot de passe conserve son masquage habituel.
5. Annulation de la destination si l'utilisateur change de champ, saisit une
   autre touche, utilise la souris ou soumet/quitte le formulaire.
6. Passage à chansrv avant sa négociation de canaux. En fonctionnement normal,
   les fragments de la session suivent ensuite exactement leur route précédente.

Les réponses clipboard ne contiennent pas d'identifiant de requête. Si une
ancienne requête est encore en vol pendant le passage à la session, son contenu
est absorbé et effacé. Les éventuelles nouvelles requêtes de chansrv reçoivent
temporairement un échec local, sans être envoyées au client, jusqu'à réception
de cette ancienne réponse. Celle-ci ne peut donc pas devenir le presse-papiers
du bureau. Il peut être nécessaire de refaire le premier collage dans le bureau.
Si un client ne répond jamais, le clipboard reste indisponible pour cette
connexion ; reconnecter réinitialise cet état. L'authentification n'est pas bloquée.

## Activation

Dans les sections **existantes** de `xrdp.ini` :

```ini
[Globals]
ls_clipboard=true

[Channels]
cliprdr=true
```

`ls_clipboard` vaut `false` par défaut. Le client doit autoriser la redirection
du presse-papiers et négocier `cliprdr`. `allow_channels=false` et les canaux
désactivés par la configuration continuent d'être respectés. Aucun changement
de PAM, de `sesman.ini`, de TLS ou de politique d'authentification n'est requis.
Une connexion automatique qui ne présente pas de formulaire n'initialise pas
ce gestionnaire.

Pour désactiver cette fonctionnalité, remettre `ls_clipboard=false` ; le
presse-papiers de la session Linux conserve son fonctionnement habituel.
Les paramètres s'appliquent aux nouvelles connexions. Les clients déjà connectés
ne chargent pas rétroactivement un nouveau binaire.

## Limites et sécurité

- Sens unique client → champ de connexion. Aucun Ctrl+C/Ctrl+X du formulaire,
  aucune publication des champs, aucun accès aux fichiers, images ou formats
  riches. Les requêtes pour lire le presse-papiers serveur sont refusées.
- Seul le texte Unicode terminé par NUL est accepté. Les surrogates invalides,
  NUL intégrés, caractères de contrôle et séparateurs de ligne sont refusés.
  Les caractères non BMP sont pris en charge. Aucune normalisation Unicode ni
  suppression d'espaces n'altère un identifiant ou un mot de passe.
- La limite existante est **255 octets UTF-8 par champ**, texte déjà présent
  compris. Ce sont des octets, pas 255 caractères Unicode. Un collage qui dépasse
  cette limite est refusé en entier ; aucun mot de passe tronqué n'est soumis.
  Le formulaire n'ajoute pas ici de sélection de texte ni de Ctrl+A.
- Chaque PDU pré-session est limité à 8 Kio, en-tête compris. Les longueurs,
  fragments, capacités et noms de formats sont bornés avant accès mémoire.
  La destination expire cinq secondes après la requête explicite, même sans
  premier fragment. Un réassemblage incomplet expire aussi après cinq secondes.
  La réponse tardive reste à drainer avant toute nouvelle requête, pour éviter
  une association ambiguë.
- Aucun cache global de contenu et aucune lecture automatique du texte lors
  d'un changement de presse-papiers. Une seule requête est en vol par connexion.
- Les tampons de réception pris en charge, le tampon de conversion et l'état
  temporaire sont effacés avec `OPENSSL_cleanse`. Les réponses annulées ne sont
  pas converties en texte. Les champs legacy enregistrent leur capacité réelle ;
  leur allocation est effacée avant libération et la suppression d'un caractère secret efface la
  queue inutilisée. Avec LVGL, les valeurs secrètes restent dans des buffers
  fixes séparés et seuls des astérisques entrent dans le stockage du toolkit.
  Les valeurs abandonnées du modèle d'authentification sont aussi effacées.
  Les copies encore nécessaires à l'authentification restent vivantes jusqu'à
  leur nettoyage normal ; ceci ne garantit pas l'absence de toute copie dans
  TLS, le système d'exploitation ou des fichiers core.
- Le gestionnaire n'écrit ni contenu de clipboard ni mot de passe dans les logs.
  Les protections de transport existantes restent en place. Utiliser TLS et
  vérifier le certificat serveur reste nécessaire pour protéger les identifiants.

Activer cette option ajoute un parseur accessible à un client non authentifié.
Le défaut désactivé, la petite surface protocolaire, les bornes, la validation
stricte et l'absence d'export limitent ce risque. Coller transmet volontairement
le texte au serveur RDP : il faut lui faire confiance, comme pour une saisie au
clavier. Un client qui autorise clipboard peut répondre aux requêtes d'un serveur
malveillant indépendamment du comportement de cette implémentation.

## Compilation et préparation d'un déploiement

Exemple de dépendances Debian/Ubuntu, à installer dans une machine de build :

```sh
apt-get install build-essential autoconf automake libtool pkg-config nasm \
  libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev \
  libxkbfile-dev libpixman-1-dev check libcmocka-dev
```

À la racine du dépôt, initialiser les sous-modules épinglés puis les outils
Autotools. Le script `bootstrap` de cette révision contient une référence obsolète
à `ulalaca` ; les étapes effectives sont :

```sh
git submodule update --init --recursive
autoreconf -fvi
```

Exemple de construction et d'installation **dans un répertoire de staging**,
sans modifier les services ou configurations de la machine :

```sh
mkdir -p /tmp/xrdp-clipboard-build /tmp/xrdp-clipboard-stage
cd /tmp/xrdp-clipboard-build
CONFIG_SHELL=/bin/bash bash /chemin/vers/xrdp/configure \
  --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
  --enable-strict-locations --with-socketdir=/run/xrdp \
  --with-systemdsystemunitdir=no --enable-tests --enable-pixman
make -j4
make check -j4
make install DESTDIR=/tmp/xrdp-clipboard-stage
```

Conserver les options nécessaires à votre déploiement (codecs, FUSE, LVGL, etc.).
LVGL reste optionnel et conserve les prérequis de [lvgl.md](lvgl.md).
Avec Check/cmocka sur Debian 13, un conflit de macro `fail` dans leurs en-têtes
peut devenir fatal avec `-Werror`. Dans l'environnement cloud, les en-têtes de
ces dépendances sont marqués système par `CPPFLAGS=-isystem <préfixe>/include` ;
les avertissements du code du projet restent traités comme erreurs.

Construire ensuite le paquet adapté à la distribution à partir du staging.
Avant installation réelle, examiner le diff, sauvegarder les binaires et la
configuration actuels, conserver leurs propriétaires et permissions, vérifier
le chemin du binaire lancé par le service et préparer le retour au paquet
précédent. Ne pas remplacer aveuglément `xrdp.ini`, les certificats ou les clés
avec les exemplaires du staging. Cette modification ne demande pas de remplacer
les modules xorgxrdp ni de modifier PAM.

Après validation et approbation du déploiement, installer ce paquet et ajouter
seulement l'option dans le fichier utilisé par le service. Planifier le
redémarrage ou la bascule vers le nouveau binaire selon la politique du serveur.
Vérifier les sessions existantes et le retour arrière avant cette opération.
Aucun déploiement de production ni redémarrage des services existants n'a été
effectué pendant ce développement.

## Vérification et limites de la validation

Les tests ajoutés à `make check` vérifient l'activation explicite, les échanges
protocolaires, Ctrl+V et Shift+Insert via le gestionnaire clavier réel, Unicode
et les surrogates, un mot de passe complexe de 252 octets, la borne de 255 octets,
le refus atomique des entrées invalides, l'annulation, le timeout, le drainage
des réponses tardives et la reprise des requêtes de session. Un test traverse
le vrai callback WM et le transport IPC vers une socket représentant chansrv.
Un corpus déterministe de 4 096 PDUs malformés complète ces cas. Les tests LVGL
vérifient aussi que le toolkit ne reçoit que le masque, que la saisie et les
suppressions Unicode modifient la valeur canonique et que la bonne valeur est
transmise au modèle d'authentification. Les régressions couvrent également les
objets détruits, les connexions indépendantes, les en-têtes sortants fragmentés,
les entiers extrêmes, le coût d'effacement des petits PDUs, 256 collages refusés
de 3 000 caractères et 100 cycles de réinitialisation du formulaire.

Commandes ciblées, depuis le répertoire de build :

```sh
make check -j4
cd tests/xrdp
CK_RUN_SUITE=login_clipboard ./test_xrdp
# Dans un build --enable-lvgl :
CK_RUN_SUITE=login ./test_xrdp
```

Un build distinct avec `-fsanitize=address,undefined -fno-sanitize=alignment
-fno-omit-frame-pointer` et `CK_FORK=no` permet de contrôler les 22 tests du
gestionnaire, y compris les chemins malformés et le nettoyage mémoire.
L'exception d'alignement suit la configuration UBSan existante du projet.

Résultats obtenus dans cette machine Debian 13 :

| Vérification | Résultat |
| --- | --- |
| Compilation GCC, `-Werror`, interface legacy | Réussie |
| Suite complète legacy | 273 tests réussis, aucun échec ni saut |
| Compilation avec LVGL 9.3.0 et suite complète | 282 tests réussis, aucun échec ni saut |
| Gestionnaire clipboard sous ASan/UBSan, détection des fuites activée | 22 tests réussis, aucune erreur signalée |
| Formulaire et modèle sous ASan/UBSan avec LVGL | 10 tests réussis, aucune erreur signalée |
| Corpus malformé inclus dans ces tests | 4 096 PDUs traités |
| libFuzzer + ASan/UBSan, parseurs et machine à états | 2 919 456 exécutions en 61 s, aucun incident détecté |

Un essai local avec FreeRDP 3.15, TLS et une empreinte de certificat vérifiée,
un serveur séparé sur loopback:3391 et Xvfb a montré le formulaire normal,
le collage d'un identifiant accentué et le collage d'un mot de passe Unicode
long par Ctrl+V et Shift+Insert, avec masquage. Les valeurs étaient fictives.
Les logs serveur ont été contrôlés pour l'absence de ce mot de passe en UTF-8
et UTF-16LE. Aucun programme externe n'intervient dans l'implémentation ; les
outils X11 n'ont servi qu'à piloter le client pendant cet essai.

Le compte de la machine cloud est refusé par les contrôles PAM du système.
**L'authentification réussie, l'ouverture d'un bureau Xorg/xorgxrdp et le
copier-coller dans un bureau authentifié n'ont donc pas été testés de bout en
bout.** Le test IPC et ceux du passage à chansrv ne remplacent pas cette
validation. Windows mstsc et Remmina n'ont pas été exécutés ; leur compatibilité
est recherchée par l'emploi du protocole standard, pas déclarée comme testée.

Avant déploiement, terminer cette matrice sur un serveur de validation : clients
mstsc, Remmina et FreeRDP ; utilisateurs et mots de passe ASCII/Unicode ; client
sans clipboard ; login refusé puis nouvelle tentative ; login réussi et
collage bidirectionnel dans Xorg ; reconnexion à une session ; plusieurs clients
concurrents ; soumission pendant un collage lent ; vérification des logs.

Le [rapport de sécurité A–F](security-audit-login-clipboard.md) détaille les
constats, correctifs, commandes, alertes statiques et limites de cette campagne.
Le lanceur reproductible de fuzzing est `tests/xrdp/run_login_clipboard_fuzz.sh` :

```sh
XRDP_BUILD_DIR=/chemin/build CLANG=clang \
  bash tests/xrdp/run_login_clipboard_fuzz.sh
```

L'audit a également exercé l'interface LVGL sur trois connexions TLS FreeRDP
successives vers un serveur isolé sur loopback:3392, avec certificat épinglé.
Le mot de passe généré pour cet essai est resté en mémoire et n'apparaît pas dans
les logs contrôlés ; les captures montrent seulement son masque. Le fuzzing est
une campagne bornée, avec les limites d'instrumentation décrites dans le rapport.
