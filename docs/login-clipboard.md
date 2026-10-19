# Collage dans le formulaire de connexion XRDP 0.10

Ce portage cible la branche **v0.10** de `ValentinM4RS/xrdp`, à partir du
commit `0ed6e5ea2d64b999bd6ddf6bbceabd42a4d33e4f` (version 0.10.6.1).
Il adapte le gestionnaire de collage du commit devel `8bbfc2ee` au formulaire
natif et aux API clavier, configuration et transport de la branche stable.
La validation de ce portage est décrite dans
[login-clipboard-v0.10-validation.md](login-clipboard-v0.10-validation.md).

## Utilisation

Avec le binaire construit depuis cette branche, activer l'option dans les
sections existantes du fichier `xrdp.ini` réellement utilisé par le service :

```ini
[Globals]
ls_clipboard=true

[Channels]
cliprdr=true
```

L'option est **désactivée par défaut**. Le client RDP doit autoriser la redirection
du presse-papiers. Cliquer dans Username ou Password puis utiliser **Ctrl+V** ou
**Maj+Inser**. Le mot de passe reste masqué. Le pavé numérique fournit Inser quand
NumLock est désactivé ; la touche Inser étendue fonctionne aussi avec NumLock.
Les événements Ctrl droit suivent la représentation clavier native de v0.10.

Windows mstsc propose « Ressources locales → Presse-papiers » ; Remmina doit
autoriser la synchronisation du presse-papiers ; FreeRDP utilise `/clipboard`.
Seul FreeRDP a été exécuté dans la campagne cloud décrite dans la validation.

Après installation du paquet construit, charger le nouveau binaire selon le
cycle de déploiement du service, puis établir une nouvelle connexion. Un push
Git ne remplace pas le binaire installé. L'option n'exige aucune modification de
PAM, sesman, TLS ou de la politique de canaux. Les connexions automatiques sans
formulaire ne démarrent pas ce gestionnaire.

## Architecture et garanties locales

Le gestionnaire appartient à un seul `xrdp_wm` et réutilise le canal statique
`cliprdr` négocié. Il ne démarre ni X11, ni chansrv avant l'authentification.
Il annonce des capacités minimales et acquitte les formats sans demander de
contenu. Une demande de `CF_UNICODETEXT` n'est envoyée qu'après un raccourci de
collage explicite, vers le champ actuellement actif.

- Sens unique client → formulaire. Aucune publication de champ ni fonction de
  copie depuis le serveur. Toute demande de lecture du clipboard serveur reçoit
  un échec. Fichiers, images et formats riches ne sont pas pris en charge.
- PDU limité à **8 192 octets**, en-tête compris, et allocation fixe par connexion.
  Longueurs, en-têtes, capacités, formats courts/longs et fragments sont bornés.
- Texte UTF-16LE terminé par NUL, conversion UTF-8 stricte. Surrogates incorrects,
  NUL intégrés, caractères de contrôle et séparateurs de ligne sont refusés.
  Les caractères non BMP sont pris en charge. Pas de normalisation du secret.
- Limite de **255 octets UTF-8 par champ**, contenu existant compris. Un collage
  trop long est refusé en entier. Il n'y a ni troncature ni suppression d'espaces.
- Une requête en vol par connexion. La destination expire après **5 secondes**,
  même sans premier fragment ; un réassemblage incomplet expire également.
  L'horloge monotone est fournie par un petit helper backporté dans `common`.
- Clavier, souris, changement d'état et destruction d'edit annulent la destination.
  Le jeton ne sert qu'à comparer le champ encore actif. Les références de focus
  sont effacées avant libération des widgets.
- Réception, conversion, champs secrets supprimés, allocations d'edit et copies
  abandonnées du modèle sont nettoyés avec `OPENSSL_cleanse`. La capacité réelle
  de chaque edit est enregistrée ; aucun effacement de taille supposée n'est fait.
- Le gestionnaire n'écrit ni contenu de clipboard ni mot de passe dans les logs
  ou fichiers. Aucun cache global ne partage du texte entre connexions. Les
  valeurs nécessaires à l'authentification suivent le flux sesman/backend normal.

Activer l'option expose un parseur supplémentaire avant authentification. Le
client reste maître des données et événements de sa propre connexion. Les
protections locales ne remplacent pas la vérification du certificat TLS, la
confiance dans le serveur ou les limites d'admission des connexions du déploiement.
Le nettoyage applicatif ne garantit pas l'absence de copie dans TLS, le système
d'exploitation, le swap, les bibliothèques ou des fichiers core.

## Passage à la session Linux

Avant le branchement de chansrv, le gestionnaire abandonne toute destination de
formulaire. Les messages ordinaires suivent ensuite leur route habituelle.
Si une ancienne requête est encore en vol, sa réponse est absorbée et effacée :
elle ne doit pas devenir le clipboard du bureau.

Les réponses texte cliprdr n'ont pas d'identifiant de requête. Pendant ce drainage,
les nouvelles requêtes de session reçoivent un échec local. Leur blocage persiste
jusqu'à la fin du message, même si l'en-tête sortant est fragmenté et si l'ancienne
réponse arrive entre les fragments. Il peut être nécessaire de refaire le premier
collage du bureau. Si le client ne répond jamais, reconnecter réinitialise cet
état. La destination expire et les données partielles sont effacées ; seule une
petite quantité fixe d'état est conservée.

Pendant cette quarantaine, un message sortant dont le premier fragment ne contient
pas les deux octets du type peut être abandonné même s'il s'avère ne pas être une
requête. Le chansrv standard fournit son en-tête complet ; les modules qui
fragmentent autrement doivent faire l'objet d'essais spécifiques.

## Construction et tests

Conserver les options de compilation du déploiement et initialiser les sous-modules
épinglés de **v0.10**, puis générer les outils Autotools :

```sh
git submodule update --init --recursive
autoreconf -fvi
mkdir -p /tmp/xrdp-v0.10-build /tmp/xrdp-v0.10-stage
cd /tmp/xrdp-v0.10-build
CONFIG_SHELL=/bin/bash /bin/bash /chemin/xrdp/configure \
  --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
  --enable-strict-locations --with-socketdir=/run/xrdp \
  --with-systemdsystemunitdir=no --enable-tests --enable-pixman
make -j4
make check -j4
make install DESTDIR=/tmp/xrdp-v0.10-stage
```

Les dépendances sont celles de XRDP 0.10, avec Check/cmocka pour les tests.
OpenSSL, déjà requis par XRDP, est lié explicitement aux objets qui effacent les
secrets. Aucune bibliothèque graphique ni dépendance de service n'est ajoutée.
La recherche Autoconf de `clock_gettime` utilise `librt` si la plateforme l'exige.
Ne pas recopier les configurations ou clés du staging sur un serveur existant.

Les tests protocolaires sont inclus dans `make check`. Depuis le build :

```sh
cd tests/xrdp
CK_RUN_SUITE=login_clipboard ./test_xrdp
```

Le harnais de fuzzing compile les parseurs et la machine à états réels avec des
substituts pour le transport, l'horloge et le dessin. Depuis la source :

```sh
XRDP_BUILD_DIR=/chemin/build CLANG=clang \
  bash tests/xrdp/run_login_clipboard_fuzz.sh
```

Le lanceur utilise libFuzzer, ASan/UBSan, une seed fixe et des limites de taille,
temps et RSS. Les outils de test ne sont pas utilisés par le serveur en service.
