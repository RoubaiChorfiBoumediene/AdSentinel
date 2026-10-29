# AdSentinel

Extension Chrome / Edge (Manifest V3) qui détecte les comportements suspects des publicités,
à partir des techniques décrites dans les rapports Confiant et Citizen Lab sur Discover-Tech et Candiru (2026).

Créée par **Roubai Chorfi Boumediene**.

![Tests](https://github.com/RoubaiChorfiBoumediene/AdSentinel/actions/workflows/test.yml/badge.svg)
![Licence MIT](https://img.shields.io/badge/licence-MIT-blue)

<p align="center">
  <img src="docs/screenshot.png" alt="Popup AdSentinel montrant des alertes critiques sur une page" width="420">
</p>

## Installation

1. Ouvrir `chrome://extensions` (ou `edge://extensions`).
2. Activer le **mode développeur**.
3. Cliquer sur **Charger l'extension non empaquetée** et choisir le dossier `ad-sentinel`.
4. Épingler l'icône AdSentinel dans la barre d'outils.

## Tester avec la page de démo

Servir le dossier `test` en local, par exemple :

```bash
python -m http.server 8000 --directory test
```

Puis ouvrir <http://localhost:8000/demo.html>, cliquer sur **Afficher la « publicité » simulée**
et ouvrir le popup. La démo ne contacte que des domaines `.invalid` et une IP de documentation (203.0.113.10).

## Ce qui est détecté

| Signal | Où | Lien avec l'attaque |
|---|---|---|
| Domaine IOC connu | réseau | Infrastructure Discover-Tech, CloudFront Candiru, C&C DevilsTongue |
| Empreinte + contrôle à distance dans un même cadre | corrélation | Schéma du SDK `trustlayersdk` |
| Cookies envoyés dans une URL | réseau | Vol de cookies `getCookies()` avec séparateur `~~~` |
| DNS-over-HTTPS lancé par la page | réseau | Helper DoH du SDK pour cacher les domaines |
| Contact d'une IP brute | réseau | Suite du DoH : connexion à l'IP sans nom d'hôte |
| `new Function(...)` | page | Exécution du code envoyé par le C2 |
| WebSocket / WebRTC | page | Canal C2 persistant, fuite d'IP derrière un VPN |
| Lecture de `document.cookie` par un tiers ou un cadre | page | Accès aux cookies de l'éditeur |
| Canvas, WebGL (carte graphique), batterie | page | Empreinte de l'appareil |
| Écoute souris / clavier / défilement depuis un cadre | page | Surveillance comportementale anti-robot |
| `/getAd`, cadre CloudFront anonyme | réseau | Chargeur NOAS et couche de livraison |

Le bouton **Bloquer les domaines IOC connus** ajoute une règle `declarativeNetRequest` qui bloque la liste de `iocs.js`.
Chaque alerte **critique** déclenche aussi une notification système (une seule par type et par page).

## Développement

Les tests de l'analyse réseau et de la corrélation tournent sous Node.js 22 ou plus récent, sans dépendance :

```bash
npm test
```

GitHub Actions les relance à chaque push. Pour régénérer les icônes après une modification du dessin :

```bash
powershell -ExecutionPolicy Bypass -File scripts/make-icons.ps1
```

La capture du README vient de `docs/preview.html`, qui affiche le vrai popup avec des alertes d'exemple.

## Structure

- `inject.js` : sondes dans le contexte de la page (world MAIN), dans tous les cadres.
- `content.js` : relais des événements vers le service worker.
- `background.js` : analyse réseau (`webRequest`), corrélation par cadre, badge et blocage.
- `iocs.js` : indicateurs de compromission et serveurs DoH ; à mettre à jour.
- `popup.*` : interface des alertes, export JSON.
- `icons/` : icônes générées par `scripts/make-icons.ps1`.
- `tests/` : tests Node.js avec un faux objet `chrome`.
- `docs/` : page d'aperçu et capture d'écran.

## Limites

- **Ne détecte pas l'exploit lui-même** : seulement la préparation (empreinte, canal C2, livraison).
- Un attaquant qui connaît l'extension peut repérer les sondes (Proxy) et ne rien faire.
  C'est d'ailleurs un effet utile : le SDK reste silencieux face à un environnement d'analyse.
- `eval` n'est pas surveillé, car l'envelopper casse le comportement de `eval` direct.
- Une page peut fabriquer de fausses alertes en déclenchant l'événement `__adsentinel`.
- Faux positifs possibles : visioconférence (WebRTC), régies légitimes (`/getAd`), scripts anti-fraude (empreinte).
  C'est la **combinaison** de signaux dans un cadre publicitaire qui compte.

## Licence et crédits

Distribué sous licence **MIT** : voir [LICENSE](LICENSE).
Tu peux utiliser, modifier et redistribuer ce code, y compris dans un projet commercial,
à condition de **conserver la mention de copyright et le texte de la licence**.

Si tu t'appuies sur AdSentinel dans un projet, un article ou une présentation, cite-le ainsi :

> AdSentinel, par Roubai Chorfi Boumediene — https://github.com/RoubaiChorfiBoumediene/AdSentinel

Sources des indicateurs : rapports de [Confiant](https://www.confiant.com/) et du
[Citizen Lab](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/).
