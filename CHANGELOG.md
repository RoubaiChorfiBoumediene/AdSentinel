# Journal des modifications

## 1.2.0

Améliorations issues d'un premier test sur un vrai site de streaming.

- Nouvelle alerte **Script tiers qui profile** : un domaine extérieur au site qui prend l'empreinte
  de l'appareil et lit les cookies du site.
- Liste de **scripts de confiance** (Google Analytics, Tag Manager, reCAPTCHA…) : leurs lectures de cookies
  et empreintes passent en « faible », hors badge. Le code dynamique et le réseau restent toujours signalés.
- Les alertes sont regroupées par **type + script source** (et par hôte côté réseau) au lieu de leur texte :
  fini les doublons quand seul le nombre de cookies change.
- Les cadres **about:blank / srcdoc** affichent l'origine qu'ils héritent du site et expliquent pourquoi
  ils accèdent à ses cookies.
- 6 tests supplémentaires, dont un qui rejoue le cas observé.

## 1.1.0

- Icônes de l'extension (barre d'outils, page des extensions, notifications).
- Notification système lors d'une alerte critique (une seule par type et par page).
- Tests automatiques de l'analyse réseau et de la corrélation (`npm test`), exécutés par GitHub Actions.
- Capture d'écran du popup dans le README.
- Fins de ligne normalisées (`.gitattributes`).

## 1.0.0

- Première version : sondes dans la page, analyse réseau, corrélation par cadre, popup, blocage des IOC, page de démo.
