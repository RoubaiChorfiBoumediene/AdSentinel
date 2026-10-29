// Indicateurs de compromission tirés des rapports Confiant et Citizen Lab (2026).
// Un sous-domaine correspond aussi : "noas.mtrtb.com" est couvert par "mtrtb.com".
export const IOC_DOMAINS = [
  // Discover-Tech : diffusion publicitaire et façades
  'mtrtb.com',
  'adtimizer.co',
  'myipinfo.io',
  'akedo.gg',
  'volasim.com',
  'tekma-dmp.ai',
  'discover-tech.io',
  'powerium.net',
  'platc-tester.com',
  'myweb3id.io',
  // Synchronisation de cookies
  'cookie-sync.xyz',
  'tracookiepixel.xyz',
  'cookiesurfer.com',
  'ads-monitor.xyz',
  // C2 du SDK
  'trustlayersdk.com',
  // C&C de l'implant Windows (DevilsTongue / Candiru)
  'fearevolve.com',
  'jobmarcher.com',
  // CloudFront : couche de livraison Candiru et pixel de suivi
  'd8lmy5wyiokrq.cloudfront.net',
  'd23625plpxg1yn.cloudfront.net',
  'd39619tdxn6mhj.cloudfront.net',
  'd2f4zpg1mgzwov.cloudfront.net',
  'd1fzw0miu1r9rc.cloudfront.net',
  'd19oo8r6k9oumb.cloudfront.net',
  'd147nolwbekx2b.cloudfront.net',
  'dcv2rnj2ograe.cloudfront.net',
  'd1x4e580sn23dn.cloudfront.net',
  // Domaine fictif utilisé par la page de démo (ne résout jamais)
  'adsentinel-test.invalid'
];

// Points d'entrée DNS-over-HTTPS connus : une page web n'a normalement aucune raison de les appeler.
export const DOH_HOSTS = [
  'cloudflare-dns.com',
  'mozilla.cloudflare-dns.com',
  'dns.google',
  'dns.quad9.net',
  'doh.opendns.com',
  'dns.nextdns.io',
  'dns.adguard-dns.com'
];
