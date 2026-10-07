/**
 * SecureScan AI - Technology Profiler
 * Safely extracts technology clues from headers and response body.
 * Note: Detected technologies are informational evidence, NOT vulnerabilities.
 */

import { TechnologyEvidenceItem } from '@securescan/types';

export class TechnologyScanner {
  public analyze(headers: Record<string, string>, htmlBody: string): TechnologyEvidenceItem[] {
    const techMap = new Map<string, TechnologyEvidenceItem>();

    const addTech = (item: TechnologyEvidenceItem) => {
      if (!techMap.has(item.name)) {
        techMap.set(item.name, item);
      }
    };

    // Header inspection
    const server = headers['server'];
    if (server) {
      if (/nginx/i.test(server)) addTech({ name: 'Nginx', category: 'Web Server', evidenceSource: 'header' });
      if (/apache/i.test(server)) addTech({ name: 'Apache', category: 'Web Server', evidenceSource: 'header' });
      if (/cloudflare/i.test(server)) addTech({ name: 'Cloudflare', category: 'CDN / Reverse Proxy', evidenceSource: 'header' });
      if (/caddy/i.test(server)) addTech({ name: 'Caddy', category: 'Web Server', evidenceSource: 'header' });
    }

    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      if (/express/i.test(poweredBy)) addTech({ name: 'Express.js', category: 'Backend Framework', evidenceSource: 'header' });
      if (/php/i.test(poweredBy)) addTech({ name: 'PHP', category: 'Programming Language', evidenceSource: 'header' });
      if (/asp\.net/i.test(poweredBy)) addTech({ name: 'ASP.NET', category: 'Backend Framework', evidenceSource: 'header' });
      if (/next\.js/i.test(poweredBy)) addTech({ name: 'Next.js', category: 'Web Framework', evidenceSource: 'header' });
    }

    // HTML / Body inspection
    if (htmlBody) {
      if (htmlBody.includes('__NEXT_DATA__')) {
        addTech({ name: 'Next.js', category: 'Web Framework', evidenceSource: 'html_meta' });
      }
      if (htmlBody.includes('__NUXT__')) {
        addTech({ name: 'Nuxt.js', category: 'Web Framework', evidenceSource: 'html_meta' });
      }
      if (/wp-content|wp-includes/i.test(htmlBody)) {
        addTech({ name: 'WordPress', category: 'CMS', evidenceSource: 'html_meta' });
      }
      if (/react(\.production)?\.min\.js|_react/i.test(htmlBody)) {
        addTech({ name: 'React', category: 'Frontend Library', evidenceSource: 'script_src' });
      }
      if (/vue(\.runtime)?\.min\.js/i.test(htmlBody)) {
        addTech({ name: 'Vue.js', category: 'Frontend Framework', evidenceSource: 'script_src' });
      }
    }

    return Array.from(techMap.values());
  }
}
