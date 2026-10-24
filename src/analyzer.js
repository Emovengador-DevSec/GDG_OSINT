import dns from 'node:dns/promises';

export async function analyzeDomain(domain) {
  const report = {
    target: domain,
    timestamp: new Date().toISOString(),
    records: {},
    securityFindings: []
  };

  try {
    report.records.A = await dns.resolve4(domain);
  } catch {
    report.records.A = [];
  }

  try {
    report.records.MX = await dns.resolveMx(domain);
  } catch {
    report.records.MX = [];
  }

  try {
    const txt = await dns.resolveTxt(domain);
    report.records.TXT = txt.flat();

    const spf = report.records.TXT.find(r => r.startsWith('v=spf1'));
    if (spf) {
      report.securityFindings.push({ type: 'SPF', status: 'PASS', detail: spf });
    } else {
      report.securityFindings.push({ type: 'SPF', status: 'WARN', detail: 'Registro SPF no detectado' });
    }
  } catch {
    report.records.TXT = [];
    report.securityFindings.push({ type: 'TXT/SPF', status: 'WARN', detail: 'Sin registros TXT publicos' });
  }

  try {
    const dmarc = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = dmarc.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      report.securityFindings.push({ type: 'DMARC', status: 'PASS', detail: dmarcRecord });
    } else {
      report.securityFindings.push({ type: 'DMARC', status: 'WARN', detail: 'DMARC ausente o mal configurado' });
    }
  } catch {
    report.securityFindings.push({ type: 'DMARC', status: 'FAIL', detail: 'Sin politica DMARC publica' });
  }

  return report;
}

if (process.argv[1]?.endsWith('analyzer.js')) {
  const target = process.argv[2] || 'google.com';
  console.log(`[OSINT] Auditando dominio: ${target}...`);
  analyzeDomain(target).then(res => console.log(JSON.stringify(res, null, 2)));
}
