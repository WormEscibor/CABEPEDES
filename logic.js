(function(global){
  'use strict';
  const EXCEL_FORMULAS = {
    total: '=COUNTA(\'Data Register\'!A:A)-1',
    open: '=COUNTIF(\'Data Register\'!L:L, "Open")',
    closed: '=COUNTIF(\'Data Register\'!L:L, "Close*")',
    high: '=COUNTIF(\'Data Register\'!G:G, "High")'
  };
  const APP_SERIES = [
    'Dashboard SATUSEHAT','KALKULATOR NUTRI CHECK','Aplikasi Android SATUSEHAT STAGING',
    'SSRME API','SIAKPEL','Sertifikat LMS','NAKULA','SIAKSI'
  ];
  const DOMAIN_SERIES = [
    'Application & Vulnerability Mgmt / Access Control',
    'Application & Vulnerability Mgmt / Security Config',
    'Application & Vulnerability Mgmt / Input Validation',
    'Application & Vulnerability Mgmt / Secure Coding',
    'Application & Vulnerability Mgmt / Session Management',
    'Application & Vulnerability Mgmt / Supply Chain',
    'Application & Vulnerability Mgmt / Information Disclosure',
    'Application & Vulnerability Mgmt / Architecture',
    'Application & Vulnerability Mgmt / Mobile Security',
    'Application & Vulnerability Mgmt / Network Security',
    'Application & Vulnerability Mgmt / Integration Security',
    'Application & Vulnerability Mgmt / Secure Storage',
    'Application & Vulnerability Mgmt / Cryptography',
    'Application & Vulnerability Mgmt / Error Handling'
  ];
  const text=v=>v==null?'':String(v);
  const equalsExcel=(a,b)=>text(a).toLocaleLowerCase('id-ID')===text(b).toLocaleLowerCase('id-ID');
  const startsWithExcel=(a,p)=>text(a).toLocaleLowerCase('id-ID').startsWith(text(p).toLocaleLowerCase('id-ID'));
  const countIf=(records,field,pred)=>records.reduce((n,r)=>n+(pred(r&&r[field]==null?'':r[field])?1:0),0);
  const countExact=(records,field,value)=>countIf(records,field,v=>equalsExcel(v,value));
  const countStartsWith=(records,field,prefix)=>countIf(records,field,v=>startsWithExcel(v,prefix));
  const groupCount=(records,field,categories)=>categories.map(label=>({label,value:countExact(records,field,label)}));
  function calculate(records){
    const safe=Array.isArray(records)?records:[];
    const allAppsMap=Object.create(null), allDomainsMap=Object.create(null), noteMap=Object.create(null);
    for(const r of safe){
      const app=text(r?.['Aplikasi / Sistem'])||'(Kosong)';
      const dom=text(r?.['Domain Kontrol'])||'(Kosong)';
      const note=text(r?.['Notifikasi'])||'(Kosong)';
      allAppsMap[app]=(allAppsMap[app]||0)+1;
      allDomainsMap[dom]=(allDomainsMap[dom]||0)+1;
      noteMap[note]=(noteMap[note]||0)+1;
    }
    const sorter=(a,b)=>b.value-a.value||a.label.localeCompare(b.label,'id');
    const mapToArray=o=>Object.entries(o).map(([label,value])=>({label,value})).sort(sorter);
    const severity=groupCount(safe,'Severity',['High','Medium','Low']);
    const status=[{label:'Open',value:countExact(safe,'Status Kerentanan','Open')},{label:'Closed',value:countStartsWith(safe,'Status Kerentanan','Close')}];
    return {
      total:countIf(safe,'ID Issue',v=>v!==''&&v!==null&&v!==undefined),
      open:status[0].value, closed:status[1].value, high:severity[0].value,
      severity,status,apps:groupCount(safe,'Aplikasi / Sistem',APP_SERIES),domains:groupCount(safe,'Domain Kontrol',DOMAIN_SERIES),
      allApps:mapToArray(allAppsMap), allDomains:mapToArray(allDomainsMap), notificationSummary:mapToArray(noteMap), sourceFormulas:EXCEL_FORMULAS
    };
  }
  function nextId(records, year=new Date().getFullYear()){
    const yyyy=String(year).padStart(4,'0');
    let max=0;
    for(const r of Array.isArray(records)?records:[]){
      const m=text(r?.['ID Issue']).match(/^VA-(\d{4})-(\d{3})$/i);
      if(m && Number(m[1])===Number(year)) max=Math.max(max,Number(m[2]));
    }
    return `VA-${yyyy}-${String(max+1).padStart(3,'0')}`;
  }
  global.CSIRT={EXCEL_FORMULAS,APP_SERIES,DOMAIN_SERIES,calculate,nextId,equalsExcel,startsWithExcel};
  if(typeof module!=='undefined'&&module.exports) module.exports=global.CSIRT;
})(typeof window!=='undefined'?window:globalThis);
