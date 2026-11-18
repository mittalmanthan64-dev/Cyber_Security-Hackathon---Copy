async function inspectAllPages() {
  const res = await fetch('https://onecampus-trust-pass.lovable.app/assets/routes-X4CUDuBS.js');
  const code = await res.text();
  
  // Find all component functions or sections
  const sections = code.split('function ');
  console.log('Total functions in routes:', sections.length);
  
  for (const s of sections) {
    if (s.includes('return(0,N.jsxs)') || s.includes('return(0,N.jsx)')) {
      // Find headings or main titles
      const headings = s.match(/children:\[?`([^`]{4,60})`/g) || [];
      if (headings.length > 0) {
        console.log('--- COMPONENT ---');
        console.log(headings.map(h => h.replace(/children:\[?`/, '').replace(/`$/, '')));
      }
    }
  }
}

inspectAllPages().catch(console.error);
