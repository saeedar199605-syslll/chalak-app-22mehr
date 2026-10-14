function u(l,r){const t=r.filter(e=>e.value!==(e.allValue??"all"));return t.length===0?[...l]:l.filter(e=>t.every(a=>String(a.getValue(e)??"")===a.value))}export{u as a};
