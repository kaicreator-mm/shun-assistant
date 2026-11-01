/**
 * A bounded, display-only projection of the durable Host guided-case journal.
 * Accepted form answers do not imply that a Windows effect completed.
 */
const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
/** @param {unknown} value */
export function projectGuidedHistory(value){
 if(!Array.isArray(value)||value.length>256)return {status:'REFUSED',items:[]};
 const items=[];
 for(const row of value){
  if(!row||typeof row!=='object'||Array.isArray(row)||
     !ID.test(row.stepId)||!['ACCEPTED','REFUSED'].includes(row.status)||
     typeof row.at!=='string'||!ISO.test(row.at)||
     !Number.isFinite(Date.parse(row.at))||
     new Date(row.at).toISOString()!==row.at)
    return {status:'REFUSED',items:[]};
  items.push({status:row.status,at:row.at});
 }
 return {status:'READY',items:items.slice(-40).reverse()};
}
