import {describe, expect, it} from 'vitest';
import {summarizeBrowserFolder, guidedReceiptStatus} from '../../../../apps/control-ui/public/v03/desktop-folder.js';

const folder = [
 {size: 123, webkitRelativePath: 'Documents/photos/a.jpg'},
 {size: 456, webkitRelativePath: 'Documents/work/report.pdf'},
];

describe('R04 browser-only folder selection',()=>{
 it('shows a bounded local folder summary without exposing file names',()=>{
  expect(summarizeBrowserFolder(folder)).toEqual({
   status:'PREVIEW',folder:'Documents',files:2,bytes:579
  });
  expect(JSON.stringify(summarizeBrowserFolder(folder))).not.toContain('report.pdf');
 });
 it('refuses mixed/traversal/absolute or invalid file lists',()=>{
  expect(summarizeBrowserFolder([]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder([{size:1,webkitRelativePath:'C:/Windows/file'}]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder([{size:1,webkitRelativePath:'safe/../secret'}]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder([{size:1,webkitRelativePath:'safe\\secret'}]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder([...folder,{size:1,webkitRelativePath:'Elsewhere/x'}]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder([{size:-1,webkitRelativePath:'safe/a'}]).status).toBe('REFUSED');
  expect(summarizeBrowserFolder({length:4097}).status).toBe('REFUSED');
 });
});
describe('R04 truthful Guided HTTP receipt classification',()=>{
 it('accepts only one exact non-authorizing recorded receipt',()=>{
  const good={status:'RECORDED',humanGrantIssued:false,effectSent:false,history:[]};
  expect(guidedReceiptStatus(200,good)).toBe('RECORDED');
  expect(guidedReceiptStatus(200,{...good,effectSent:true})).toBe('UNKNOWN');
  expect(guidedReceiptStatus(200,{...good,humanGrantIssued:true})).toBe('UNKNOWN');
 });
 it('does not equate refusal, stale, unknown or malformed status with success',()=>{
  expect(guidedReceiptStatus(422,{status:'REFUSED'})).toBe('REFUSED');
  expect(guidedReceiptStatus(409,{status:'STALE'})).toBe('STALE');
  expect(guidedReceiptStatus(503,{status:'UNKNOWN'})).toBe('UNKNOWN');
  expect(guidedReceiptStatus(200,{status:'COMPLETED'})).toBe('UNKNOWN');
  expect(guidedReceiptStatus(409,{status:'REFUSED'})).toBe('UNKNOWN');
  expect(guidedReceiptStatus(200,null)).toBe('UNKNOWN');
 });
});
