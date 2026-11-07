import {describe, expect, it} from 'vitest';
import {projectFolderSelection, guidedReceiptStatus} from '../../../../apps/control-ui/public/v03/desktop-folder.js';

const now = 1_800_000_000_000;
const selected = {
  status: 'SELECTED',
  selectionRef: 'host:folder:' + 'a'.repeat(64),
  displayName: 'Documents',
  expiresAtUnixMs: now + 60_000,
};

describe('R04 Host-owned folder selection projection', () => {
  it('accepts only a short-lived opaque Host reference and safe display name', () => {
    expect(projectFolderSelection(200, selected, now)).toEqual({
      status:'SELECTED',selectionRef:selected.selectionRef,displayName:'Documents',
      expiresAtUnixMs:now+60_000,
    });
  });
  it('treats cancellation as state-neutral and refuses malformed or expired selections', () => {
    expect(projectFolderSelection(200,{status:'CANCELLED'},now)).toEqual({status:'CANCELLED'});
    expect(projectFolderSelection(200,{...selected,expiresAtUnixMs:now},now).status).toBe('UNKNOWN');
    expect(projectFolderSelection(200,{...selected,selectionRef:'C:/private'},now).status).toBe('UNKNOWN');
    expect(projectFolderSelection(200,{...selected,displayName:'C:\\private'},now).status).toBe('UNKNOWN');
    expect(projectFolderSelection(200,{...selected,displayName:'..'},now).status).toBe('UNKNOWN');
    expect(projectFolderSelection(200,{...selected,extra:'path'},now).status).toBe('UNKNOWN');
    expect(projectFolderSelection(200,{...selected,expiresAtUnixMs:now+300_001},now).status).toBe('UNKNOWN');
  });
  it('keeps stale, refused and unknown outcomes distinct', () => {
    expect(projectFolderSelection(409,{status:'STALE'},now).status).toBe('STALE');
    expect(projectFolderSelection(422,{status:'REFUSED'},now).status).toBe('REFUSED');
    expect(projectFolderSelection(503,{status:'UNKNOWN'},now).status).toBe('UNKNOWN');
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
