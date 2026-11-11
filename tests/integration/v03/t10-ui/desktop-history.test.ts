import { describe, expect, it } from 'vitest';
import { projectGuidedHistory } from '../../../../apps/control-ui/public/v03/desktop-history.js';

describe('R04 read-only Guided history projection', () => {
 it('shows bounded Host-recorded decisions newest first, without IDs', () => {
  const value=projectGuidedHistory([
   {stepId:'step-a',status:'ACCEPTED',at:'2026-11-01T12:00:00.000Z'},
   {stepId:'step-b',status:'REFUSED',at:'2026-11-01T12:01:00.000Z'}
  ]);
  expect(value).toEqual({status:'READY',items:[
   {status:'REFUSED',at:'2026-11-01T12:01:00.000Z'},
   {status:'ACCEPTED',at:'2026-11-01T12:00:00.000Z'}
  ]});
  expect(JSON.stringify(value)).not.toContain('step-a');
 });
 it('never upgrades an unsupported outcome into effect completion', () => {
  expect(projectGuidedHistory([{stepId:'a',status:'COMPLETED',at:'2026-11-01T12:00:00.000Z'}]).status).toBe('REFUSED');
  expect(projectGuidedHistory([{stepId:'a',status:'UNKNOWN',at:'2026-11-01T12:00:00.000Z'}]).status).toBe('REFUSED');
 });
 it('refuses malformed dates, timestamps and step identifiers', () => {
  expect(projectGuidedHistory([{stepId:'a',status:'ACCEPTED',at:'not-a-time'}]).status).toBe('REFUSED');
  expect(projectGuidedHistory([{stepId:'a',status:'ACCEPTED',at:'2026-02-31T12:00:00.000Z'}]).status).toBe('REFUSED');
  expect(projectGuidedHistory([{stepId:'../file',status:'ACCEPTED',at:'2026-11-01T12:00:00.000Z'}]).status).toBe('REFUSED');
  expect(projectGuidedHistory(null).status).toBe('REFUSED');
 });
 it('limits large Host histories and accepts a verified empty history', () => {
  const item={stepId:'step-a',status:'ACCEPTED',at:'2026-11-01T12:00:00.000Z'};
  expect(projectGuidedHistory(Array(50).fill(item)).items).toHaveLength(40);
  expect(projectGuidedHistory(Array(257).fill(item)).status).toBe('REFUSED');
  expect(projectGuidedHistory([])).toEqual({status:'READY',items:[]});
 });
});
