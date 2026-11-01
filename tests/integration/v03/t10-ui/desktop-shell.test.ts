import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const root = new URL('../../../../apps/control-ui/public/v03/', import.meta.url);
function source(file: string): string {
  return readFileSync(new URL(file, root), 'utf8');
}

describe('R04 source contract: the shipped desktop surface replaces technical operator panels', () => {
  it('uses the new Windows-familiar shell as the sole shipped entry', () => {
    const html = source('index.html');
    expect(html).toContain('src="./desktop.js"');
    expect(html).toContain('href="./desktop.css"');
    expect(html).toContain('id="dynamic-form"');
    expect(html).toContain('aria-label="Main navigation"');
    expect(html).not.toContain('src="./app.js"');
    expect(html).not.toContain('id="v03-j-grant"');
    expect(html).not.toContain('id="v03-j-approval"');
  });

  it('renders approved Host StepSpec fields without offering a raw effect/permit route', () => {
    const app = source('desktop.js');
    expect(app).toContain("import { currentStepModel, buildStepOutcome, userDecisionRelay, replayGuard }");
    expect(app).toContain("model.fields");
    expect(app).toContain("decision:'ANSWER'");
    expect(app).toContain("humanApproval:false");
    expect(app).toContain("model.kind!=='ASK'");
    expect(app).toContain("currentModel.fields.flatMap");
    expect(app).toContain("!f.required && (value==='' || value===false)");
    expect(app).toContain("addEventListener('click',()=>page('home'))");
    expect(app).not.toContain('/api/v03/effect/submit');
    expect(app).not.toContain('/api/v03/provider/first-use');
    expect(app).not.toContain('/api/v03/meta/feedback');
    expect(app).not.toContain('new AuthorizedAction');
  });

  it('exposes only real local read-only checks and obvious keyboard focus', () => {
    const app = source('desktop.js');
    const css = source('desktop.css');
    expect(app).toContain('/api/system/inventory');
    expect(app).toContain('/api/system/diagnosis');
    expect(app).toContain("event.key.toLowerCase()==='k'");
    expect(css).toContain(':focus-visible');
    expect(css).toContain('prefers-reduced-motion');
    expect(css).toContain('[hidden]');
  });

  it('keeps user-facing copy in both languages, not internal authorization identifiers', () => {
    const app = source('desktop.js');
    for (const label of ["heroTitle:", "actionInventory:", "actionDiagnosis:", "scopeTitle:", "notAnApproval:"]) {
      expect(app.split(label).length).toBeGreaterThan(2);
    }
    const html = source('index.html');
    expect(html).not.toMatch(/(planRef|grantRef|approvalRef|currentnessRef|effectPermit)/);
  });
});
