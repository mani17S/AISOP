/**
 * Public front page. Every statement describes behaviour the application has today; there are no counts, logos,
 * quotes or claims about customers. The screenshot is the real application running on sample data.
 */

import React from 'react';

const steps = [
  { name: 'Ingest', text: 'Alerts and telemetry from SIEM, EDR, email, cloud and network sources are normalized to one format. The raw record and its SHA-256 are kept.' },
  { name: 'Open a case', text: 'Related alerts are promoted to a case. Access is scoped by role and by case assignment, and the server decides what each analyst may see.' },
  { name: 'Review evidence', text: 'Each event shows its time in UTC, its source and its extracted indicators. Duplicate records count as one piece of evidence.' },
  { name: 'Report', text: 'Reports are drafted for the executive, the incident responder and the detection engineer. Nothing is released until an analyst approves it.' },
];

const keeps = [
  'Observed evidence, analyst notes, threat intelligence and AI output are shown separately.',
  'An evidence sufficiency check reports sufficient, limited or insufficient, with the reasons.',
  'ATT&CK mappings come only from rules backed by the evidence in the case.',
  'The language model is optional. Everything except AI drafting works without it.',
];

export const Landing: React.FC = () => (
  <div className="lp">
    <header className="lp-nav">
      <a className="lp-wordmark" href="/">AISOP</a>
      <nav aria-label="Primary">
        <a href="#how">How it works</a>
        <a href="#keeps">What it keeps</a>
        <a href="https://github.com/mani17S/AISOP">Source code</a>
      </nav>
      <a className="lp-navlink" href="/app">Open the workbench</a>
    </header>

    <main>
      <section className="lp-hero">
        <h1>Alerts from any source. One case backed by evidence.</h1>
        <p className="lp-lede">
          AISOP turns alerts and telemetry into cases and reports an analyst can defend, with the raw evidence, its hash
          and its source kept beside every claim.
        </p>
        <div className="lp-actions">
          <a className="btn btn-primary" href="/app">Open the workbench</a>
        </div>
        <figure className="lp-shot">
          <img src="/shots/workspace.png" alt="A case in AISOP listing linked evidence with time, source and severity" width="1600" height="1000" />
          <figcaption>The case workspace, running on sample data.</figcaption>
        </figure>
      </section>

      <section className="lp-section" id="how" aria-labelledby="how-title">
        <h2 id="how-title">From alert to report</h2>
        <ol className="lp-steps">
          {steps.map((s, i) => (
            <li key={s.name}>
              <span className="lp-step-index">{i + 1}</span>
              <h3>{s.name}</h3>
              <p>{s.text}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="lp-section" id="keeps" aria-labelledby="keeps-title">
        <h2 id="keeps-title">What it keeps, and what it refuses to blur</h2>
        <ul className="lp-keeps">
          {keeps.map((k) => (
            <li key={k}>{k}</li>
          ))}
        </ul>
      </section>

      <section className="lp-section lp-close">
        <h2>See a case file.</h2>
        <a className="btn btn-primary" href="/app">Open the workbench</a>
        <p className="lp-note">This deployment shows sample data only.</p>
      </section>
    </main>

    <footer className="app-footer">
      <span>AISOP</span>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
      <a href="https://github.com/mani17S/AISOP">Source code</a>
    </footer>
  </div>
);
