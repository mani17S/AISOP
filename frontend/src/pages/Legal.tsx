/**
 * Privacy Policy and Terms of Service pages.
 *
 * Statements about data handling describe what this codebase does. Operator identity comes from
 * src/legal/operator.ts and is never invented. These pages are not legal advice and need review by
 * qualified counsel before launch.
 */

import React from 'react';
import { operator } from '../legal/operator';

const Shell: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="legal-page">
    <a className="legal-back" href="/">Back to AISOP</a>
    <h1>{title}</h1>
    <p className="legal-meta">
      {operator.name ? `Operated by ${operator.name}.` : 'Operator not yet named.'}
      {operator.effectiveDate ? ` Effective ${operator.effectiveDate}.` : ''}
    </p>
    {children}
    <p className="legal-meta">
      Questions:{' '}
      {operator.contactEmail ? (
        <a href={`mailto:${operator.contactEmail}`}>{operator.contactEmail}</a>
      ) : (
        'contact address not yet set'
      )}
    </p>
  </div>
);

export const PrivacyPolicy: React.FC = () => (
  <Shell title="Privacy Policy">
    <h2>What AISOP is</h2>
    <p>
      AISOP is a security operations workbench. Analysts load security telemetry and alerts, review the evidence, and
      produce reports. It is built to run on infrastructure controlled by the operator named above.
    </p>

    <h2>What the website stores in your browser</h2>
    <ul>
      <li>
        The API key you enter is kept in this browser tab's session storage so a page refresh does not log you out. It
        is cleared when the tab closes. It is never written to local storage and is sent only to the AISOP backend you
        are using.
      </li>
      <li>The site sets no advertising or analytics cookies and loads no analytics, tracking or advertising scripts.</li>
      <li>Fonts are served by the site itself. The pages make no requests to third-party servers.</li>
    </ul>

    <h2>What the AISOP backend stores</h2>
    <p>
      The backend stores the security data your organisation chooses to ingest: raw alert and event payloads, their
      SHA-256 hashes, normalised events, extracted entities such as IP addresses, hostnames, usernames and file hashes,
      cases, analyst accounts and roles, and an audit trail of investigation actions. This data can contain personal
      data about people in your environment. It is held in the operator's own PostgreSQL database.
    </p>

    <h2>AI features</h2>
    <p>
      Report drafting and investigation synthesis are optional and use a language model chosen by the operator. In the
      default configuration the model runs locally and evidence is not sent to a third-party AI service. If an operator
      connects an external model or threat intelligence service, the data sent to it is governed by that operator's
      configuration and that service's own terms. AI output is labelled as inference and is reviewed by an analyst
      before use.
    </p>

    <h2>Who can see data</h2>
    <p>
      Access is controlled by analyst accounts, global roles and per-case assignments enforced by the backend. The role
      selector in the interface is a preview aid only and does not change what the backend allows.
    </p>

    <h2>Retention and deletion</h2>
    <p>
      The operator decides how long data is kept. To request access to, correction of, or deletion of personal data
      held in a deployment, contact the operator at the address on this page.
    </p>

    <h2>Changes</h2>
    <p>Changes to this policy are published on this page with a new effective date.</p>
  </Shell>
);

export const TermsOfService: React.FC = () => (
  <Shell title="Terms of Service">
    <h2>Acceptance</h2>
    <p>
      By using this AISOP deployment you agree to these terms. If you do not agree, do not use it. If you use it for an
      organisation, you confirm you may bind that organisation.
    </p>

    <h2>Authorised use only</h2>
    <p>
      Use AISOP only on data and systems you are authorised to analyse. Do not use it to access, probe or disrupt
      systems you do not own or have permission to test, and do not ingest data you have no right to process.
    </p>

    <h2>Accounts and credentials</h2>
    <p>
      You are responsible for the API keys issued to you and for activity under them. Keep keys secret and report
      suspected compromise to the operator immediately.
    </p>

    <h2>Analyst responsibility</h2>
    <p>
      AISOP assists analysts. It does not take containment or remediation actions on its own. Its output, including any
      AI-generated text, can be incomplete or wrong and is not evidence by itself. Verify findings against the
      underlying telemetry before acting on them or sharing a report.
    </p>

    <h2>Your data</h2>
    <p>
      You keep ownership of the data you ingest. You grant the operator the right to process it to run the service as
      described in the Privacy Policy.
    </p>

    <h2>No warranty</h2>
    <p>
      AISOP is provided as is and as available. It does not guarantee detection of any threat, including previously
      unseen ones, and does not guarantee the accuracy or completeness of any result.
    </p>

    <h2>Limitation of liability</h2>
    <p>
      To the extent the law allows, the operator is not liable for indirect or consequential loss, or for loss of data
      or business, arising from use of the service. Nothing here limits liability that cannot be limited by law.
    </p>

    <h2>Suspension and changes</h2>
    <p>
      The operator may suspend access for misuse or security reasons and may update these terms. Continued use after an
      update means you accept it.
    </p>

    <h2>Governing law</h2>
    <p>
      {operator.jurisdiction
        ? `These terms are governed by the laws of ${operator.jurisdiction}.`
        : 'Governing law is not yet set.'}
    </p>
  </Shell>
);
