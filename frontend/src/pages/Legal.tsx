/**
 * Privacy Policy and Terms of Service pages.
 *
 * Statements about data handling describe what this codebase does and can be checked in the browser:
 * Application, Session Storage for the key; Network for third-party requests; Cookies for cookies.
 * These pages are a student project's policies and have not had legal review.
 */

import React from 'react';
import { operator } from '../legal/operator';

const Shell: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="legal-shell">
    <header className="legal-head">
      <a className="lp-wordmark" href="/">AISOP</a>
      <a className="legal-back" href="/app">Open the workbench</a>
    </header>
    <div className="legal-page">
      <h1>{title}</h1>
      <p className="legal-meta">
        Operated by {operator.name}. Effective {operator.effectiveDate}.
      </p>
      {children}
      <p className="legal-meta">
        Questions or requests: <a href={operator.contactUrl}>{operator.contactUrl}</a>
      </p>
    </div>
    <footer className="app-footer">
      <span>AISOP</span>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
      <a href="/">Home</a>
    </footer>
  </div>
);

export const PrivacyPolicy: React.FC = () => (
  <Shell title="Privacy Policy">
    <p>
      AISOP is a security operations workbench. Analysts load alerts and telemetry, review the evidence and produce
      reports. This deployment is a college project operated by the person named above.
    </p>

    <h2>What this website stores in your browser</h2>
    <ul>
      <li>
        The API key you enter is kept in this browser tab's session storage so a page refresh does not sign you out. It
        is cleared when the tab closes. It is not written to local storage and is sent only to the AISOP server.
      </li>
      <li>The site sets no cookies and loads no analytics, tracking or advertising scripts.</li>
      <li>Fonts are served by the site itself. The pages make no requests to third-party servers.</li>
    </ul>

    <h2>What the AISOP server stores</h2>
    <p>The server stores the security data your organization chooses to ingest:</p>
    <ul>
      <li>raw alert and event payloads, with their SHA-256 hashes</li>
      <li>normalized events and the entities extracted from them (IP addresses, hostnames, usernames, file hashes)</li>
      <li>cases, analyst accounts and roles</li>
      <li>an audit trail of investigation actions</li>
      <li>
        a security log of requests the server refused (a rejected API key, a lockout, a request for a path that does not
        exist, an oversized or malformed request). It keeps counts per minute with the source IP address, the request
        method and path, the response status and the first 160 characters of the client's user agent. It never keeps API
        keys, request bodies or other headers. Rows are deleted after 30 days and only a security admin can read them.
      </li>
    </ul>
    <p>
      This data can contain personal data about people in your environment. It is held in the operator's PostgreSQL
      database. This deployment is intended for sample data only.
    </p>

    <h2>AI features</h2>
    <p>
      Report drafting and investigation synthesis are optional and use a language model chosen by the operator. In the
      default configuration the model runs locally and evidence is not sent to a third-party AI service. If an
      operator connects an external model or threat intelligence service, the data sent to it is governed by that
      operator's configuration and that service's own terms. AI output is labeled as inference and an analyst reviews
      it before use.
    </p>

    <h2>Who can see data</h2>
    <p>
      Access is controlled by analyst accounts, global roles and per-case assignments enforced by the server. The "View
      as" selector in the header only changes what the interface shows. It does not change what the server allows.
    </p>

    <h2>Retention and deletion</h2>
    <p>
      The operator decides how long data is kept. To ask for access to, correction of, or deletion of personal data
      held in this deployment, contact the operator at the address above.
    </p>

    <h2>Changes</h2>
    <p>Changes to this policy are published on this page with a new effective date.</p>
  </Shell>
);

export const TermsOfService: React.FC = () => (
  <Shell title="Terms of Service">
    <p>
      These terms have not had legal review. This deployment is a college project provided for demonstration and
      learning.
    </p>

    <h2>Acceptance</h2>
    <p>
      By using this AISOP deployment you agree to these terms. If you do not agree, do not use it. If you use it for an
      organization, you confirm you may bind that organization.
    </p>

    <h2>Authorized use only</h2>
    <p>
      Use AISOP only on data and systems you are authorized to analyze. Do not use it to access, probe or disrupt
      systems you do not own or have permission to test, and do not ingest data you have no right to process. Use
      sample data only on this deployment.
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
        : 'No governing law has been chosen for this project. If a dispute arises, the operator and the user will try to resolve it in good faith first.'}
    </p>
  </Shell>
);
