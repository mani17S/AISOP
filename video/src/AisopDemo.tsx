/**
 * AISOP demo video.
 *
 * Layout and timing are adapted from two Locomotion templates (screen-showcase and step-explainer):
 * a framed screen beside staggered callouts, and a titled list whose underlines draw in. The template mockups
 * (placeholder rectangles, traffic-light dots, circular badges, animated cursor) are replaced by real screenshots
 * of the application running on sample data. No gradients, no emoji, no counters or claims beyond what the app does.
 */
import React from 'react';
import { AbsoluteFill, Img, Sequence, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig } from 'remotion';

const C = {
  bg: '#0b0d12',
  surface: '#14171d',
  border: '#262b35',
  text: '#eceef2',
  secondary: '#9aa3b2',
  muted: '#8795ad',
  accent: '#60a5fa',
};

const FONT = '"Geist Variable", "Segoe UI", system-ui, sans-serif';
const fontFace = `@font-face { font-family: "Geist Variable"; src: url("${staticFile('fonts/geist-latin-wght-normal.woff2')}") format("woff2"); font-weight: 100 900; }`;

const FADE = 12;

/** Fade in and out at the edges of a scene. */
const useSceneOpacity = (duration: number) => {
  const frame = useCurrentFrame();
  return interpolate(frame, [0, FADE, duration - FADE, duration], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
};

/** Smooth ease-out entrance with no overshoot. */
const useEnter = (delay: number) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config: { damping: 200 } });
};

const Title: React.FC<{ duration: number }> = ({ duration }) => {
  const opacity = useSceneOpacity(duration);
  const enter = useEnter(4);
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg, justifyContent: 'center', padding: '0 160px', opacity }}>
      <div style={{ opacity: enter, transform: `translateY(${interpolate(enter, [0, 1], [16, 0])}px)` }}>
        <div style={{ fontSize: 96, fontWeight: 500, color: C.text, lineHeight: 1 }}>AISOP</div>
        <div style={{ fontSize: 40, color: C.secondary, marginTop: 28, maxWidth: 1100, lineHeight: 1.3 }}>
          Alerts, cases and evidence in one analyst-controlled workflow
        </div>
        <div style={{ fontSize: 24, color: C.muted, marginTop: 56 }}>Security operations platform. Local first.</div>
      </div>
    </AbsoluteFill>
  );
};

type Callout = { text: string };

const Showcase: React.FC<{ duration: number; image: string; heading: string; callouts: Callout[] }> = ({
  duration,
  image,
  heading,
  callouts,
}) => {
  const opacity = useSceneOpacity(duration);
  const shot = useEnter(4);
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg, opacity, flexDirection: 'row', alignItems: 'center', padding: '0 80px', gap: 64 }}>
      <div
        style={{
          width: 1180,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          overflow: 'hidden',
          opacity: shot,
          transform: `translateX(${interpolate(shot, [0, 1], [-20, 0])}px)`,
          flexShrink: 0,
        }}
      >
        <Img src={staticFile(`shots/${image}`)} style={{ width: '100%', display: 'block' }} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 44, fontWeight: 500, color: C.text, lineHeight: 1.15, marginBottom: 40 }}>{heading}</div>
        {callouts.map((c, i) => (
          <Reveal key={c.text} delay={18 + i * 14}>
            <div style={{ fontSize: 26, color: C.secondary, lineHeight: 1.4, marginBottom: 28 }}>{c.text}</div>
          </Reveal>
        ))}
        <div style={{ fontSize: 20, color: C.muted, marginTop: 48 }}>Sample data</div>
      </div>
    </AbsoluteFill>
  );
};

const Reveal: React.FC<{ delay: number; children: React.ReactNode }> = ({ delay, children }) => {
  const p = useEnter(delay);
  return <div style={{ opacity: p, transform: `translateX(${interpolate(p, [0, 1], [16, 0])}px)` }}>{children}</div>;
};

const Workflow: React.FC<{ duration: number }> = ({ duration }) => {
  const opacity = useSceneOpacity(duration);
  const title = useEnter(4);
  const steps = ['Ingest alerts', 'Open a case', 'Review the evidence', 'Approve and export the report'];
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg, justifyContent: 'center', padding: '0 160px', opacity }}>
      <div
        style={{
          fontSize: 64,
          fontWeight: 500,
          color: C.text,
          marginBottom: 56,
          opacity: title,
          transform: `translateY(${interpolate(title, [0, 1], [16, 0])}px)`,
        }}
      >
        One workflow, analyst in control
      </div>
      {steps.map((s, i) => (
        <Step key={s} index={i + 1} text={s} delay={14 + i * 14} />
      ))}
      <div style={{ fontSize: 24, color: C.muted, marginTop: 56 }}>
        Reports and rules are never released without analyst approval.
      </div>
    </AbsoluteFill>
  );
};

const Step: React.FC<{ index: number; text: string; delay: number }> = ({ index, text, delay }) => {
  const p = useEnter(delay);
  return (
    <div style={{ display: 'flex', gap: 24, marginBottom: 28, opacity: p, transform: `translateX(${interpolate(p, [0, 1], [-20, 0])}px)` }}>
      <div style={{ fontSize: 28, color: C.muted, width: 40, paddingTop: 4 }}>{index}</div>
      <div>
        <div style={{ fontSize: 40, color: C.text }}>{text}</div>
        <div style={{ height: 2, backgroundColor: C.accent, width: `${interpolate(p, [0, 1], [0, 100])}%`, marginTop: 8 }} />
      </div>
    </div>
  );
};

const SCENES = [
  { id: 'title', frames: 120 },
  { id: 'alerts', frames: 210 },
  { id: 'workspace', frames: 210 },
  { id: 'evidence', frames: 180 },
  { id: 'workflow', frames: 180 },
] as const;

export const TOTAL_FRAMES = SCENES.reduce((n, s) => n + s.frames, 0);

export const AisopDemo: React.FC = () => {
  let from = 0;
  const start = (frames: number) => {
    const f = from;
    from += frames;
    return f;
  };
  const [title, alerts, workspace, evidence, workflow] = SCENES;
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg, fontFamily: FONT }}>
      <style>{fontFace}</style>
      <Sequence from={start(title.frames)} durationInFrames={title.frames}>
        <Title duration={title.frames} />
      </Sequence>
      <Sequence from={start(alerts.frames)} durationInFrames={alerts.frames}>
        <Showcase
          duration={alerts.frames}
          image="alerts.png"
          heading="Alerts from every source in one queue"
          callouts={[
            { text: 'SIEM, EDR, email, cloud and network alerts are normalized to one format' },
            { text: 'Each alert keeps the SHA-256 of its raw record' },
            { text: 'Related alerts are promoted to a case' },
          ]}
        />
      </Sequence>
      <Sequence from={start(workspace.frames)} durationInFrames={workspace.frames}>
        <Showcase
          duration={workspace.frames}
          image="workspace.png"
          heading="A case keeps its evidence together"
          callouts={[
            { text: 'Linked evidence is listed with UTC time, source and severity' },
            { text: 'Findings separate what was observed from what was inferred' },
            { text: 'AI synthesis runs only when an analyst starts it' },
          ]}
        />
      </Sequence>
      <Sequence from={start(evidence.frames)} durationInFrames={evidence.frames}>
        <Showcase
          duration={evidence.frames}
          image="evidence.png"
          heading="Evidence you can inspect"
          callouts={[
            { text: 'Normalized events with the indicators extracted from them' },
            { text: 'Duplicate records count as one piece of evidence' },
          ]}
        />
      </Sequence>
      <Sequence from={start(workflow.frames)} durationInFrames={workflow.frames}>
        <Workflow duration={workflow.frames} />
      </Sequence>
    </AbsoluteFill>
  );
};
