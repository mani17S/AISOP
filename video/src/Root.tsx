import React from 'react';
import { Composition } from 'remotion';
import { AisopDemo, TOTAL_FRAMES } from './AisopDemo';

export const Root: React.FC = () => (
  <Composition id="AisopDemo" component={AisopDemo} durationInFrames={TOTAL_FRAMES} fps={30} width={1920} height={1080} />
);
