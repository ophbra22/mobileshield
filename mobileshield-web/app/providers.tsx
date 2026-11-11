"use client";

import React from 'react';
import { LanguageProvider } from './context/LanguageContext';
import { StorageNotice } from './components/StorageNotice';

export function Providers({ children }: { children: React.ReactNode }) {
  return <LanguageProvider>{children}<StorageNotice /></LanguageProvider>;
}
