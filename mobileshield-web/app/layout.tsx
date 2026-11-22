import type { Metadata, Viewport } from 'next';
import './globals.css';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'PauseCheck | Check a suspicious message',
  description: 'Paste a suspicious SMS, WhatsApp or email message and get a plain-language answer about its warning signs.',
  icons: [{ rel: 'icon', url: '/favicon.svg' }],
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
  themeColor: '#0F4F4A',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="he" dir="rtl">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
