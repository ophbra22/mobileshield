import type { Metadata, Viewport } from 'next';
import '@fontsource-variable/heebo';
import './globals.css';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'MobileShield | Check a suspicious message',
  description: 'Paste a suspicious SMS, WhatsApp or email message and get a plain-language answer about its warning signs.',
  icons: [{ rel: 'icon', url: '/favicon.svg' }],
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
  themeColor: '#08415C',
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
