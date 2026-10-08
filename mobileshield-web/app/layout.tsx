import type { Metadata } from 'next';
import './globals.css';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'MobileShield | Message warning checks',
  description: 'Check pasted messages and links for warning signs with MobileShield.',
  icons: [{ rel: 'icon', url: '/favicon.svg' }],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="he" dir="rtl">
      <body className="bg-bg text-text">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
