import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import { StorageNotice } from './StorageNotice';
import { SiteFooter } from './SiteFooter';
import { HeaderBar } from './HeaderBar';
import { LanguageProvider } from '../context/LanguageContext';
import { CHOICE_KEY, LANGUAGE_KEY } from '@/lib/consent';

function show() {
  render(<LanguageProvider><HeaderBar /><SiteFooter /><StorageNotice /></LanguageProvider>);
}

beforeEach(() => { localStorage.clear(); localStorage.setItem(LANGUAGE_KEY, 'en'); });

describe('storage notice', () => {
  it('shows on a first visit with equal-weight choices and stores nothing optional yet', async () => {
    localStorage.clear();
    show();
    expect(await screen.findByRole('region', { name: 'עוגיות ואחסון' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'אישור' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'לא לשמור' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'מדיניות עוגיות ואחסון' })).toHaveAttribute('href', '/cookies');
    await userEvent.setup().click(screen.getByRole('button', { name: /^English/ }));
    expect(localStorage.getItem(LANGUAGE_KEY)).toBeNull();
  });

  it('saves the language only after Allow', async () => {
    localStorage.clear();
    show();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'אישור' }));
    expect(localStorage.getItem(CHOICE_KEY)).toBe('granted');
    expect(screen.queryByRole('region', { name: 'עוגיות ואחסון' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^English/ }));
    expect(localStorage.getItem(LANGUAGE_KEY)).toBe('en');
  });

  it('"Do not save" deletes the saved language and keeps working', async () => {
    show();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Do not save' }));
    expect(localStorage.getItem(CHOICE_KEY)).toBe('denied');
    expect(localStorage.getItem(LANGUAGE_KEY)).toBeNull();
    await user.click(screen.getByRole('button', { name: /Switch to Hebrew/ }));
    expect(localStorage.getItem(LANGUAGE_KEY)).toBeNull();
    expect(document.documentElement).toHaveAttribute('dir', 'rtl');
  });

  it('can be reopened from the footer and takes focus when reopened', async () => {
    localStorage.setItem(CHOICE_KEY, 'denied');
    show();
    expect(screen.queryByRole('region', { name: 'Cookies and storage' })).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Storage settings' }));
    expect(await screen.findByRole('region', { name: 'Cookies and storage' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Allow' })).toHaveFocus();
    await act(async () => { await user.click(screen.getByRole('button', { name: 'Allow' })); });
    expect(localStorage.getItem(CHOICE_KEY)).toBe('granted');
  });
});
