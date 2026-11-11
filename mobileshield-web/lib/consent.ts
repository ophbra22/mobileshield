/**
 * Device-storage consent. MobileShield sets no cookies. The only optional item
 * it can keep on a device is the language preference (localStorage "ms_lang"),
 * and only after the visitor allows it. The choice itself is kept so the notice
 * is not shown again; that record is strictly necessary to respect the choice.
 */
export type StorageChoice = 'granted' | 'denied';

export const CHOICE_KEY = 'ms_storage_choice';
export const LANGUAGE_KEY = 'ms_lang';
export const CHOICE_EVENT = 'ms-storage-choice';

export function readStorageChoice(): StorageChoice | null {
  try {
    const value = localStorage.getItem(CHOICE_KEY);
    return value === 'granted' || value === 'denied' ? value : null;
  } catch {
    return null;
  }
}

export function writeStorageChoice(choice: StorageChoice): void {
  try {
    localStorage.setItem(CHOICE_KEY, choice);
    if (choice === 'denied') localStorage.removeItem(LANGUAGE_KEY);
  } catch {
    /* Storage may be blocked; the site works the same without it. */
  }
  window.dispatchEvent(new CustomEvent<StorageChoice>(CHOICE_EVENT, { detail: choice }));
}

/** Ask the notice to show again (from the footer's storage settings link). */
export const OPEN_SETTINGS_EVENT = 'ms-open-storage-settings';
export function openStorageSettings(): void {
  window.dispatchEvent(new Event(OPEN_SETTINGS_EVENT));
}
