import { test } from 'node:test';
import assert from 'node:assert';
import { translations, locales, defaultLocale } from '../src/i18n/translations';
import { useI18n } from '../src/composables/useI18n';

test('i18n translations dictionary is well-formed for EN and FR', () => {
  assert.deepStrictEqual(locales, ['en', 'fr']);
  assert.strictEqual(defaultLocale, 'en');

  // Verify cockpit namespace exists in both languages
  assert.ok(translations.en.cockpit, 'translations.en.cockpit must exist');
  assert.ok(translations.fr.cockpit, 'translations.fr.cockpit must exist');

  // Verify sub-namespaces
  const requiredNamespaces = [
    'header',
    'sidebar',
    'kpi',
    'columns',
    'drawer',
    'actionHeaders',
    'accountModal',
    'exportModal',
    'enrollModal',
    'footer',
    'unauthorized',
  ] as const;

  for (const ns of requiredNamespaces) {
    assert.ok(
      (translations.en.cockpit as any)[ns],
      `translations.en.cockpit.${ns} must exist`
    );
    assert.ok(
      (translations.fr.cockpit as any)[ns],
      `translations.fr.cockpit.${ns} must exist`
    );

    // Verify all keys present in FR are also present in EN
    const enKeys = Object.keys((translations.en.cockpit as any)[ns]).sort();
    const frKeys = Object.keys((translations.fr.cockpit as any)[ns]).sort();
    assert.deepStrictEqual(
      enKeys,
      frKeys,
      `Keys in cockpit.${ns} must match between EN and FR`
    );
  }
});

test('useI18n composable manages reactive locale and dictionary switching', () => {
  const { locale, t, setLocale, toggleLocale } = useI18n();

  // Switch to FR
  setLocale('fr');
  assert.strictEqual(locale.value, 'fr');
  assert.strictEqual(t.value.cockpit.header.title, "Vue d'ensemble du Cockpit");
  assert.strictEqual(t.value.cockpit.sidebar.title, 'Cockpit SOC');

  // Switch to EN
  setLocale('en');
  assert.strictEqual(locale.value, 'en');
  assert.strictEqual(t.value.cockpit.header.title, 'Cockpit Overview');
  assert.strictEqual(t.value.cockpit.sidebar.title, 'SOC Cockpit');

  // Toggle back to FR
  toggleLocale();
  assert.strictEqual(locale.value, 'fr');
  assert.strictEqual(t.value.cockpit.header.title, "Vue d'ensemble du Cockpit");
});
