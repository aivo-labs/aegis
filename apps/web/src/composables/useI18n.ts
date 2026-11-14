import { ref, computed, onMounted, onUnmounted, getCurrentInstance } from 'vue';
import { translations, type Locale } from '../i18n/translations';

// État réactif partagé au niveau du module pour synchroniser immédiatement tous les composants Vue du Cockpit
const currentLocale = ref<Locale>('fr');
let isInitialized = false;

function detectInitialLocale(): Locale {
  if (typeof window === 'undefined') return 'fr';
  
  try {
    const saved = localStorage.getItem('aegis_locale');
    if (saved === 'en' || saved === 'fr') {
      return saved;
    }
  } catch (e) {}

  if (typeof document !== 'undefined') {
    const docLang = document.documentElement.getAttribute('lang');
    if (docLang === 'en' || docLang === 'fr') {
      return docLang;
    }
  }

  if (typeof navigator !== 'undefined') {
    if (navigator.language && navigator.language.toLowerCase().startsWith('en')) {
      return 'en';
    }
  }

  return 'fr';
}

export function useI18n() {
  if (typeof window !== 'undefined' && !isInitialized) {
    currentLocale.value = detectInitialLocale();
    isInitialized = true;
  }

  const locale = computed(() => currentLocale.value);

  const t = computed(() => {
    return translations[currentLocale.value] || translations.fr;
  });

  const setLocale = (newLocale: Locale) => {
    if (newLocale !== 'en' && newLocale !== 'fr') return;
    currentLocale.value = newLocale;

    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem('aegis_locale', newLocale);
      } catch (e) {}

      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('lang', newLocale);
      }

      window.dispatchEvent(
        new CustomEvent('aegis-locale-changed', { detail: { locale: newLocale } })
      );
    }
  };

  const toggleLocale = () => {
    setLocale(currentLocale.value === 'fr' ? 'en' : 'fr');
  };

  const handleLocaleChanged = (e: any) => {
    const loc = e?.detail?.locale;
    if (loc === 'en' || loc === 'fr') {
      currentLocale.value = loc;
    }
  };

  if (getCurrentInstance()) {
    onMounted(() => {
      if (typeof window !== 'undefined') {
        window.addEventListener('aegis-locale-changed', handleLocaleChanged);
      }
    });

    onUnmounted(() => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('aegis-locale-changed', handleLocaleChanged);
      }
    });
  }

  return {
    locale,
    t,
    setLocale,
    toggleLocale,
  };
}
