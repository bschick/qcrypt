import { Injectable, effect, signal } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  private readonly THEME_KEY = 'qcrypt-theme';

  private readonly mode = signal<'light' | 'dark' | 'auto'>('light');

  constructor() {
    // Load saved preference
    const saved = localStorage.getItem(this.THEME_KEY);
    if (saved === 'light' || saved === 'dark' || saved === 'auto') {
      this.mode.set(saved);
    } else {
      // Default to light mode
      this.mode.set('light');
    }

    // Apply initial theme immediately
    this.applyTheme();

    // Watch for changes and apply theme
    effect(() => {
      this.applyTheme();
    });
  }

  private applyTheme(): void {
    const theme = this.mode();
    let effectiveTheme: string;

    if (theme === 'auto') {
      // Check system preference
      effectiveTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } else {
      effectiveTheme = theme;
    }

    const htmlElement = document.documentElement;
    if (effectiveTheme === 'dark') {
      htmlElement.classList.add('dark-theme');
      htmlElement.classList.remove('light-theme');
    } else {
      htmlElement.classList.add('light-theme');
      htmlElement.classList.remove('dark-theme');
    }
  }

  getTheme(): 'light' | 'dark' | 'auto' {
    return this.mode();
  }

  setTheme(theme: 'light' | 'dark' | 'auto'): void {
    this.mode.set(theme);
    localStorage.setItem(this.THEME_KEY, theme);
  }

  toggleDarkMode(): void {
    const current = this.mode();
    if (current === 'light') {
      this.setTheme('dark');
    } else if (current === 'dark') {
      this.setTheme('light');
    } else {
      this.setTheme('dark');
    }
  }

  getIcon(): string {
    const theme = this.mode();
    switch(theme) {
      case 'dark': return 'dark_mode';
      case 'light': return 'light_mode';
      case 'auto': return 'brightness_auto';
      default: return 'light_mode';
    }
  }

  getLabel(): string {
    const theme = this.mode();
    switch(theme) {
      case 'dark': return 'Dark';
      case 'light': return 'Light';
      case 'auto': return 'Auto';
      default: return 'Light';
    }
  }
}

