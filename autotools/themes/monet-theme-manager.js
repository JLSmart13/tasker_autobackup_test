// monet-theme-manager.js
const monetThemeManager = {
    currentTheme: null,
    listeners: [],
    
    init: function() {
        this.extractSystemColors();
        this.watchSystemTheme();
        this.setupEventListeners();
    },
    
    extractSystemColors: function() {
        this.colors = {
            primary: this.getMonetColor('primary'),
            surface: this.getMonetColor('surface'),
            onSurface: this.getMonetColor('on-surface'),
            surfaceVariant: this.getMonetColor('surface-variant'),
            error: this.getMonetColor('error'),
            errorContainer: this.getMonetColor('error-container'),
            outline: this.getMonetColor('outline')
        };
        
        this.updateTheme(this.colors);
    },
    
    getMonetColor: function(name) {
        return window.getComputedStyle(document.documentElement)
            .getPropertyValue(`--md-sys-color-${name}`).trim();
    },
    
    watchSystemTheme: function() {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        mediaQuery.addEventListener('change', () => {
            this.extractSystemColors();
        });

        if (window.Android && window.Android.registerWallpaperChangeListener) {
            window.Android.registerWallpaperChangeListener(() => {
                this.extractSystemColors();
            });
        }
    },

    setupEventListeners: function() {
        eventBus.on('themeChanged', this.handleThemeChange.bind(this));
        eventBus.on('systemColorsChanged', this.handleSystemColorsChange.bind(this));
    },
    
    updateTheme: function(colors) {
        this.currentTheme = this.generateTheme(colors);
        this.notifyListeners();
        this.applyTheme(this.currentTheme);
    },
    
    generateTheme: function(colors) {
        const isDark = this.isDarkMode();
        return {
            colors: {
                ...colors,
                primaryContainer: this.adjustColor(colors.primary, isDark ? 'darken' : 'lighten'),
                secondaryContainer: this.adjustColor(colors.surfaceVariant, isDark ? 'darken' : 'lighten'),
                background: colors.surface,
                elevation: {
                    level1: this.adjustColor(colors.surface, 'overlay', 0.05),
                    level2: this.adjustColor(colors.surface, 'overlay', 0.08),
                    level3: this.adjustColor(colors.surface, 'overlay', 0.11),
                    level4: this.adjustColor(colors.surface, 'overlay', 0.12),
                    level5: this.adjustColor(colors.surface, 'overlay', 0.14)
                }
            },
            isDark: isDark,
            tones: this.generateTones(colors.primary)
        };
    },
    
    applyTheme: function(theme) {
        Object.entries(theme.colors).forEach(([key, value]) => {
            if (typeof value === 'string') {
                document.documentElement.style.setProperty(`--md-sys-color-${key}`, value);
            } else if (typeof value === 'object') {
                Object.entries(value).forEach(([subKey, subValue]) => {
                    document.documentElement.style.setProperty(
                        `--md-sys-color-${key}-${subKey}`,
                        subValue
                    );
                });
            }
        });

        document.documentElement.classList.toggle('dark', theme.isDark);
    },
    
    adjustColor: function(color, operation, amount = 0.1) {
        let hsl = this.hexToHSL(color);
        
        switch (operation) {
            case 'lighten':
                hsl.l = Math.min(1, hsl.l + amount);
                break;
            case 'darken':
                hsl.l = Math.max(0, hsl.l - amount);
                break;
            case 'overlay':
                return this.blend(color, this.isDarkMode() ? '#ffffff' : '#000000', amount);
        }
        
        return this.HSLToHex(hsl);
    },
    
    generateTones: function(baseColor) {
        const hsl = this.hexToHSL(baseColor);
        const tones = {};
        
        for (let i = 0; i <= 100; i += 10) {
            tones[i] = this.HSLToHex({
                h: hsl.h,
                s: hsl.s,
                l: i / 100
            });
        }
        
        return tones;
    },
    
    blend: function(color1, color2, amount) {
        const [r1, g1, b1] = this.hexToRGB(color1);
        const [r2, g2, b2] = this.hexToRGB(color2);
        
        const r = Math.round(r1 * (1 - amount) + r2 * amount);
        const g = Math.round(g1 * (1 - amount) + g2 * amount);
        const b = Math.round(b1 * (1 - amount) + b2 * amount);
        
        return this.RGBToHex(r, g, b);
    },
    
    hexToRGB: function(hex) {
        hex = hex.replace(/^#/, '');
        const bigint = parseInt(hex, 16);
        return [
            (bigint >> 16) & 255,
            (bigint >> 8) & 255,
            bigint & 255
        ];
    },
    
    RGBToHex: function(r, g, b) {
        return '#' + [r, g, b]
            .map(x => x.toString(16).padStart(2, '0'))
            .join('');
    },
    
    hexToHSL: function(hex) {
        let [r, g, b] = this.hexToRGB(hex);
        r /= 255;
        g /= 255;
        b /= 255;

        const max = Math.max(r, g, b);
        const min = Math.min(r, g, b);
        let h, s, l = (max + min) / 2;

        if (max === min) {
            h = s = 0;
        } else {
            const d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            switch (max) {
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;
                case g: h = (b - r) / d + 2; break;
                case b: h = (r - g) / d + 4; break;
            }
            h /= 6;
        }

        return { h, s, l };
    },
    
    HSLToHex: function({ h, s, l }) {
        let r, g, b;

        if (s === 0) {
            r = g = b = l;
        } else {
            const hue2rgb = (p, q, t) => {
                if (t < 0) t += 1;
                if (t > 1) t -= 1;
                if (t < 1/6) return p + (q - p) * 6 * t;
                if (t < 1/2) return q;
                if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
                return p;
            };

            const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
            const p = 2 * l - q;

            r = hue2rgb(p, q, h + 1/3);
            g = hue2rgb(p, q, h);
            b = hue2rgb(p, q, h - 1/3);
        }

        return this.RGBToHex(
            Math.round(r * 255),
            Math.round(g * 255),
            Math.round(b * 255)
        );
    },
    
    isDarkMode: function() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches;
    },
    
    subscribe: function(callback) {
        this.listeners.push(callback);
        callback(this.currentTheme);
        return () => {
            this.listeners = this.listeners.filter(cb => cb !== callback);
        };
    },
    
    notifyListeners: function() {
        this.listeners.forEach(callback => callback(this.currentTheme));
    },

    handleThemeChange: function(event) {
        this.extractSystemColors();
    },

    handleSystemColorsChange: function(event) {
        this.extractSystemColors();
    }
};

// Initialize theme manager
monetThemeManager.init();

// Export for use in other modules
export default monetThemeManager;
