// react/hooks/use-monet-theme.js
import { useState, useEffect } from 'react';

const useMonetTheme = () => {
    const [theme, setTheme] = useState(null);
    const [isDark, setIsDark] = useState(false);

    useEffect(() => {
        // Initial theme setup
        updateTheme();

        // Watch for system theme changes
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        mediaQuery.addListener(handleThemeChange);

        // Watch for wallpaper changes if available
        if (window.Android?.registerWallpaperChangeListener) {
            window.Android.registerWallpaperChangeListener(updateTheme);
        }

        return () => {
            mediaQuery.removeListener(handleThemeChange);
            if (window.Android?.unregisterWallpaperChangeListener) {
                window.Android.unregisterWallpaperChangeListener(updateTheme);
            }
        };
    }, []);

    const handleThemeChange = (e) => {
        setIsDark(e.matches);
        updateTheme();
    };

    const updateTheme = () => {
        const colors = extractSystemColors();
        const currentIsDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        setIsDark(currentIsDark);
        setTheme(generateTheme(colors, currentIsDark));
    };

    const extractSystemColors = () => {
        // Get colors from CSS variables or system
        return {
            primary: getMonetColor('primary'),
            surface: getMonetColor('surface'),
            onSurface: getMonetColor('on-surface'),
            surfaceVariant: getMonetColor('surface-variant'),
            error: getMonetColor('error'),
            errorContainer: getMonetColor('error-container'),
            outline: getMonetColor('outline')
        };
    };

    const getMonetColor = (name) => {
        if (window.Android?.getMonetColor) {
            return window.Android.getMonetColor(name);
        }
        // Fallback to CSS variables
        return getComputedStyle(document.documentElement)
            .getPropertyValue(`--md-sys-color-${name}`).trim();
    };

    const generateTheme = (colors, isDark) => {
        return {
            colors: {
                ...colors,
                // Generate all Material You color variants
                primaryContainer: adjustColor(colors.primary, isDark ? 'darken' : 'lighten'),
                secondaryContainer: adjustColor(colors.surfaceVariant, isDark ? 'darken' : 'lighten'),
                background: colors.surface,
                elevation: {
                    level1: adjustColor(colors.surface, 'overlay', 0.05),
                    level2: adjustColor(colors.surface, 'overlay', 0.08),
                    level3: adjustColor(colors.surface, 'overlay', 0.11),
                    level4: adjustColor(colors.surface, 'overlay', 0.12),
                    level5: adjustColor(colors.surface, 'overlay', 0.14)
                }
            },
            isDark,
            tones: generateTones(colors.primary)
        };
    };

    const adjustColor = (color, operation, amount = 0.1) => {
        const hsl = hexToHSL(color);
        
        switch (operation) {
            case 'lighten':
                hsl.l = Math.min(1, hsl.l + amount);
                break;
            case 'darken':
                hsl.l = Math.max(0, hsl.l - amount);
                break;
            case 'overlay':
                return blend(color, isDark ? '#ffffff' : '#000000', amount);
        }
        
        return HSLToHex(hsl);
    };

    const generateTones = (baseColor) => {
        const hsl = hexToHSL(baseColor);
        const tones = {};
        
        for (let i = 0; i <= 100; i += 10) {
            tones[i] = HSLToHex({
                h: hsl.h,
                s: hsl.s,
                l: i / 100
            });
        }
        
        return tones;
    };

    // Color utility functions
    const blend = (color1, color2, amount) => {
        const [r1, g1, b1] = hexToRGB(color1);
        const [r2, g2, b2] = hexToRGB(color2);
        
        const r = Math.round(r1 * (1 - amount) + r2 * amount);
        const g = Math.round(g1 * (1 - amount) + g2 * amount);
        const b = Math.round(b1 * (1 - amount) + b2 * amount);
        
        return RGBToHex(r, g, b);
    };

    const hexToRGB = (hex) => {
        hex = hex.replace(/^#/, '');
        const bigint = parseInt(hex, 16);
        return [
            (bigint >> 16) & 255,
            (bigint >> 8) & 255,
            bigint & 255
        ];
    };

    const RGBToHex = (r, g, b) => {
        return '#' + [r, g, b]
            .map(x => x.toString(16).padStart(2, '0'))
            .join('');
    };

    const hexToHSL = (hex) => {
        let [r, g, b] = hexToRGB(hex);
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
    };

    const HSLToHex = ({ h, s, l }) => {
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

        return RGBToHex(
            Math.round(r * 255),
            Math.round(g * 255),
            Math.round(b * 255)
        );
    };

    return { theme, isDark, updateTheme };
};

export default useMonetTheme;
