using System.Windows;
using System.Windows.Media;
using LocalCam.Models;

namespace LocalCam.Services {
    internal static class AppThemeService {
        private static readonly (string AliasKey, string FluentBrushKey)[] ThemeBrushMappings = {
            ("WindowBackgroundBrush", "SolidBackgroundFillColorBaseBrush"),
            ("PanelBackgroundBrush", "SolidBackgroundFillColorSecondaryBrush"),
            ("CardBackgroundBrush", "CardBackgroundFillColorDefaultBrush"),
            ("InputBackgroundBrush", "ControlFillColorDefaultBrush"),
            ("PrimaryTextBrush", "TextFillColorPrimaryBrush"),
            ("SecondaryTextBrush", "TextFillColorSecondaryBrush"),
            ("MutedTextBrush", "TextFillColorTertiaryBrush"),
            ("BorderBrush", "ControlStrokeColorDefaultBrush"),
            ("InputBorderBrush", "ControlStrokeColorDefaultBrush"),
            ("AccentBrush", "AccentFillColorDefaultBrush"),
            ("AccentTextBrush", "TextOnAccentFillColorPrimaryBrush"),
            ("ButtonBackgroundBrush", "ControlFillColorDefaultBrush"),
            ("ButtonHoverBrush", "ControlFillColorSecondaryBrush"),
            ("ButtonPressedBrush", "ControlFillColorTertiaryBrush"),
            ("ErrorBrush", "SystemFillColorCriticalBrush"),
            ("SuccessBrush", "SystemFillColorSuccessBrush"),
            ("RecordingBrush", "SystemFillColorCriticalBrush"),
            ("OverlayBackgroundBrush", "LayerFillColorDefaultBrush"),
            ("OverlayBorderBrush", "SurfaceStrokeColorDefaultBrush"),
            ("OverlayToolbarBrush", "LayerFillColorAltBrush"),
            ("StopBrush", "TextFillColorPrimaryBrush"),
            ("PlayBrush", "AccentFillColorDefaultBrush"),
            ("CheckboxBrush", "AccentFillColorDefaultBrush")
        };

#pragma warning disable WPF0001
        public static void Apply(AppThemePreference preference) {
            if (Application.Current is null) {
                return;
            }

            Application.Current.ThemeMode = preference switch {
                AppThemePreference.Light => ThemeMode.Light,
                AppThemePreference.Dark => ThemeMode.Dark,
                _ => ThemeMode.System
            };

            RefreshLocalBrushes();
        }

        private static void RefreshLocalBrushes() {
            if (Application.Current is null) {
                return;
            }

            var resources = Application.Current.Resources;
            foreach (var (aliasKey, fluentBrushKey) in ThemeBrushMappings) {
                if (resources[fluentBrushKey] is not SolidColorBrush fluentBrush) {
                    continue;
                }

                resources[aliasKey] = fluentBrush.CloneCurrentValue();
            }
        }

        public static Brush GetBrush(string key) {
            return Application.Current?.Resources[key] as Brush
                ?? Brushes.Transparent;
        }
#pragma warning restore WPF0001
    }
}
