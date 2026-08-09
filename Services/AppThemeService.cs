using System.Windows;
using System.Windows.Media;
using LocalCam.Models;

namespace LocalCam.Services {
    internal static class AppThemeService {
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

            var isDark = preference switch {
                AppThemePreference.Dark => true,
                AppThemePreference.Light => false,
                _ => IsSystemDark()
            };

            SetBrush("WindowBackgroundBrush", isDark ? "#101722" : "#F4F6F8");
            SetBrush("PanelBackgroundBrush", isDark ? "#1B2231" : "#FFFFFF");
            SetBrush("CardBackgroundBrush", isDark ? "#202736" : "#FFFFFF");
            SetBrush("InputBackgroundBrush", isDark ? "#0F1624" : "#FFFFFF");
            SetBrush("PrimaryTextBrush", isDark ? "#E8EEF5" : "#172033");
            SetBrush("SecondaryTextBrush", isDark ? "#A9B4C7" : "#4A5568");
            SetBrush("MutedTextBrush", isDark ? "#8FA2BE" : "#5B6B82");
            SetBrush("BorderBrush", isDark ? "#2D3648" : "#CBD5E1");
            SetBrush("InputBorderBrush", isDark ? "#34405A" : "#A8B4C4");
            SetBrush("AccentBrush", isDark ? "#365070" : "#2E6DDE");
            SetBrush("ButtonBackgroundBrush", isDark ? "#26364D" : "#E7EEF8");
            SetBrush("ButtonHoverBrush", isDark ? "#304665" : "#D8E5F5");
            SetBrush("ButtonPressedBrush", isDark ? "#37557A" : "#C7D9F0");
            SetBrush("OverlayBackgroundBrush", isDark ? "#AA111827" : "#E8EEF5");
            SetBrush("OverlayBorderBrush", isDark ? "#CC365070" : "#9FB6D2");
            SetBrush("OverlayToolbarBrush", isDark ? "#CC1B2231" : "#E7EEF8");
            SetBrush("StopBrush", "#E11D48");
            SetBrush("PlayBrush", "#22C55E");
            SetBrush("CheckboxBrush", isDark ? "#0EA5E9" : "#1976D2");
        }

        public static Brush GetBrush(string key) {
            return Application.Current?.Resources[key] as Brush ?? Brushes.Transparent;
        }

        private static void SetBrush(string key, string color) {
            var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)!);
            brush.Freeze();
            Application.Current.Resources[key] = brush;
        }

        private static bool IsSystemDark() {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
#pragma warning restore WPF0001
    }
}
