using System.Windows;
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

        }

        public static System.Windows.Media.Brush GetBrush(string key) {
            return Application.Current?.Resources[key] as System.Windows.Media.Brush
                ?? System.Windows.Media.Brushes.Transparent;
        }
#pragma warning restore WPF0001
    }
}
