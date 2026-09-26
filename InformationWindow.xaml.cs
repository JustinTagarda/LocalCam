using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text;
using System.Runtime.InteropServices;

namespace LocalCam {
    public partial class InformationWindow : Window {
        private readonly string _clipboardText;

        public InformationWindow(
            string title,
            IReadOnlyList<(string Section, string Label, string Value)> rows) {
            InitializeComponent();
            Title = title;
            DialogTitleText.Text = title;
            System.Windows.Automation.AutomationProperties.SetName(CopyButton, "Copy camera information");
            _clipboardText = FormatClipboardText(rows);
            PopulateSections(rows);
        }

        private static string FormatClipboardText(IReadOnlyList<(string Section, string Label, string Value)> rows) {
            var text = new StringBuilder();
            string? currentSection = null;
            foreach (var row in rows) {
                if (!string.Equals(currentSection, row.Section, StringComparison.Ordinal)) {
                    if (text.Length > 0) {
                        text.AppendLine();
                    }

                    currentSection = row.Section;
                    text.AppendLine(currentSection);
                }

                text.Append(row.Label).Append(": ").AppendLine(row.Value);
            }

            return text.ToString().TrimEnd();
        }

        private void PopulateSections(IReadOnlyList<(string Section, string Label, string Value)> rows) {
            foreach (var section in rows.GroupBy(static row => row.Section)) {
                var sectionPanel = new StackPanel();
                var heading = new TextBlock {
                    Text = section.Key,
                    FontSize = 12,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = GetBrush("AccentBrush"),
                    Margin = new Thickness(0, 0, 0, 7)
                };
                sectionPanel.Children.Add(heading);

                foreach (var row in section) {
                    sectionPanel.Children.Add(CreateInformationRow(row.Label, row.Value));
                }

                InformationSections.Children.Add(new Border {
                    Background = GetBrush("PanelBackgroundBrush"),
                    BorderBrush = GetBrush("BorderBrush"),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(10),
                    Margin = new Thickness(0, 0, 0, 8),
                    Child = sectionPanel
                });
            }
        }

        private static FrameworkElement CreateInformationRow(string label, string value) {
            var grid = new Grid {
                Margin = new Thickness(0, 2, 0, 2)
            };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(112) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var labelText = new TextBlock {
                Text = label,
                Foreground = GetBrush("SecondaryTextBrush"),
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(labelText, 0);
            grid.Children.Add(labelText);

            var valueText = new TextBlock {
                Text = value,
                Foreground = GetBrush("PrimaryTextBrush"),
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap
            };
            Grid.SetColumn(valueText, 1);
            grid.Children.Add(valueText);
            return grid;
        }

        private static Brush GetBrush(string resourceKey) {
            return Application.Current?.Resources[resourceKey] as Brush ?? Brushes.Transparent;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) {
            Close();
        }

        private void CopyButton_Click(object sender, RoutedEventArgs e) {
            try {
                Clipboard.SetText(_clipboardText);
                CopyStatusText.Text = "Copied";
                CopyStatusText.Visibility = Visibility.Visible;
            } catch (ExternalException) {
                ShowCopyFailure();
            } catch (InvalidOperationException) {
                ShowCopyFailure();
            }
        }

        private void ShowCopyFailure() {
            CopyStatusText.Text = "Could not copy. Try again.";
            CopyStatusText.Visibility = Visibility.Visible;
        }
    }
}
