using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;

namespace LocalCam {
    public partial class PromoCodeRedemptionDialog : Window {
        private static readonly Regex PromoCodePattern = new("^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private string _promoCode = string.Empty;

        public PromoCodeRedemptionDialog() {
            InitializeComponent();
        }

        public bool ShouldRedeem { get; private set; }
        public string PromoCode => _promoCode;

        private void Redeem_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            if (!TryGetNormalizedPromoCode(out var promoCode)) {
                return;
            }

            _promoCode = promoCode;
            ShouldRedeem = true;
            DialogResult = true;
        }

        private void Close_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            DialogResult = false;
        }

        private void PromoCodeTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) {
            _ = sender;
            _ = e;
            ValidatePromoCode(showMessage: false);
        }

        private void Window_KeyDown(object sender, KeyEventArgs e) {
            _ = sender;
            if (e.Key == Key.Escape) {
                DialogResult = false;
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            PromoCodeTextBox.Focus();
            PromoCodeTextBox.SelectAll();
        }

        private bool TryGetNormalizedPromoCode(out string promoCode) {
            promoCode = string.Empty;
            if (!ValidatePromoCode(showMessage: true)) {
                return false;
            }

            promoCode = _promoCode;
            return true;
        }

        private bool ValidatePromoCode(bool showMessage) {
            var normalized = NormalizePromoCode(PromoCodeTextBox.Text);
            var isValid = normalized is not null;
            _promoCode = isValid ? normalized! : string.Empty;

            if (showMessage) {
                ValidationTextBlock.Text = isValid ? string.Empty : "Enter a valid promo code in the format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.";
                ValidationTextBlock.Visibility = isValid ? Visibility.Collapsed : Visibility.Visible;
            }
            else if (isValid) {
                ValidationTextBlock.Text = string.Empty;
                ValidationTextBlock.Visibility = Visibility.Collapsed;
            }

            return isValid;
        }

        private static string? NormalizePromoCode(string? promoCode) {
            if (string.IsNullOrWhiteSpace(promoCode)) {
                return null;
            }

            var normalized = new string(promoCode
                .Trim()
                .ToUpperInvariant()
                .Where(ch => char.IsLetterOrDigit(ch) || ch == '-')
                .ToArray());

            return PromoCodePattern.IsMatch(normalized) ? normalized : null;
        }
    }
}
