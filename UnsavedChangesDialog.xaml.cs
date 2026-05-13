using System.Windows;

namespace LocalCam {
    public partial class UnsavedChangesDialog : Window {
        public UnsavedChangesDialog() {
            InitializeComponent();
        }

        public UnsavedChangesChoice Choice { get; private set; } = UnsavedChangesChoice.ContinueEditing;

        private void SaveAndClose_Click(object sender, RoutedEventArgs e) {
            Choice = UnsavedChangesChoice.SaveAndClose;
            DialogResult = true;
        }

        private void DiscardChanges_Click(object sender, RoutedEventArgs e) {
            Choice = UnsavedChangesChoice.DiscardChanges;
            DialogResult = true;
        }

        private void ContinueEditing_Click(object sender, RoutedEventArgs e) {
            Choice = UnsavedChangesChoice.ContinueEditing;
            DialogResult = false;
        }
    }

    public enum UnsavedChangesChoice {
        SaveAndClose,
        DiscardChanges,
        ContinueEditing
    }
}
