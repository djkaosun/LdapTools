using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using LdapToolsLib;

namespace LdapToolsWpf
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private AuthnTesterViewModel authnTestViewModel;
        private PasswdChangerViewModel passwdChangeViewModel;
        private SearcherViewModel searchViewModel;

        public MainWindow()
        {
            InitializeComponent();

            authnTestViewModel = new AuthnTesterViewModel();
            this.AuthnTestTab.DataContext = authnTestViewModel;

            passwdChangeViewModel = new PasswdChangerViewModel();
            this.ChangePasswdTab.DataContext = passwdChangeViewModel;

            searchViewModel = new SearcherViewModel();
            this.SystemPasswordBox.Password = searchViewModel.Password;
            this.SearchTab.DataContext = searchViewModel;
        }

        private void UserPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            authnTestViewModel.UserPassword = UserPasswordBox.Password;
        }

        private void OldPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            passwdChangeViewModel.OldPassword = OldPasswordBox.Password;
        }

        private void NewPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            passwdChangeViewModel.NewPassword = NewPasswordBox.Password;
        }

        private void ConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            passwdChangeViewModel.ConfirmPassword = ConfirmPasswordBox.Password;
        }

        private void SystemPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            searchViewModel.Password = SystemPasswordBox.Password;
        }
    }
}
