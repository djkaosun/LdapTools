using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.ComponentModel;
using System.Windows.Input;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;

namespace LdapToolsLib
{
    public class AuthnTesterViewModel : INotifyPropertyChanged
    {
        private const string EXECUTE_COMMAND_CONTENT = "Authenticate User";

        /// <summary>
        /// LDAP のポート番号
        /// </summary>
        public const int LDAP_PORT = 389;

        /// <summary>
        /// LDAPS のポート番号
        /// </summary>
        public const int LDAPS_PORT = 636;

        #region Properties for Binding

        private string _Server;
        public string Server
        {
            get { return _Server; }
            set
            {
                _Server = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Server)));
            }
        }

        private bool _IsTls;
        public bool IsTls
        {
            get { return _IsTls; }
            set
            {
                _IsTls = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsTls)));
            }
        }

        private string _UserName;
        public string UserName
        {
            get { return _UserName; }
            set
            {
                _UserName = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UserName)));
            }
        }

        private string _Prefix;
        public string Prefix
        {
            get { return _Prefix; }
            set
            {
                _Prefix = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Prefix)));
            }
        }

        private string _Suffix;
        public string Suffix
        {
            get { return _Suffix; }
            set
            {
                _Suffix = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Suffix)));
            }
        }

        private string _UserPassword;
        public string UserPassword
        {
            get { return _UserPassword; }
            set
            {
                _UserPassword = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UserPassword)));
            }
        }

        private string _BindDN;
        public string BindDN
        {
            get { return _BindDN; }
            set
            {
                _BindDN = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(BindDN)));
            }
        }

        private string _Message;
        public string Message
        {
            get { return _Message; }
            set
            {
                _Message = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Message)));
            }
        }

        private string _MessageColor;
        public string MessageColor
        {
            get { return _MessageColor; }
            set
            {
                _MessageColor = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MessageColor)));
            }
        }

        #endregion

        #region Commands

        private string _ExecuteCommandContent;
        public string ExecuteCommandContent
        {
            get { return _ExecuteCommandContent; }
            private set
            {
                _ExecuteCommandContent = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ExecuteCommandContent)));
            }
        }

        /// <summary>
        /// 実行コマンド。
        /// </summary>
        public ICommand ExecuteCommand { get; private set; }
        private class ExecuteCommandImpl : ICommand
        {
            private AuthnTesterViewModel viewModel;
            private CancellationTokenSource _cts;
            public ExecuteCommandImpl(AuthnTesterViewModel viewModel)
            {
                this.viewModel = viewModel;
                viewModel.PropertyChanged += OnViewModelPropertyChangedEventHandler;
            }

            private void OnViewModelPropertyChangedEventHandler(object sender, PropertyChangedEventArgs e)
            {
                switch (e.PropertyName)
                {
                    case nameof(viewModel.CanExecute):
                        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
                        break;
                }
            }

            public event EventHandler CanExecuteChanged;

            public bool CanExecute(object parameter)
            {
                return viewModel.CanExecute || _cts != null;
            }

            public async void Execute(object parameter)
            {
                if (_cts != null)
                {
                    _cts?.Cancel();
                    viewModel.ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
                    viewModel.Message = "Canceled.";
                    viewModel.MessageColor = "Black";
                    _cts = null;
                }
                else
                {
                    viewModel.Message = "Processing...";
                    viewModel.MessageColor = "Black";

                    var serverString = ServerPortSpecify(viewModel.Server, viewModel.IsTls);

                    _cts = new CancellationTokenSource();
                    viewModel.ExecuteCommandContent = "Cancel";

                    Result result = new Result();
                    try
                    {
                        result = await AuthnTestCoreProcess(viewModel.UserName, viewModel.UserPassword, viewModel.Prefix, viewModel.Suffix, serverString, viewModel.IsTls, _cts.Token);

                        _cts = null;
                        viewModel.ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
                        viewModel.Message = result.Message;
                        viewModel.MessageColor = result.MessageColor;
                    }
                    catch (OperationCanceledException e)
                    {
                        System.Diagnostics.Debug.WriteLine(e);
                    }
                    finally
                    {
                    }
                }
            }

            private async Task<Result> AuthnTestCoreProcess(string userName, string userPasswd, string prefix, string suffix,string server,bool isTls, CancellationToken ct)
            {
                var result = new Result();

                await Task.Run(() =>
                {
                    try
                    {
                        var userEntry = LdapAuthnTester.Authn(userName, userPasswd, prefix, suffix, server, isTls);

                        if (userEntry != null)
                        {
                            result.Message = "[[[  Authn succeed.  ]]]\n";
                            foreach (DictionaryEntry item in userEntry.Attributes)
                            {
                                var dirAttr = item.Value as DirectoryAttribute;
                                // 属性名の出力
                                result.Message += dirAttr.Name + ": ";
                                foreach (string valueString in dirAttr.GetValues(typeof(string)))
                                {
                                    // 雑にすべての値を文字列として出力するので、内容によっては文字化ける。
                                    result.Message += valueString + ", ";
                                }
                                result.Message += "\n";
                            }
                            result.MessageColor = "DodgerBlue";
                        }
                        else
                        {
                            result.Message = "[[[  Authn failed.  ]]]";
                            result.MessageColor = "Red";
                        }
                    }
                    catch (Exception e)
                    {
                        result.Message = "(" + e.GetType().Name + ")\n" + e.Message + "\n\n" + e;
                        result.MessageColor = "Red";
                    }
                });

                ct.ThrowIfCancellationRequested();

                return result;
            }

            private struct Result
            {
                public string Message { get; set; }
                public string MessageColor { get; set; }
            }
        }

        #endregion

        private bool _CanExecute;
        private bool CanExecute
        {
            get { return _CanExecute; }
            set
            {
                _CanExecute = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanExecute)));
            }
        }

        /// <summary>
        /// プロパティが変更されたときに発生するイベントです。
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// コンストラクター。
        /// </summary>
        public AuthnTesterViewModel()
        {
            ExecuteCommand = new ExecuteCommandImpl(this);
            ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
            this.PropertyChanged += PropertyChangedEventHandler;

            Server = LdapToolsSettings.GetValue("AuthnTest", "server");
            bool tlsValue;
            Boolean.TryParse(LdapToolsSettings.GetValue("AuthnTest", "tls"), out tlsValue);
            IsTls = tlsValue;
            Prefix = LdapToolsSettings.GetValue("AuthnTest", "attr");
            Suffix = LdapToolsSettings.GetValue("AuthnTest", "basedn");
        }

        #region Event Handlers

        private void PropertyChangedEventHandler(object sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(Server):
                case nameof(UserName):
                case nameof(UserPassword):
                case nameof(Prefix):
                case nameof(Suffix):
                    if (String.IsNullOrEmpty(Server))
                    {
                        Message = "Server is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(UserName))
                    {
                        Message = "User name is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(UserPassword))
                    {
                        Message = "Password is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(Prefix))
                    {
                        Message = "Prefix is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(Suffix))
                    {
                        Message = "Prefix is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else
                    {
                        Message = "Passed the input validation check.";
                        MessageColor = "DodgerBlue";
                        CanExecute = true;
                    }

                    BindDN = LdapAuthnTester.GetUserDN(Prefix, UserName, Suffix);
                    
                    break;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// TCP ポート指定がされていないとき、明示的にポート指定を追加する。
        /// </summary>
        /// <param name="ldapServer">LDAP サーバー指定</param>
        private static string ServerPortSpecify(string ldapServer, bool isTls)
        {
            if (!Regex.IsMatch(ldapServer, ":[1-9][0-9]*$"))
            {
                if (isTls) return ldapServer + ":" + LDAPS_PORT;
                else return ldapServer + ":" + LDAP_PORT;
            }
            else return ldapServer;
        }

        #endregion
    }
}
