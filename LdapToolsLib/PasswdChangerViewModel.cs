using System;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Windows.Input;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;

namespace LdapToolsLib
{
    public class PasswdChangerViewModel : INotifyPropertyChanged
    {
        private const string EXECUTE_COMMAND_CONTENT = "Change Password";

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

        private string _DistinguishedName;
        public string DistinguishedName
        {
            get { return _DistinguishedName; }
            set
            {
                _DistinguishedName = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DistinguishedName)));
            }
        }

        private string _OldPassword;
        public string OldPassword
        {
            get { return _OldPassword; }
            set
            {
                _OldPassword = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(OldPassword)));
            }
        }

        private string _NewPassword;
        public string NewPassword
        {
            get { return _NewPassword; }
            set
            {
                _NewPassword = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(NewPassword)));
            }
        }

        private string _ConfirmPassword;
        public string ConfirmPassword
        {
            get { return _ConfirmPassword; }
            set
            {
                _ConfirmPassword = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ConfirmPassword)));
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
            private PasswdChangerViewModel viewModel;
            private CancellationTokenSource _cts;
            public ExecuteCommandImpl(PasswdChangerViewModel viewModel)
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
                        result = await PasswordChangeCoreProcess(viewModel.DistinguishedName, viewModel.OldPassword, viewModel.NewPassword, serverString, viewModel.IsTls, _cts.Token);

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

            private async Task<Result> PasswordChangeCoreProcess(string accountDN, string oldPasswd, string newPasswd, string server , bool isTls, CancellationToken ct)
            {
                var result = new Result();

                await Task.Run(() => {
                    try
                    {
                        LdapPasswdChanger.ChangePassword(accountDN, oldPasswd, newPasswd, server, isTls);

                        result.Message = "Completed successfully.\nYour password has been changed.";
                        result.MessageColor = "DodgerBlue";
                    }
                    catch (Exception e)
                    {
                        /*
                        if(e is LdapException ldapException)
                        {
                            result.Message = "(" + ldapException.GetType().Name + ":" + ldapException.ErrorCode + ")\n"
                                    + ldapException.Message;
                            if (!String.IsNullOrEmpty(ldapException.ServerErrorMessage)) result.Message += "\n" + ldapException.ServerErrorMessage;
                        }
                        else {
                            result.Message = "(" + e.GetType().Name + ")\n" + e.Message;
                        }
                        //*/
                        result.Message = "(" + e.GetType().Name + ")\n" + e.Message + "\n" + e;

                        if (e.InnerException != null)
                        {
                            try
                            {
                                var sockException = (System.Net.Sockets.SocketException)e.InnerException;
                                result.Message += "\n\n" + sockException.Message
                                        + "\n" + sockException.NativeErrorCode + "(0x" + Int32.Parse(sockException.NativeErrorCode.ToString()).ToString("x8").ToUpper() + ")"
                                        + "\n" + sockException.SocketErrorCode
                                        + "\n" + sockException.Source
                                        + "\n" + sockException.TargetSite
                                        + "\n0x" + sockException.HResult.ToString("x8").ToUpper();
                            }
                            catch (Exception castException)
                            {
                                result.Message += "\n\n" + castException;
                            }
                        }

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
        private bool CanExecute {
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
        public PasswdChangerViewModel()
        {
            ExecuteCommand = new ExecuteCommandImpl(this);
            ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
            this.PropertyChanged += PropertyChangedEventHandler;

            Server = LdapToolsSettings.GetValue("PasswdChange", "server");
            bool tlsValue;
            Boolean.TryParse(LdapToolsSettings.GetValue("PasswdChange", "tls"), out tlsValue);
            IsTls = tlsValue;
            DistinguishedName = LdapToolsSettings.GetValue("PasswdChange", "dn");
        }

        #region Event Handlers

        private void PropertyChangedEventHandler(object sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(Server):
                case nameof(DistinguishedName):
                case nameof(OldPassword):
                case nameof(NewPassword):
                case nameof(ConfirmPassword):
                    if (String.IsNullOrEmpty(Server))
                    {
                        Message = "Server is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(DistinguishedName))
                    {
                        Message = "DN is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(OldPassword))
                    {
                        Message = "Old password is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(NewPassword))
                    {
                        Message = "New password is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (NewPassword != ConfirmPassword)
                    {
                        Message = "Input for confirm is different from new password.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else
                    {
                        Message = "Passed the input validation check.";
                        MessageColor = "DodgerBlue";
                        CanExecute = true;
                    }
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
