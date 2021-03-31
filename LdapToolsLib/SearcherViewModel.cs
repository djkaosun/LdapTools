using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Windows.Input;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;

namespace LdapToolsLib
{
    public class SearcherViewModel : INotifyPropertyChanged
    {
        private const int MAX_PAGE_SIZE = 1000;

        private const string EXECUTE_COMMAND_CONTENT = "Search Entries";

        /// <summary>
        /// LDAP のポート番号
        /// </summary>
        public const int LDAP_PORT = 389;

        /// <summary>
        /// LDAPS のポート番号
        /// </summary>
        public const int LDAPS_PORT = 636;

        #region Properties for Binding

        private string _SearchBaseDistinguishedName;
        public string SearchBaseDistinguishedName
        {
            get { return _SearchBaseDistinguishedName; }
            set
            {
                _SearchBaseDistinguishedName = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SearchBaseDistinguishedName)));
            }
        }

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

        private string _Password;
        public string Password
        {
            get { return _Password; }
            set
            {
                _Password = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Password)));
            }
        }

        private string _Filter;
        public string Filter
        {
            get { return _Filter; }
            set
            {
                _Filter = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Filter)));
            }
        }

        private string _SizeString;
        public string SizeString
        {
            get { return _SizeString; }
            set
            {
                _SizeString = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SizeString)));
            }
        }

        private bool _IsContinuous;
        public bool IsContinuous
        {
            get { return _IsContinuous; }
            set
            {
                _IsContinuous = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsContinuous)));
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
            private SearcherViewModel viewModel;
            private CancellationTokenSource _cts;
            public ExecuteCommandImpl(SearcherViewModel viewModel)
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
                    if (viewModel.Message == "Processing...") {
                        viewModel.Message = "Canceled.";
                    }
                    else
                    {
                        viewModel.Message += "\nCanceled.";
                    }
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
                        result = await SearchCoreProcess(viewModel.SearchBaseDistinguishedName, viewModel.Filter, viewModel.DistinguishedName, viewModel.Password, serverString, viewModel.IsTls, Int32.Parse(viewModel.SizeString), viewModel.IsContinuous,  _cts.Token);

                        _cts = null;
                        viewModel.ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
                        //viewModel.Message = result.Message;
                        //viewModel.MessageColor = result.MessageColor;
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

            private async Task<Result> SearchCoreProcess(string baseDN, string filter, string accountDN, string passwd, string server , bool isTls, int size, bool isContinuous, CancellationToken ct)
            {
                var result = new Result();
                result.Message = String.Empty;

                await Task.Run(() =>
                {
                    ulong entryCount = 0;
                    try
                    {
                        var ldapSearcher = new LdapSearcher() {
                            SearchBaseDN = baseDN,
                            Filter = filter,
                            AccountDN = accountDN,
                            Password = passwd,
                            LdapServer = server,
                            IsTls = isTls,
                            PageSize = size
                        };

                        viewModel.Message = String.Empty;
                        viewModel.MessageColor = "DodgerBlue";

                        foreach (var entries in ldapSearcher)
                        {
                            foreach (SearchResultEntry entry in entries)
                            {
                                var message = String.Empty;
                                foreach (DictionaryEntry item in entry.Attributes)
                                {
                                    var dirAttr = item.Value as DirectoryAttribute;

                                    // 属性名の出力
                                    message += dirAttr.Name + ": ";
                                    foreach (string valueString in dirAttr.GetValues(typeof(string)))
                                    {
                                        // 雑にすべての値を文字列として出力するので、内容によっては文字化ける。
                                        message += valueString + ", ";
                                    }
                                    message += "\n";
                                }
                                viewModel.Message += message + "\n";

                                entryCount++;
                            }

                            ct.ThrowIfCancellationRequested();
                            if (!isContinuous) break;
                        }
                    }
                    catch (Exception e)
                    {
                        if (e is OperationCanceledException ocException) throw ocException;


                        //viewModel.Message += "(" + e.GetType().Name + ")\n" + e.Message + "\n\n" + e;
                        viewModel.Message = "(" + e.GetType().Name + ")\n" + e.Message + "\n\n" + e;
                        viewModel.MessageColor = "Red";

                        if (e is LdapException ldapException) viewModel.Message += "\n\nErrorCode: " + ldapException.ErrorCode;
                        if (e is DirectoryOperationException doException)
                        {
                            if (doException.Response is SearchResponse searchResponse)
                            {
                                foreach (SearchResultEntry entry in searchResponse.Entries)
                                {
                                    var message = String.Empty;
                                    foreach (DictionaryEntry item in entry.Attributes)
                                    {
                                        var dirAttr = item.Value as DirectoryAttribute;

                                        // 属性名の出力
                                        message += dirAttr.Name + ": ";
                                        foreach (string valueString in dirAttr.GetValues(typeof(string)))
                                        {
                                            // 雑にすべての値を文字列として出力するので、内容によっては文字化ける。
                                            message += valueString + ", ";
                                        }
                                        message += "\n";
                                    }
                                    viewModel.Message += message + "\n";
                                    entryCount++;
                                }
                                viewModel.Message += "\n\n" + entryCount;
                                viewModel.Message += "\n\n" + searchResponse.Entries.Count;
                            }

                            viewModel.Message += "\n\nResultCode: " + doException.Response.ResultCode;
                        }
                    }
                });

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
        public SearcherViewModel()
        {
            ExecuteCommand = new ExecuteCommandImpl(this);
            ExecuteCommandContent = EXECUTE_COMMAND_CONTENT;
            this.PropertyChanged += PropertyChangedEventHandler;

            Server = LdapToolsSettings.GetValue("Search", "server");
            
            bool tlsValue;
            Boolean.TryParse(LdapToolsSettings.GetValue("Search", "tls"), out tlsValue);
            IsTls = tlsValue;
            
            DistinguishedName = LdapToolsSettings.GetValue("Search", "dn");
            Password = LdapToolsSettings.GetValue("Search", "passwd");
            SearchBaseDistinguishedName = LdapToolsSettings.GetValue("Search", "basedn");
            
            int sizeValue;
            Int32.TryParse(LdapToolsSettings.GetValue("Search", "continue"), out sizeValue);
            if (sizeValue < 1 || MAX_PAGE_SIZE < sizeValue) SizeString = MAX_PAGE_SIZE.ToString();
            else SizeString = sizeValue.ToString();

            bool continueValue;
            Boolean.TryParse(LdapToolsSettings.GetValue("Search", "continue"), out continueValue);
            IsContinuous = continueValue;
        }

        #region Event Handlers

        private void PropertyChangedEventHandler(object sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(Server):
                case nameof(DistinguishedName):
                case nameof(Password):
                case nameof(SearchBaseDistinguishedName):
                case nameof(Filter):
                    if (String.IsNullOrEmpty(Server))
                    {
                        Message = "Server is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(DistinguishedName))
                    {
                        Message = "Account DN is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(Password))
                    {
                        Message = "Password is null.";
                        MessageColor = "Red";
                        CanExecute = false;
                    }
                    else if (String.IsNullOrEmpty(SearchBaseDistinguishedName))
                    {
                        Message = "Base DN is null.";
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
