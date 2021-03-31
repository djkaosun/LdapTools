using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Collections;

namespace LdapToolsLib
{
    public class LdapSearcher : IEnumerable<List<SearchResultEntry>>
    {
        #region Constant Values

        /// <summary>
        /// LDAP のポート番号
        /// </summary>
        public const int LDAP_PORT = 389;

        /// <summary>
        /// LDAPS のポート番号
        /// </summary>
        public const int LDAPS_PORT = 636;
        //public const int LDAPS_DEFAULT_PORT = 3296;

        /// <summary>
        /// 既定のページサイズ
        /// </summary>
        public const int DEFAULT_PAGE_SIZE = 1000;

        /// <summary>
        /// すべてのエントリーを検索対象とするフィルター
        /// </summary>
        public const string DEFAULT_FILTER = "(objectClass=*)";

        /// <summary>
        /// このクラスで使用する LDAP バージョン
        /// </summary>
        public const int LDAP_VERSION = 3;

        #endregion

        #region Properties

        /// <summary>
        /// <see cref="System.Threading.CancellationToken"/>。
        /// </summary>
        public CancellationToken CancellationToken { get; set; }

        public string _SearchBaseDN;
        /// <summary>
        /// 検索のベースとなる DN。
        /// </summary>
        public string SearchBaseDN
        {
            get { return _SearchBaseDN; }
            set
            {
                _SearchBaseDN = value;
            }
        }

        public string _Filter;
        /// <summary>
        /// 検索フィルター。
        /// </summary>
        public string Filter
        {
            get { return _Filter; }
            set
            {
                _Filter = value;
            }
        }

        public string _AccountDN;
        /// <summary>
        /// アカウント DN。
        /// </summary>
        public string AccountDN
        {
            get { return _AccountDN; }
            set
            {
                _AccountDN = value;
            }
        }

        public string _Password;
        /// <summary>
        /// パスワード。
        /// </summary>
        public string Password
        {
            get { return _Password; }
            set
            {
                _Password = value;
            }
        }

        public string _LdapServer;
        /// <summary>
        /// LDAP サーバー。
        /// </summary>
        public string LdapServer
        {
            get { return _LdapServer; }
            set
            {
                _LdapServer = value;
            }
        }

        public bool _IsTls;
        /// <summary>
        /// LDAPS を利用する場合 true。利用しない場合は false。
        /// </summary>
        public bool IsTls
        {
            get { return _IsTls; }
            set
            {
                _IsTls = value;
            }
        }

        public int _PageSize;
        /// <summary>
        /// ページ サイズ。
        /// </summary>
        public int PageSize
        {
            get { return _PageSize; }
            set
            {
                _PageSize = value;
            }
        }

        #endregion

        public IEnumerator<List<SearchResultEntry>> GetEnumerator()
        {
            return new SearchEnumerator(SearchBaseDN, Filter, AccountDN, Password, LdapServer, IsTls, PageSize);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        #region Static Methods

        /// <summary>
        /// エントリを検索する。
        /// </summary>
        /// <param name="searchBaseDN">検索のベースとなる DN。</param>
        /// <param name="filter">検索フィルター。</param>
        /// <param name="accountDN">アカウント DN。</param>
        /// <param name="passwd">パスワード。</param>
        /// <param name="ldapServer">LDAP サーバー。</param>
        /// <param name="isTls">LDAPS を利用する場合 true。利用しない場合は false。</param>
        /// <returns>検索結果。</returns>
        public static List<SearchResultEntry> Search(string searchBaseDN, string filter, string accountDN, string passwd, string ldapServer, bool isTls, int size, bool isContinuous)
        {
            return Search(searchBaseDN, filter, accountDN, passwd, ldapServer, isTls, size, isContinuous, CancellationToken.None);
        }

        /// <summary>
        /// エントリを検索する。
        /// </summary>
        /// <param name="searchBaseDN">検索のベースとなる DN。</param>
        /// <param name="filter">検索フィルター。</param>
        /// <param name="accountDN">アカウント DN。</param>
        /// <param name="passwd">パスワード。</param>
        /// <param name="ldapServer">LDAP サーバー。</param>
        /// <param name="isTls">LDAPS を利用する場合 true。利用しない場合は false。</param>
        /// <param name="ct"><see cref="CancellationToken"/>。</param>
        /// <returns>検索結果。</returns>
        public static List<SearchResultEntry> Search(string searchBaseDN, string filter, string accountDN, string passwd, string ldapServer, bool isTls, int size, bool isContinuous, CancellationToken ct)
        {
            var resultList = new List<SearchResultEntry>();

            var ldapSearcher = new LdapSearcher() {
                SearchBaseDN = searchBaseDN,
                Filter = filter,
                AccountDN = accountDN,
                Password = passwd,
                LdapServer = ldapServer,
                IsTls = isTls,
                PageSize = size
            };

            foreach(var pagedList in ldapSearcher)
            {
                foreach(var enrty in pagedList)
                {
                    resultList.Add(enrty);
                }

                ct.ThrowIfCancellationRequested();
                if (!isContinuous) break;
            }

            return resultList;
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

        /// <summary>
        /// Cookie が null もしくは全ゼロであるかを判定します。
        /// </summary>
        /// <param name="cookie">LDAP サーバーから返ってきた Cookie</param>
        /// <returns>null もしくは全ゼロである場合は True。それ以外の場合 false。</returns>
        private static bool IsNullCookie(byte[] cookie)
        {
            if (cookie != null)
            {
                foreach (var byteCookie in cookie)
                {
                    if (byteCookie != 0)
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        #endregion

        #region Enumerator Class
        private class SearchEnumerator : IEnumerator<List<SearchResultEntry>>
        {
            private List<SearchResultEntry> _Current;
            public List<SearchResultEntry> Current {
                get {
                    if (_Current == null) throw new InvalidOperationException();
                    return _Current;
                }
                private set { _Current = value; }
            }

            object IEnumerator.Current => Current;

            private string searchBaseDN;
            private string filter;
            private string accountDN;
            private string passwd;
            private string ldapServer;
            private bool isTls;
            private int size;
            private LdapConnection ldapConnection;
            private SearchRequest searchRequest;
            private PageResultRequestControl pageResultRequestControl;
            private bool hasNext;
            private byte[] cookie;

            public SearchEnumerator(string searchBaseDN, string filter, string accountDN, string passwd, string ldapServer, bool isTls, int size)
            {
                this.searchBaseDN = searchBaseDN;
                this.filter = filter;
                this.accountDN = accountDN;
                this.passwd = passwd;
                this.ldapServer = ldapServer;
                this.isTls = isTls;
                this.size = size;
                Initialize();
            }

            private void Initialize()
            {
                if (String.IsNullOrEmpty(searchBaseDN)
                        || String.IsNullOrEmpty(accountDN)
                        || passwd == null
                        || String.IsNullOrEmpty(ldapServer))
                {
                    throw new InvalidOperationException("必要なプロパティがセットされていません。");
                }

                if (String.IsNullOrEmpty(filter)) filter = DEFAULT_FILTER;
                if (size < 1) size = DEFAULT_PAGE_SIZE;
                hasNext = true;

                ldapServer = ServerPortSpecify(ldapServer, isTls);

                // LDAP 接続を生成
                var ldapCnct = new LdapConnection(ldapServer)
                {
                    Credential = new NetworkCredential(accountDN, passwd),
                    AuthType = AuthType.Basic,
                    Timeout = new TimeSpan(0, 0, 10)
                };
                ldapCnct.SessionOptions.ProtocolVersion = 3;
                ldapCnct.SessionOptions.SecureSocketLayer = isTls;

                // 検索リクエストを生成
                var searchReq = new SearchRequest()
                {
                    DistinguishedName = searchBaseDN,
                    Filter = filter//,
                    //SizeLimit = 10000
                };

                // ページ単位で読み込むコントロールを生成
                var pageResReqControl = new PageResultRequestControl()
                {
                    PageSize = size
                };

                // 検索リクエストにコントロールを追加
                searchReq.Controls.Add(pageResReqControl);

                try
                {
                    // バインド
                    ldapCnct.Bind();

                    ldapConnection = ldapCnct;
                    searchRequest = searchReq;
                    pageResultRequestControl = pageResReqControl;
                }
                catch (Exception e)
                {
                    if (ldapCnct != null)
                    {
                        try
                        {
                            ldapCnct.Dispose();
                        }
                        catch (Exception e2)
                        {
                            System.Diagnostics.Debug.WriteLine(e2);
                        }
                    }
                    throw e;
                }
            }

            public void Dispose()
            {
                try
                {
                    ldapConnection.Dispose();
                }
                catch (Exception e)
                {
                    System.Diagnostics.Debug.WriteLine(e);
                }
                finally
                {
                    Current = null;
                    ldapConnection = null;
                    searchRequest = null;
                    pageResultRequestControl = null;
                    hasNext = false;
                    cookie = null;
                }

                Current = null;
                ldapConnection = null;
                searchRequest = null;
                pageResultRequestControl = null;
                hasNext = false;
                cookie = null;
            }

            public bool MoveNext()
            {
                if (!hasNext)
                {
                    Current = null;
                    return false;
                }

                var resultList = new List<SearchResultEntry>();

                // Cookie をセット
                pageResultRequestControl.Cookie = cookie;

                // 検索
                SearchResponse searchResponse = ldapConnection.SendRequest(searchRequest) as SearchResponse;

                // 検索結果をリストに追加
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    resultList.Add(entry);
                }

                // 現在のアイテムとしてリストをセット
                Current = resultList;

                // 新規 Cookie を得る前にクリア
                cookie = null;

                // 新規 Cookie 取得
                if (searchResponse.Controls != null)
                {
                    for (int i = 0; i < searchResponse.Controls.Length; i++)
                    {
                        if (searchResponse.Controls[i] is PageResultResponseControl control)
                        {
                            cookie = control.Cookie;
                        }
                    }
                }

                hasNext = !IsNullCookie(cookie);

                return true;
            }

            public void Reset()
            {
                Dispose();
                Initialize();
            }
        }

        #endregion
    }
}
