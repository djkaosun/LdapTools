using System;
using System.Net;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;

namespace LdapToolsLib
{
    public static class LdapAuthnTester
    {
        /// <summary>
        /// LDAP のポート番号
        /// </summary>
        public const int LDAP_PORT = 389;

        /// <summary>
        /// LDAPS のポート番号
        /// </summary>
        public const int LDAPS_PORT = 636;
        //public const int LDAPS_DEFAULT_PORT = 3296;

        public const int LDAP_VERSION = 3;

        /// <summary>
        /// LDAP で認証する。
        /// </summary>
        /// <param name="userId">ユーザー名</param>
        /// <param name="userPassword">ユーザーのパスワード</param>
        /// <param name="userAttr">DN に指定されている属性 (多くの場合、CN)</param>
        /// <param name="parentDN">ベース DN</param>
        /// <param name="ldapServer">LDAP サーバーのホスト名または IP アドレス</param>
        /// <param name="isTls">LDAPS にする場合 true。LDAP のままにする場合 false。</param>
        /// <returns>認証成功でそのユーザーの <see cref="LdapEntry" />、認証失敗は null。</returns>
        /// <exception cref="LdapException">LDAP 例外</exception>
        public static SearchResultEntry Authn(string userId, string userPassword, string userAttr, string parentDN, string ldapServer, bool isTls)
        {
            // 認証情報が空の場合は即認証失敗
            if (userId.Length < 1 || userPassword.Length < 1)
            {
                return null;
            }

            ldapServer = ServerPortSpecify(ldapServer, isTls);
            var userDN = userAttr + "=" + LdapEscape(userId) + "," + parentDN;

            LdapConnection ldapConnection = new LdapConnection(ldapServer)
            {
                Credential = new NetworkCredential(userDN, userPassword),
                AuthType = AuthType.Basic,
                Timeout = new TimeSpan(0, 0, 10)
            };
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.SessionOptions.SecureSocketLayer = isTls;

            SearchResultEntry searchResultEntry = null;
            try
            {

                // 認証したいユーザーでバインドしてみる
                ldapConnection.Bind();

                // バインドが通ったらユーザー情報を得る
                SearchRequest searchRequest = new SearchRequest()
                {
                    DistinguishedName = userDN,
                    Filter = "(objectClass=*)",
                    Scope = System.DirectoryServices.Protocols.SearchScope.Base
                };
                SearchResponse searchResponse = ldapConnection.SendRequest(searchRequest) as SearchResponse;

                if (searchResponse.Entries.Count == 1)
                {
                    foreach (SearchResultEntry item in searchResponse.Entries)
                    {
                        searchResultEntry = item;
                        break;
                    }
                }

                if (searchResultEntry == null)
                {
                    // 念のため。この例外がスローされることはない。
                    throw new ArgumentOutOfRangeException(searchResponse.Entries.Count.ToString());
                }
            }
            catch (LdapException e)
            {
                if (e.ErrorCode != 49) // エラー コード 49 は「認証失敗」
                {
                    throw e;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine(e.Message);
                    System.Diagnostics.Debug.WriteLine(e.ServerErrorMessage);
                }
            }
            finally
            {
                if (ldapConnection != null)
                {
                    try
                    {
                        ldapConnection.Dispose();
                    }
                    catch (Exception e)
                    {
                        System.Diagnostics.Debug.WriteLine(e);
                    }
                }
            }

            return searchResultEntry;
        }

        /// <summary>
        /// ホスト名とポート番号を分割します。
        /// </summary>
        /// <param name="ldapServer">LDAP サーバー指定。</param>
        /// <param name="isTls">TLS を使用するか否か。</param>
        /// <param name="ldapServerHostname">切り分けたホスト名。</param>
        /// <param name="ldapServerPort">切り分けたポート番号。指定がない場合は TLS の使用有無に従います。</param>
        private static void GetHostnameAndPort(string ldapServer, bool isTls, out string ldapServerHostname, out int ldapServerPort)
        {
            if (Regex.IsMatch(ldapServer, ":[1-9][0-9]*$"))
            {
                // ポート指定あり
                var match = Regex.Match(ldapServer, "^([^:]*):([1-9][0-9]*$)");
                ldapServerHostname = match.Groups[1].Captures[0].Value;
                ldapServerPort = Int32.Parse(match.Groups[2].Captures[0].Value);
            }
            else
            {
                // ポート指定なし
                ldapServerHostname = ldapServer;
                ldapServerPort = (isTls) ? LDAPS_PORT : LDAP_PORT;
            }
        }

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
        /// ユーザーの DN を組み立てます。userAttr=userId,parentDN となります。
        /// </summary>
        /// <param name="userAttr">ユーザーの属性名</param>
        /// <param name="userId">ユーザー名</param>
        /// <param name="parentDN">ベース DN</param>
        /// <returns></returns>
        public static string GetUserDN(string userAttr, string userId, string parentDN)
        {
            if (userAttr == null) userAttr = String.Empty;
            if (userId == null) userId = String.Empty;
            if (parentDN == null) parentDN = String.Empty;

            return userAttr + "=" + LdapEscape(userId) + "," + parentDN;
        }

        /// <summary>
        /// 正常に処理できるよう、特殊文字をエスケープする。(RFC2253)
        /// </summary>
        /// <param name="ldapValue">エスケープ処理前の文字列</param>
        /// <returns>エスケープ処理済みの文字列</returns>
        static string LdapEscape(string ldapValue)
        {
            if (NeedEscape(ldapValue))
            {
                return "\"" + ldapValue.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
            }
            else
            {
                return ldapValue;
            }
        }

        private static bool NeedEscape(string ldapValue)
        {
            if (ldapValue.StartsWith(" ")) return true;
            if (ldapValue.StartsWith("#")) return true;
            if (ldapValue.EndsWith(" ")) return true;
            if (ldapValue.Contains(",")) return true;
            if (ldapValue.Contains("+")) return true;
            if (ldapValue.Contains("\"")) return true;
            if (ldapValue.Contains("\\")) return true;
            if (ldapValue.Contains("<")) return true;
            if (ldapValue.Contains(">")) return true;
            if (ldapValue.Contains(";")) return true;

            return false;
        }
    }
}
