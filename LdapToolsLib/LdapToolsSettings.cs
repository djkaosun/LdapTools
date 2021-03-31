using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using System.Diagnostics;

namespace LdapToolsLib
{
    public static class LdapToolsSettings
    {
        /// <summary>
        /// コンフィグのファイル名。
        /// </summary>
        private const string CONFIG_FILE_NAME = "LdapTools_config.json";

        /// <summary>
        /// コンフィグの正しい値。
        /// </summary>
        private static Dictionary<string, List<string>> ValidValueItem = new Dictionary<string, List<string>> {
            { "AuthnTest", new List<string>(){ "server" ,"tls", "attr" , "basedn" } },
            { "PasswdChange", new List<string>{ "server" , "tls", "dn" } },
            { "Search", new List<string>{ "server" , "tls", "dn", "passwd", "basedn", "size", "continue" } }
        };

        private static Dictionary<string, Dictionary<string, string[]>> SettingDic;
        private static string ConfigPath;

        public static string GetValue(string tag, string valueName)
        {
            FirstTime();
            if (!SettingDic.ContainsKey(tag) || !SettingDic[tag].ContainsKey(valueName))
            {
                if (ValidValueItem.ContainsKey(tag) && ValidValueItem[tag].Contains(valueName)) return String.Empty;
                else return null;
            }
            if (SettingDic[tag][valueName].Length > 0) return SettingDic[tag][valueName][0];
            else return null;
        }

        public static string[] GetValues(string tag, string valueName)
        {
            FirstTime();
            if (!SettingDic.ContainsKey(tag) || !SettingDic[tag].ContainsKey(valueName))
            {
                if (ValidValueItem.ContainsKey(tag) && ValidValueItem[tag].Contains(valueName)) return new string[0];
                else return null;
            }
            return SettingDic[tag][valueName];
        }

        public static void SetValue(string tag, string valueName, string value)
        {
            FirstTime();
            if (ValidValueItem.ContainsKey(tag) && ValidValueItem[tag].Contains(valueName)) SettingDic[tag][valueName] = new string[] { value };
        }

        public static void SetValues(string tag, string valueName, string[] values)
        {
            FirstTime();
            if (ValidValueItem.ContainsKey(tag) && ValidValueItem[tag].Contains(valueName)) SettingDic[tag][valueName] = values;
        }

        public static void Save()
        {
            FirstTime();
            /*
            var configString = JsonSerializer.Serialize(SettingDic);

            // コンフィグ ファイルの書き込み
            var sw = new StreamWriter(ConfigPath);
            sw.Write(configString);
            sw.Close();
            */
            var sw = new StreamWriter(ConfigPath);
            var jsonSerializer = new JsonSerializer();
            jsonSerializer.Serialize(sw, SettingDic);
            sw.Close();
        }

        public static string ToJsonString()
        {
            FirstTime();
            /*
            return JsonSerializer.Serialize(SettingDic);
            */
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var jsonSerializer = new JsonSerializer();
            jsonSerializer.Serialize(sw, SettingDic);
            sw.Close();
            return sb.ToString();
        }

        private static void FirstTime()
        {
            // 既にディクショナリが生成済みなら以降の処理はしない
            if (SettingDic != null) return;

            ConfigPath = GetConfigPath();






            /*
            // デフォルト設定書き出し用。
            var defaultSetting = new Dictionary<string, Dictionary<string, string[]>>()
            {
                {
                    "AuthnTest", new Dictionary<string, string[]>() {
                        { "server", new string[] { "192.168.28.30" } },
                        { "tls", new string[] { "true" } },
                        { "attr", new string[] { "cn" } },
                        { "basedn", new string[] { "ou=Person,ou=Entries,o=exampleDir,c=jp" } },
                    }
                },
                {
                    "PasswdChange", new Dictionary<string, string[]>() {
                        { "server", new string[] { "192.168.28.30" } },
                        { "tls", new string[] { "true" } },
                        { "dn", new string[] { "cn=INPUT_YOUR_ID,ou=System-User,o=exampleDir,c=jp" } }
                    }
                }
            };


            var aaasw = new StreamWriter(ConfigPath);
            var aaajsonSerializer = new JsonSerializer();
            aaajsonSerializer.Serialize(aaasw, defaultSetting);
            aaasw.Close();
            //*/






            // コンフィグファイルがない場合は空っぽ
            if (!File.Exists(ConfigPath))
            {
                SettingDic = new Dictionary<string, Dictionary<string, string[]>>();
                return;
            }
            /*
            // コンフィグ ファイルの読み取り
            var sr = new StreamReader(ConfigPath);
            var configString = sr.ReadToEnd();
            sr.Close();

            // JSON からディクショナリーに変換
            SettingDic = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string[]>>>(configString);
            */
            // コンフィグ ファイルの読み取り
            var sr = new StreamReader(ConfigPath);
            var jr = new JsonTextReader(sr);

            // JSON からディクショナリーに変換
            var jsonSerializer = new JsonSerializer();
            SettingDic = jsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string[]>>>(jr);
            sr.Close();

            // ディクショナリーから不要分を削除
            ShapeSettingsDic();
        }

        private static string GetConfigPath()
        {
            // .exe が置かれたフォルダーのフルパスを取得
            var fullPath = Directory.GetParent(Process.GetCurrentProcess().MainModule.FileName);

            // コンフィグ ファイルのフルパス
            return fullPath + Path.DirectorySeparatorChar.ToString() + CONFIG_FILE_NAME;
        }

        private static void ShapeSettingsDic()
        {
            foreach (var key in SettingDic.Keys)
            {
                if (!ValidValueItem.ContainsKey(key)) SettingDic.Remove(key);
            }

            foreach (var item in SettingDic)
            {
                foreach (var value in item.Value.Keys)
                {
                    if (!ValidValueItem[item.Key].Contains(value)) SettingDic[item.Key].Remove(value);
                }
            }
        }
    }
}
