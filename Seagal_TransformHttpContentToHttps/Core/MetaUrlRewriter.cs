using Seagal_TransformHttpContentToHttps.Model;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Seagal_TransformHttpContentToHttps.Core
{
    public class MetaUrlRewriter
    {
        private static Regex UrlHttpRegex = new Regex($"src=[\"'](.+?)[\"'].+?", RegexOptions.Compiled);

        public MetaUrlRewriter()
        {
        }

        public object RewriteUrl(object obj)
        {
            return urlrewriter(obj);
        }

        private object urlrewriter(object obj)
        {
            if (obj == null) return obj;
            if (obj is string)
            {
                obj = ReplaceUrls((string)obj);
                return obj;
            }
            if (obj is bool) return obj;
            if (obj is int) return obj;
            if (obj is double) return obj;
            if (obj is List<object>)
            {
                var modObjList = new List<object>();
                var a = (List<object>)obj;
                for (int i = 0; i < a.Count; i++)
                {
                    modObjList.Add(urlrewriter(a[i]));
                }
                return modObjList;
            }
            if (obj is Dictionary<object, object>)
            {
                var modObjDic = new Dictionary<object, object>();
                var a = (Dictionary<object, object>)obj;
                foreach (var entry in a)
                {
                    modObjDic.Add(entry.Key, urlrewriter(entry.Value));
                }
                return modObjDic;
            }
            return obj;
        }
    
        private string ReplaceUrls(string text)
        {
            if (!String.IsNullOrEmpty(text))
            {
                var replacedText = UrlHttpRegex.Replace(text, match => RewriteSource(match));
                if (!string.Equals(text, replacedText))
                {
                    text = replacedText;
                }
            }
            return text;
        }

        private string RewriteSource(Match match)
        {
            var url = match.Groups[0].Value.Replace("http:", "");
            return url;
        }
    }
}
