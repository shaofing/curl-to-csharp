using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace CurlToCSharp.Models
{
    public class CurlOptionsEqualityComparer : IEqualityComparer<CurlOptions>
    {
        public bool Equals(CurlOptions x, CurlOptions y)
        {
            return getPropertiesString(x).Equals(getPropertiesString(y));
        }

        public int GetHashCode([DisallowNull] CurlOptions obj)
        {
            throw new NotImplementedException();
        }

        private string getPropertiesString(object op)
        {
            var ps = op.GetType().GetProperties().OrderBy(p => p.Name).ToArray();
            var list = new List<string>(ps.Length);
            foreach (var item in ps)
            {
                if (!item.CanRead)
                    continue;
                var pValue = item.GetValue(op);
                if (pValue == null)
                    continue;
                string val;
                if (item.PropertyType.IsAssignableFrom(typeof(IEnumerable)))
                {
                    var collectionValues = pValue as IEnumerable;
                    val = getCollectionValue(collectionValues);
                }
                else if (IsFundamental(item.PropertyType))
                    val = pValue as string;
                else
                    val = getPropertiesString(pValue);

                list.Add($"{item.Name}:{val}");
            }
            var sAll = string.Join(",", list);
            return $"{{{sAll}}}";
        }

        private string getCollectionValue(IEnumerable collectionValues)
        {
            List<string> list = new List<string>();
            foreach (var itemValue in collectionValues)
            {
                if (IsFundamental(itemValue.GetType()))
                {
                    list.Add(itemValue?.ToString() ?? string.Empty);
                }
            }
            var listStr = string.Join(",", list);
            return $"[{listStr}]";
        }

        private bool IsFundamental(Type type)
        {
            return type.IsPrimitive || type.IsEnum || type.Equals(typeof(string)) || type.Equals(typeof(DateTime)) || type.Equals(typeof(Uri));
        }

        public string GetCurlOptionsMD5(CurlOptions x)
        {
            var md5 = System.Security.Cryptography.MD5.Create();
            var str = getPropertiesString(x);
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            byte[] md5buffer = md5.ComputeHash(buffer);
            StringBuilder sb = new StringBuilder();
            // 通过使用循环，将字节类型的数组转换为字符串，此字符串是常规字符格式化所得
            foreach (byte b in md5buffer)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

    }
}
