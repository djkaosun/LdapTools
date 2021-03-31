using System;
using System.Globalization;
using System.Windows.Controls;
using System.Linq;

namespace LdapToolsWpf
{
    class PageSizeValidationRule : ValidationRule
    {
        public const int MAX_PAGE_SIZE = 1000;

        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            if (value is string str)
            {
                int parsedValue;
                if (Int32.TryParse(str, out parsedValue))
                {
                    if (0 < parsedValue && parsedValue <= MAX_PAGE_SIZE) return new ValidationResult(true, null);
                    else return new ValidationResult(false, "Value is out of range.");
                }
                else if (String.IsNullOrEmpty(str))
                {
                    return new ValidationResult(false, "Value is empty.");
                }
                else
                {
                    return new ValidationResult(false, "Invalid character.");
                }
            }
            return new ValidationResult(false, "Value is not string.");
        }
    }
}
