using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Security;

namespace Miiwoo.Web.Security
{
    /// <summary>
    /// Provides simple authentication by a master password.
    /// </summary>
    public interface IMasterPasswordAuth
    {
        /// <summary>
        /// Create a login for the user if the master password and username are valid.
        /// </summary>
        /// <param name="masterPassword">The master password to validate.</param>
        /// <param name="username">The username to validate.</param>
        /// <param name="persist">Whether the session should persist.</param>
        /// <returns>Whether the login succeeded.</returns>
        bool Login(string masterPassword, string username, bool persist = false);

        /// <summary>
        /// Create a login for the user if the master password is valid.
        /// </summary>
        /// <param name="masterPassword">The master password to validate.</param>
        /// <param name="persist">Whether the session should persist.</param>
        /// <returns>Whether the login succeeded.</returns>
        bool Login(string masterPassword, bool persist = false);
    }

    /// <summary>
    /// Provides simple authentication by a master password configured in the AppSettings section of Web.config.
    /// </summary>
    /// <remarks>
    /// Master password authentication requires Forms Authentication to be enabled with the following settings.
    ///  * CookieMode = UseCookies; force the use of cookies.
    ///  * RequireSSL = True; ensure that the cookies are not sent insecure.
    /// Also, the cookie is flagged with HttpOnly for browsers that support this feature, to prevent scripts from accessing the contents.
    /// To comply with the above requirements, you can use the below (incomplete) sample configuration elements for Web.config:
    /// <code>
    /// <authentication mode="Forms">
    ///    <forms loginUrl="~/Login" cookieless="UseCookies" requireSSL="true" />
    /// </authentication>
    /// </code>
    /// </remarks>
    public class WebConfigMasterPasswordAuth : IMasterPasswordAuth
    {
        /// <summary>
        /// Default username used when no specific username is provided.
        /// </summary>
        public const string DefaultUsername = "Master";

        /// <summary>
        /// Specifies the key used in AppSettings section of Web.config to set the default username.
        /// </summary>
        public const string DefaultUsernameConfigKey = "Authentication.Master.DefaultUsername";

        /// <summary>
        /// Specifies the key used in AppSettings section of Web.config to set the SHA-1 hash of the master password.
        /// </summary>
        public const string PasswordHashConfigKey = "Authentication.Master.Password.SHA1";

        /// <summary>
        /// Specifies the key used in AppSettings section of Web.config to set the salt prepended to the user provided password to generate the SHA-1 hash to compare with the master password hash.
        /// </summary>
        public const string PasswordSaltConfigKey = "Authentication.Master.Password.Salt";

        public bool Login(string masterPassword, string username, bool persist = false)
        {
            // Ensure that the Forms Authentication configuration is secure.
            if (FormsAuthentication.IsEnabled &&
                FormsAuthentication.CookiesSupported &&
                FormsAuthentication.CookieMode == HttpCookieMode.UseCookies &&
                FormsAuthentication.RequireSSL)
            {
                // Determine the username with following priority; custom username, configuration and code default.
                username = username ?? ConfigurationManager.AppSettings[DefaultUsernameConfigKey] ?? DefaultUsername;
                // Get the required configuration values and if they do not exist, throw an error.
                var passwordHash = ConfigurationManager.AppSettings[PasswordHashConfigKey];
                var passwordSalt = ConfigurationManager.AppSettings[PasswordSaltConfigKey];
                if (passwordHash == null) throw new InvalidOperationException("No master password configured.");
                if (passwordSalt == null) throw new InvalidOperationException("No salt for the master password configured.");
                // Get the password by adding the salt.
                var password = passwordSalt + masterPassword;
                // Compute a SHA-1 hash from the password.
                var computedByteHash = SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
                var computedHash = BitConverter.ToString(computedByteHash).Replace("-", string.Empty);
                // Compare the computed hash to the one stored in the configuration.
                if (computedHash.Equals(passwordHash.ToUpper()))
                {
                    // Password is valid, authenticate the user by setting a cookie.
                    FormsAuthentication.SetAuthCookie(username, persist);
                    return true;
                }
                // Password was incorrect.
                return false;
            }
            else throw new InvalidOperationException("Master password authentication requires Forms Authentication with cookies via HTTPS.");
        }

        public bool Login(string masterPassword, bool persist = false)
        {
            // Login with the default username, per configuration or else the class constant.
            return Login(masterPassword, null, persist);
        }
    }
}