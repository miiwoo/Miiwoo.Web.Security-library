using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.QualityTools.Testing.Fakes;
using System.Collections.Specialized;
using System.Web.Security;
using System.Web;
using System.Web.Security.Fakes;

namespace Miiwoo.Web.Security.Tests
{
    [TestClass]
    public class WebConfigMasterPasswordAuthTests
    {
        public const string TestMasterUsername = "Username";
        public const string TestMasterPasswordOkay = "ABC";
        public const string TestMasterPasswordFail = "abc";
        public const string TestMasterPasswordSha1 = "c6d8d5bad9d62f25fbf5dd89d589b9d5b04b59e2"; // SHA-1: "123ABC".
        public const string TestMasterPasswordSalt = "123";

        /// <summary>
        /// Warmup the shims context to get accurate execution metrics for the unit tests.
        /// </summary>
        [ClassInitialize]
        public static void Warmup(TestContext context)
        {
            context.WriteLine("Warming up shims context.");
            WhileShimming(delegate { });
        }

        /// <summary>
        /// Helper method that prepares the shimming environment.
        /// </summary>
        /// <param name="action">The action to perform while shimming the HttpContext.</param>
        protected static void WhileShimming(Action<HttpContext> action)
        {
            using (ShimsContext.Create())
            {
                // Preparation.
                var httpContext = new HttpContext(new HttpRequest(null, "http://localhost", null), new HttpResponse(null));
                System.Web.Fakes.ShimHttpContext.CurrentGet = () => httpContext;
                System.Configuration.Fakes.ShimConfigurationManager.AppSettingsGet = () =>
                {
                    var settings = new NameValueCollection();
                    settings.Add(WebConfigMasterPasswordAuth.PasswordHashConfigKey, TestMasterPasswordSha1);
                    settings.Add(WebConfigMasterPasswordAuth.PasswordSaltConfigKey, TestMasterPasswordSalt);
                    return settings;
                };
                ShimFormsAuthentication.IsEnabledGet = () => true;
                ShimFormsAuthentication.CookiesSupportedGet = () => true;
                ShimFormsAuthentication.CookieModeGet = () => HttpCookieMode.UseCookies;
                ShimFormsAuthentication.RequireSSLGet = () => true;
                // Execute the action.
                action(httpContext);
            }
        }

        [TestMethod]
        public void CorrectMasterPasswordLogin()
        {
            WhileShimming(httpContext =>
            {
                var auth = new WebConfigMasterPasswordAuth();
                // Assert.
                Assert.IsTrue(auth.Login(TestMasterPasswordOkay), "Correct password invalid.");
                Assert.IsTrue(httpContext.Response.Cookies.Count == 1, "No cookie was set.");
            });
        }

        [TestMethod]
        public void IncorrectMasterPasswordLogin()
        {
            WhileShimming(httpContext =>
            {
                var auth = new WebConfigMasterPasswordAuth();
                // Assert.
                Assert.IsFalse(auth.Login(TestMasterPasswordFail), "Incorrect password valid.");
            });
        }

        [TestMethod]
        public void CorrectMasterPasswordWithUsernameLogin()
        {
            WhileShimming(httpContext =>
            {
                var auth = new WebConfigMasterPasswordAuth();
                // Assert.
                Assert.IsTrue(auth.Login(TestMasterPasswordOkay, TestMasterUsername), "Correct password invalid.");
                Assert.IsTrue(httpContext.Response.Cookies.Count == 1, "No cookie was set.");
            });
        }

        [TestMethod]
        public void IncorrectMasterPasswordWithUsernameLogin()
        {
            WhileShimming(httpContext =>
            {
                var auth = new WebConfigMasterPasswordAuth();
                // Assert.
                Assert.IsFalse(auth.Login(TestMasterPasswordFail, TestMasterUsername), "Incorrect password valid.");
            });
        }
    }
}