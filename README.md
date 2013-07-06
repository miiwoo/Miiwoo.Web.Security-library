Miiwoo.Web.Security Library
===========================

This is an open-source .NET library that provides ASP.NET security components.

 * Targets .NET Framework 4.
 * Visual Studio 2012 Solution.
 * Contains MS-Test unit tests in a separate project.
 * Provides interfaces for dependency injection.
 * Licenced open-source under the [Apache License, Version 2.0](http://opensource.org/licenses/Apache-2.0).

Components
----------
Currently the library is tiny with just a single component, but is expected to expand over time.

### WebConfigMasterPasswordAuth
*Provides simple Forms Authentication with a master password set in the AppSettings section of Web.config.*

This is useful to be able to always get access to an administration section of a website even when external authentication via database or OAuth are not working.

Refer to the XML documentation on the class for usage.

Contributions
-------------

The initial library is written by Bart Verkoeijen and is the maintainer of this repository. Feel free to fork and send pull requests to extend and improve the library, thanks!

Bart