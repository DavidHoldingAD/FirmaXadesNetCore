using System.Resources;

namespace System.Security;

internal static class SecurityResources
{
	private static volatile ResourceManager _resMgr;

	internal static string GetResourceString(string key)
	{
		if (_resMgr == null)
		{
			_resMgr = new ResourceManager("system.security", typeof(SecurityResources).Assembly);
		}

		return _resMgr.GetString(key, null);
	}
}
