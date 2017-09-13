using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using Rosenbjerg.SessionManager.Rosenbjerg.SessionManager;

namespace Rosenbjerg.SessionManager
{
    namespace Rosenbjerg.SessionManager
    {

        /// <summary>
        ///     The settings available for SameSite
        /// </summary>
        public enum SameSiteSetting
        {
            None,
            Lax,
            Strict
        }
    }
    /// <summary>
    ///     Minimal session manager for cookie-based authentication.
    /// </summary>
    /// <typeparam name="TSess">The class of the session data object. There are no requirements for this class</typeparam>
    public class SessionManager<TSess>
    {
        private readonly string _cookie;
        private readonly TimeSpan _sessionLength;
        private readonly ConcurrentDictionary<string, Session> _sessions = new ConcurrentDictionary<string, Session>();

        /// <summary>
        ///     The name of the session token cookie. Defaults to 'token'
        /// </summary>
        public string TokenName = "token";

        /// <summary>
        ///     Constructor for SessionManager.
        ///     Remeber to set 'secure' to false unless the cookie is sent over a secured (https) connection.
        /// </summary>
        /// <param name="sessionLength">The default length of a session</param>
        /// <param name="domain">The domain specified for the cookie</param>
        /// <param name="path">The path specified for the cookie</param>
        /// <param name="httpOnly">Whether the cookie should be unavailable to javascript</param>
        /// <param name="secure">Whether the session cookie only should be sent over secure (https) connections.</param>
        /// <param name="sameSite">The same-site policy specified for the cookie</param>
        public SessionManager(TimeSpan sessionLength, string domain = "", string path = "", bool httpOnly = true,
            bool secure = true, SameSiteSetting sameSite = SameSiteSetting.Strict)
        {
            _sessionLength = sessionLength;
            var d = domain == "" ? "" : $" Domain={domain};";
            var p = path == "" ? "" : $" Path={path};";
            var h = httpOnly ? " HttpOnly;" : "";
            var s = secure ? " Secure;" : "";
            var ss = sameSite == SameSiteSetting.None ? "" : $" SameSite={sameSite};";
            _cookie = $"{d}{p}{h}{s}{ss}";
            ExpiredCookie = $"{TokenName}=;{_cookie} Expires=Thu, 01 Jan 1970 00:00:00 GMT";
            Maintain();
        }

        // Simple maintainer loop
        private async void Maintain()
        {
            var delay = TimeSpan.FromMinutes(_sessionLength.TotalMinutes * 0.26);
            while (true)
            {
                await Task.Delay(delay);
                var now = DateTime.UtcNow;
                var expired = _sessions.Where(kvp => kvp.Value.Expires < now).ToList();
                foreach (var kvp in expired)
                    _sessions.TryRemove(kvp.Key, out var s);
            }
        }

        /// <summary>
        ///     Returns an expired cookie with the token name. Send with'Set-Cookie' header to make browsers delete the cookie
        /// </summary>
        public string ExpiredCookie { get; }

        /// <summary>
        ///     Determines if a token is a valid authentication token. Returns session data object through out paramenter if token is valid.
        /// </summary>
        /// <param name="token">Token to authenticate</param>
        /// <param name="data">Session data if token is valid</param>
        /// <returns>True if token is valid</returns>
        public bool TryAuthenticateToken(string token, out TSess data)
        {
            if (!_sessions.TryGetValue(token, out var s) || s.Expires <= DateTime.UtcNow)
            {
                data = default(TSess);
                return false;
            }
            data = s.SessionData;
            return true;
        }


        /// <summary>
        ///     Creates a new session and returns the cookie to send the client with 'Set-Cookie' header.
        /// </summary>
        /// <param name="sessionData">Object that represents the session data</param>
        /// <returns>The string to send with 'Set-Cookie' header</returns>
        public string OpenSession(TSess sessionData)
        {
            var id = Guid.NewGuid().ToString("N").Substring(8);
            var exp = DateTime.UtcNow.Add(_sessionLength);
            _sessions.TryAdd(id, new Session(sessionData, exp));
            return $"{TokenName}={id};{_cookie} Expires={exp:R}";
        }

        /// <summary>
        ///     Renews the expiration of an active session and returns the cookie to send the client with 'Set-Cookie' header. Returns
        ///     empty string if token invalid
        /// </summary>
        /// <param name="token">The authentication token to renew the expiration of</param>
        /// <returns>The string to send with 'Set-Cookie' header</returns>
        public string RenewSession(string token)
        {
            if (!_sessions.TryGetValue(token, out var sess))
                return "";
            sess.Expires = DateTime.UtcNow.Add(_sessionLength);
            return $"{TokenName}={token};{_cookie} Expires={sess.Expires:R}";
        }

        /// <summary>
        ///     Closes an active session so the token becomes invalid. Returns true if an active session was found
        /// </summary>
        /// <param name="token">The authentication token to invalidate</param>
        /// <param name="cookie">The cookie to return, to invalidate the existing cookie</param>
        /// <returns>Whether the session was found and closed</returns>
        public bool CloseSession(string token, out string cookie)
        {
            cookie = ExpiredCookie;
            return _sessions.TryRemove(token, out var s);
        }

        private class Session
        {
            internal Session(TSess tsess, DateTime exp)
            {
                SessionData = tsess;
                Expires = exp;
            }

            public TSess SessionData { get; }
            public DateTime Expires { get; set; }
        }
    }
}