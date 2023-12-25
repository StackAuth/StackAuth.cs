using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Linq;
using System.IO.Compression;
using System.Drawing;
using Newtonsoft.Json;

using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace YourAppName
{

    #region Private JWT Function
    public interface IAuthContainerModel
    {
        #region Members
        string SecretKey { get; set; }
        string SecurityAlgorithm { get; set; }
        int ExpireMinutes { get; set; }

        Claim[] Claims { get; set; }
        #endregion
    }
    public class JWTContainerModel : IAuthContainerModel
    {
        #region Public Methods
        public int ExpireMinutes { get; set; } = 1440; // 1 days.
        public string SecretKey { get; set; } = ""; //leave empty
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;

        public Claim[] Claims { get; set; }
        #endregion
    }

    public interface IAuthService
    {
        string SecretKey { get; set; }
        bool IsTokenValid(string token);
        string GenerateToken(IAuthContainerModel model);
        IEnumerable<Claim> GetTokenClaims(string token);
    }

    public class JWTService : IAuthService
    {
        #region Members
        /// <summary>
        /// The secret key we use to encrypt out token with.
        /// </summary>
        public string SecretKey { get; set; }
        #endregion

        #region Constructor
        public JWTService(string secretKey)
        {
            SecretKey = secretKey;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Validates whether a given token is valid or not, and returns true in case the token is valid otherwise it will return false;
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Generates token by given model.
        /// Validates whether the given model is valid, then gets the symmetric key.
        /// Encrypt the token and returns it.
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Generated token.</returns>
        public string GenerateToken(IAuthContainerModel model)
        {
            if (model == null || model.Claims == null || model.Claims.Length == 0)
                throw new ArgumentException("Arguments to create token are not valid.");

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(model.Claims),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToInt32(model.ExpireMinutes)),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), model.SecurityAlgorithm)
            };

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            string token = jwtSecurityTokenHandler.WriteToken(securityToken);
            return token;
        }

        /// <summary>
        /// Receives the claims of token by given token as string.
        /// </summary>
        /// <remarks>
        /// Pay attention, one the token is FAKE the method will throw an exception.
        /// </remarks>
        /// <param name="token"></param>
        /// <returns>IEnumerable of claims for the given token.</returns>
        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                return tokenValid.Claims;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region Private Methods
        private SecurityKey GetSymmetricSecurityKey()
        {
            byte[] symmetricKey = Convert.FromBase64String(SecretKey);
            return new SymmetricSecurityKey(symmetricKey);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }
        #endregion
    }

    #endregion

    internal class App
    {
        public static string GrabVariable(string name)
        {
            try
            {
                if (User.ID != null || User.HWID != null || User.IP != null || !Constants.Breached)
                {
                    return Variables[name];
                }
                else
                {
                    Constants.Breached = true;
                    return "User is not logged in, possible breach detected!";
                }
            }
            catch
            {
                return $"{name} don't exist!";
            }
        }
        public static Dictionary<string, string> Variables = new Dictionary<string, string>();
    }

    internal class Constants
    {
        public static bool hwidcheckvalid = false;

        public static string Token { get; set; }

        public static string Date { get; set; }

        public static string APIENCRYPTKEY { get; set; }

        public static string APIENCRYPTSALT { get; set; }

        public static bool Breached = false;

        public static bool Started = false;

        public static string IV = null;

        public static string Key = null;

        public static string ApiUrl;

        public static string Server01 = "https://stackworkshop.com/auth/Auth/";

        public static string Server02 = "https://stackauth.com/auth/";

        public static string[] dllhash = { "Newtonsoft.Json.dll:081d9558bbb7adce142da153b2d5577a", "System.IO.Compression.ZipFile.dll:dcda916372128f13ada8b07026c1b3e7", "System.IdentityModel.Tokens.Jwt.dll:289562fc7249580de4cf313062f4b3dc" };
        public static string[] StoreHashToIntegrity = { "Newtonsoft.Json.dll", "System.IO.Compression.ZipFile.dll", "System.IdentityModel.Tokens.Jwt.dll" };

        //System.IdentityModel.Tokens.Jwt
        public static bool Initialized = false;

        public static Random random = new Random();

        public static string RandomString(int length)
        {
            return new string(Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string HWID()
        {
            return WindowsIdentity.GetCurrent().User.Value;
        }
    }

    internal class User
    {
        public static string ID { get; set; }

        public static string Username { get; set; }

        public static string Password { get; set; }

        public static string Email { get; set; }

        public static string HWID { get; set; }

        public static string IP { get; set; }

        public static string UserVariable { get; set; }

        public static string Rank { get; set; }

        public static string Expiry { get; set; }

        public static string LastLogin { get; set; }

        public static string RegisterDate { get; set; }

        public static string ProfilePicture { get; set; }
        public static string Ban_Reason { get; set; }
    }
    internal class ApplicationSettings
    {
        public static bool Status { get; set; }

        public static bool DeveloperMode { get; set; }

        public static string Hash { get; set; }

        public static string Version { get; set; }

        public static string Update_Link { get; set; }

        public static string Updater_Check { get; set; }

        public static bool Freemode { get; set; }

        public static bool Login { get; set; }

        public static string Name { get; set; }

        public static bool Register { get; set; }

        public static string TotalUsers { get; set; }

        public static bool debug { get; set; }
    }
    public class StackWebClient : WebClient
    {
        Uri _responseUri;
        string _GetHost;

        public Uri ResponseUri
        {
            get { return _responseUri; }
        }

        public string GetHost
        {
            get { return _GetHost; }
        }

        protected override WebRequest GetWebRequest(Uri address)
        {
            var request = (HttpWebRequest)base.GetWebRequest(address);
            _GetHost = request.Host;
            request.UserAgent = "StackAuth";
            _responseUri = request.RequestUri;
            request.AllowAutoRedirect = false;
            return request;
        }
    }
    class SecureFile
    {
        public int[] Secure_File { get; set; }
        public int Key { get; set; }

        public int[] Decrypt()
        {
            int[] Decrypted = new int[Secure_File.Length];
            for (int i = 0; i < Secure_File.Length; i++)
            {
                Decrypted[i] = Secure_File[i] ^ Key;
            }
            Array.Reverse(Decrypted);
            return Decrypted;
        }
    }
    internal class OnProgramStart
    {
        public static string AID = null;

        public static string JWTKey = null;

        public static string Secret = null;

        public static string Version = null;

        public static string Name = null;

        public static string Salt = null;

        public static bool DebugCheck = false;

        public static bool ProcessCheck = false;

        public static int server = 0;

        #region Private Methods
        private static JWTContainerModel StartJWT()
        {    
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                new Claim("token", Encryption.EncryptService(Constants.Token)),
                new Claim("timestamp", Encryption.EncryptService(DateTime.Now.ToString())),
                new Claim("aid", Encryption.APIService(OnProgramStart.AID)),
                new Claim("hwid", Encryption.APIService(Constants.HWID())),
                new Claim("version", Encryption.APIService(Version))
                }
            };
        }
   
        #endregion

        public static void Initialize(string name, string aid, string secret, string version, string ActivateKey, string GetJWTKey, bool debugcheck, bool processcheck)
        {
            Constants.ApiUrl = Constants.ApiUrl ?? Constants.Server01;
            Security.AntiHttpDebugger();

            if (debugcheck)
            {
                if (Security.AntiSandboxie() || Security.AntiDebugger())
                {
                    Process.GetCurrentProcess().Kill();
                }
            }

            foreach (string dll in Constants.dllhash)
            {
                string dllpath = dll.Split(':')[0];
                string hash = dll.Split(':')[1];
                Security.HashCheck(dllpath, hash);
            }

            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(aid) || string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(version) || name.Contains("APPNAME"))
            {
                MessageBox.Show("Failed to initialize your application correctly in Program.cs!", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                System.Diagnostics.Process.Start("http://docs.stackworkshop.com");
                Process.GetCurrentProcess().Kill();
            }
            AID = aid;
            JWTKey = GetJWTKey;
            Secret = secret;
            Version = version;
            Name = name;
            DebugCheck = debugcheck;
            ProcessCheck = processcheck;
            string jwttoken = string.Empty;
            string response = string.Empty;

            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    wc.Proxy = null;
                    Security.Start();
                    IAuthContainerModel model = StartJWT();

                    model.SecretKey = JWTKey;
                    IAuthService authService = new JWTService(model.SecretKey);
                    jwttoken = authService.GenerateToken(model);

                    if (!authService.IsTokenValid(jwttoken))
                        throw new UnauthorizedAccessException();

                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.APIService(jwttoken),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(Secret),
                        ["type"] = Encryption.APIService("start")

                    }))));

                    IAuthService authService1 = new JWTService(model.SecretKey);

                    if (!authService1.IsTokenValid(response))
                       throw new UnauthorizedAccessException();

                    List<Claim> claims = authService1.GetTokenClaims(response).ToList();

                    if (claims.FirstOrDefault(e => e.Type.Equals("key")).Value != ActivateKey)
                    {
                        StackAPI.Ban("Activation Key Incorrect");
                        Process.GetCurrentProcess().Kill();
                    }
             
                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    if (wc.GetHost.ToString() != "stackworkshop.com")
                    {
                        StackAPI.Ban(response[14] + " Domain hijack detected");
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    if (Security.MaliciousCheck(claims.FirstOrDefault(e => e.Type.Equals("timestamp")).Value))
                    {
                        StackAPI.Ban(response[14] + " Domain hijack detected");
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Constants.Breached)
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (claims.FirstOrDefault(e => e.Type.Equals("token")).Value != Constants.Token)
                    {
                        MessageBox.Show("Security error has been triggered!", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Process.GetCurrentProcess().Kill();
                    }
                    switch (claims.FirstOrDefault(e => e.Type.Equals("verify")).Value)
                    {
                        case "success":
                            Constants.Initialized = true;
                            if (claims.FirstOrDefault(e => e.Type.Equals("status")).Value == "Enabled") 
                                ApplicationSettings.Status = true;
                            if (claims.FirstOrDefault(e => e.Type.Equals("dev")).Value == "Enabled")
                                ApplicationSettings.DeveloperMode = true;
                            ApplicationSettings.Hash = claims.FirstOrDefault(e => e.Type.Equals("hash")).Value;
                            ApplicationSettings.Version = claims.FirstOrDefault(e => e.Type.Equals("version")).Value;
                            ApplicationSettings.Update_Link = claims.FirstOrDefault(e => e.Type.Equals("updateurl")).Value;
                            if (claims.FirstOrDefault(e => e.Type.Equals("freemode")).Value == "Enabled")
                                ApplicationSettings.Freemode = true;
                            if (claims.FirstOrDefault(e => e.Type.Equals("Login")).Value == "Enabled")
                                ApplicationSettings.Login = true;
                            ApplicationSettings.Name = claims.FirstOrDefault(e => e.Type.Equals("App")).Value;
                            if (claims.FirstOrDefault(e => e.Type.Equals("Register")).Value == "Enabled")
                                ApplicationSettings.Register = true;
                            ApplicationSettings.TotalUsers = claims.FirstOrDefault(e => e.Type.Equals("Total Users")).Value;
                            ApplicationSettings.Updater_Check = claims.FirstOrDefault(e => e.Type.Equals("CustomUpdater")).Value;
                            if (ApplicationSettings.DeveloperMode)
                            {
                                MessageBox.Show("Application is in Developer Mode, bypassing integrity and update check!", Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                File.Create(Environment.CurrentDirectory + "/integrity.log").Close();
                                string hash = Security.Integrity(Process.GetCurrentProcess().MainModule.FileName);
                                File.WriteAllText(Environment.CurrentDirectory + "/integrity.log", OnProgramStart.Name + ": " + hash);
                                foreach (string dll in Constants.StoreHashToIntegrity)
                                {
                                    string dllpath = dll.Split(':')[0];
                                    string dllhash = Security.Integrity(dllpath);
                                    File.AppendAllText(Environment.CurrentDirectory + "/integrity.log", Environment.NewLine + dllpath + ": " + dllhash);

                                }
                                MessageBox.Show("Your applications hash has been saved to integrity.txt, please refer to this when your application is ready for release!", Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }
                            else
                            {
                                if (claims.FirstOrDefault(e => e.Type.Equals("Integrity")).Value == "Enabled")
                                {
                                    if (ApplicationSettings.Hash != Security.Integrity(Process.GetCurrentProcess().MainModule.FileName))
                                    {
                                        MessageBox.Show($"File has been tampered with, couldn't verify integrity!", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                        Process.GetCurrentProcess().Kill();
                                        Process.GetProcessesByName("cmd.exe");
                                    }
                                }
                                if (ApplicationSettings.Version != Version)
                                {
                                    if (ApplicationSettings.Updater_Check == "Enabled")
                                    {
                                        if (!Directory.Exists("updater"))
                                        {
                                            Directory.CreateDirectory("updater");
                                        }

                                        if (!File.Exists("updater/StackUpdate.exe"))
                                        {
                                            WebClient client = new WebClient();
                                            client.DownloadFile("https://stackworkshop.com/auth/StackUpdate/StackUpdate.zip", "updater/StackUpdate.zip");
                                            ZipFile.ExtractToDirectory("updater/StackUpdate.zip", "updater/"); //Use Nuget to Install System.IO.Compression.ZipFile
                                        }

                                        if (File.Exists("updater/update.json"))
                                        {
                                            File.Delete("updater/update.json");
                                        }

                                        string json = "{'StackAuth':{'update': [{'id': 'Stack_01_9308','username': '" + User.Username + "','version': '" + version + "','URL':'" + ApplicationSettings.Update_Link + "'}],'Info': [{'AppName':'" + OnProgramStart.Name + "'}]}}";
                                        JObject jsonobject = JObject.Parse(json);

                                        File.Create("updater/update.json").Dispose();
                                        File.WriteAllText("updater/update.json", jsonobject.ToString());
                                        Process.Start(AppDomain.CurrentDomain.BaseDirectory + "/updater/StackUpdate.exe");
                                        Process.GetCurrentProcess().Kill();
                                    }
                                    else
                                    {
                                        MessageBox.Show($"Update {ApplicationSettings.Version} available, redirecting to update!", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                        Process.Start(ApplicationSettings.Update_Link);
                                        Process.GetCurrentProcess().Kill();
                                    }

                                }

                            }
                            if (ApplicationSettings.Status == false)
                            {
                                MessageBox.Show("Looks like this application is disabled, please try again later!", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                Process.GetCurrentProcess().Kill();
                            }
                            break;
                        case "binderror":
                            MessageBox.Show(Encryption.Decode("RmFpbGVkIHRvIGJpbmQgdG8gc2VydmVyLCBjaGVjayB5b3VyIEFJRCAmIFNlY3JldCBpbiB5b3VyIGNvZGUh"), Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "banned":
                            MessageBox.Show("This application has been banned for violating the TOS" + Environment.NewLine + "Contact us at support@stackworkshop.com", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Process.GetCurrentProcess().Kill();
                            return;
                    }
                    Security.End();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    switch (Constants.ApiUrl)
                    {
                        case "https://stackworkshop.com/auth/Auth/":
                            Constants.ApiUrl = Constants.Server02;
                            break;
                        case "https://stackauth.com/auth/":
                            Constants.ApiUrl = Constants.Server01;
                            break;
                    }
                    server++;
                    if (server == 2)
                    {
                        MessageBox.Show("Server 1 and Server 2 are down! :(", Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        MessageBox.Show(ex.Message, Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Process.GetCurrentProcess().Kill();
                    }
                    Initialize(name, aid, secret, version, ActivateKey,JWTKey, debugcheck, processcheck);
                }
            }
        }
    }

    internal class StackAPI
    {

        public static void ForgotPassword(string username, string newpassword)
        {
            if (newpassword == null || string.IsNullOrWhiteSpace(newpassword))
            {
                MessageBox.Show("Please put desire password in the password field!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            if (username == null || string.IsNullOrWhiteSpace(username))
            {
                MessageBox.Show("Username cannot be empty!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }

            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {

                try
                {
                    wc.Proxy = null;
                    Security.Start();
                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["username"] = Encryption.APIService(username),
                        ["newpass"] = Encryption.APIService(newpassword),
                        ["hwid"] = Encryption.APIService(Constants.HWID()),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("forgotpass")

                    }))).Split("|".ToCharArray()));

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    switch (response[2])
                    {
                        case "success":
                            MessageBox.Show("Successfully updated password!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                            Security.End();
                            return;
                        case "incorrect":
                            MessageBox.Show("No account matches this hwid!" + Environment.NewLine + "Please make a ticket for more help on our discord", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "expired":
                            MessageBox.Show("Please renew your Subscription to use this feature!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "failed":
                            MessageBox.Show("Failed to update password!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
            }

        }
        public static void UpdateInformation(string email, string password)
        {
            if (email == null)
            {
                email = User.Email;
            }

            if (password == null)
            {
                password = User.Password;
            }

            if (string.IsNullOrWhiteSpace(email))
            {
                MessageBox.Show("Invalid Picture information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }


            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {

                try
                {
                    wc.Proxy = null;
                    Security.Start();
                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["username"] = Encryption.APIService(User.Username),
                        ["password"] = Encryption.APIService(User.Password),
                        ["newemail"] = Encryption.APIService(email),
                        ["newpass"] = Encryption.APIService(password),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("updateinfo")

                    }))).Split("|".ToCharArray()));

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    switch (response[0])
                    {
                        case "success":
                            User.Email = email;
                            User.Password = password;
                            MessageBox.Show("Successfully updated information!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                            Security.End();
                            return;
                        case "incorrect":
                            MessageBox.Show("Failed to login!" + Environment.NewLine + "Unable to update info", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "expired":
                            MessageBox.Show("Please renew your Subscription to use this feature!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "failed":
                            MessageBox.Show("Failed to update information!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
            }

        }
        private static JWTContainerModel JWTLog(string reason)
        {
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                new Claim("token", Encryption.EncryptService(Constants.Token)),
                new Claim("timestamp", Encryption.EncryptService(DateTime.Now.ToString())),
                new Claim("aid", Encryption.APIService(OnProgramStart.AID)),
                new Claim("hwid", Encryption.APIService(Constants.HWID())),
                new Claim("version", Encryption.EncryptService(OnProgramStart.Version)),
                new Claim("username", Encryption.APIService(User.Username)),
                new Claim("data", Encryption.APIService(reason)),
                new Claim("pcuser", Encryption.APIService(Environment.UserName)),
                new Claim("session_id", Encryption.APIService(Constants.IV)),
                new Claim("session_key", Encryption.APIService(Constants.Key))
                }
            };
        }

        public static void Log(string reason)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(reason))
            {
                MessageBox.Show("Missing log information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            string response = String.Empty;
            string jwttoken = String.Empty;
            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    IAuthContainerModel model = JWTLog(reason);
                    model.SecretKey = OnProgramStart.JWTKey;

                    IAuthService authService = new JWTService(model.SecretKey);
                    jwttoken = authService.GenerateToken(model);

                    if (!authService.IsTokenValid(jwttoken))
                        throw new UnauthorizedAccessException();

                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.APIService(jwttoken),
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("log")

                    }))));

                    model.SecretKey = OnProgramStart.JWTKey;
                    IAuthService authService1 = new JWTService(model.SecretKey);

                    if (!authService1.IsTokenValid(response))
                        throw new UnauthorizedAccessException();

                    List<Claim> claims = authService1.GetTokenClaims(response).ToList();

                    if (claims.FirstOrDefault(e => e.Type.Equals("status")).Value == "empty_webhook")
                        MessageBox.Show("No webhook set, Please login to the panel and add a discord webhook", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);

                    Security.End();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
            }
        }
        public static void Ban(string action)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(action))
            {
                MessageBox.Show("Missing log information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["username"] = Encryption.APIService(User.Username ?? Environment.UserName),
                        ["password"] = Encryption.APIService(User.Password ?? "null"),
                        ["pcuser"] = Encryption.APIService(Environment.UserName),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["data"] = Encryption.APIService(action),
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["hwid"] = Encryption.APIService(Constants.HWID()),
                        ["type"] = Encryption.APIService("ban")
                    }))).Split("|".ToCharArray()));
                    Security.End();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
            }
            Security.Abandon();
            Process.GetCurrentProcess().Kill();

        }

        public static void ChangeProfilePic(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                MessageBox.Show("Invalid Picture information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }

            string picture = Convert.ToBase64String(File.ReadAllBytes(path));
            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {

                try
                {
                    wc.Proxy = null;
                    Security.Start();
                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["username"] = Encryption.APIService(User.Username),
                        ["password"] = Encryption.APIService(User.Password),
                        ["picbytes"] = Encryption.APIService(picture),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("uploadpic")

                    }))).Split("|".ToCharArray()));

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    switch (response[0])
                    {
                        case "success":
                            MessageBox.Show("Successfully updated profile picture!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                            Security.End();
                            return;
                        case "incorrect":
                            MessageBox.Show("Failed to Login!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "expired":
                            MessageBox.Show("Please renew your Subscription to use this feature!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "maxsize":
                            MessageBox.Show("Image cannot be greater than 1 MB!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return;
                        case "failed":
                            MessageBox.Show("Failed to upload profile picture!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
            }
        }
  
        private static JWTContainerModel JWTLogin(string username, string password)
        {
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                new Claim("token", Encryption.EncryptService(Constants.Token)),
                new Claim("timestamp", Encryption.EncryptService(DateTime.Now.ToString())),
                new Claim("aid", Encryption.APIService(OnProgramStart.AID)),
                new Claim("hwid", Encryption.APIService(Constants.HWID())),
                new Claim("version", Encryption.EncryptService(OnProgramStart.Version)),
                new Claim("username", Encryption.APIService(username)),
                new Claim("password", Encryption.APIService(password)),
                new Claim("session_key", Encryption.APIService(Constants.Key))
                }
            };
        }

        public static bool Login(string username, string password)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                MessageBox.Show("Missing user login information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            string response = string.Empty;
            string jwttoken = string.Empty;

            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;

                    IAuthContainerModel model = JWTLogin(username, password);
                    model.SecretKey = OnProgramStart.JWTKey;

                    IAuthService authService = new JWTService(model.SecretKey);
                    jwttoken = authService.GenerateToken(model);

                    if (!authService.IsTokenValid(jwttoken))
                        throw new UnauthorizedAccessException();

                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.APIService(jwttoken),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("login")

                    }))));

                    model.SecretKey = OnProgramStart.JWTKey;
                    IAuthService authService1 = new JWTService(model.SecretKey);

                    Clipboard.SetText(response);
                    if (!authService1.IsTokenValid(response))
                        throw new UnauthorizedAccessException();

                    List<Claim> claims = authService1.GetTokenClaims(response).ToList();

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    if (claims.FirstOrDefault(e => e.Type.Equals("token")).Value != Constants.Token)
                    {
                        MessageBox.Show("Security error has been triggered!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Security.MaliciousCheck(claims.FirstOrDefault(e => e.Type.Equals("timestamp")).Value))
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Constants.Breached)
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    switch (claims.FirstOrDefault(e => e.Type.Equals("status")).Value)
                    {
                        case "success":
                            User.ID = claims.FirstOrDefault(e => e.Type.Equals("id")).Value;
                            User.Username = claims.FirstOrDefault(e => e.Type.Equals("username")).Value;
                            User.Password = claims.FirstOrDefault(e => e.Type.Equals("password")).Value;
                            User.Email = claims.FirstOrDefault(e => e.Type.Equals("mail")).Value;
                            User.HWID = claims.FirstOrDefault(e => e.Type.Equals("hwid")).Value;
                            User.UserVariable = claims.FirstOrDefault(e => e.Type.Equals("user_var")).Value;
                            User.Rank = claims.FirstOrDefault(e => e.Type.Equals("rank")).Value;
                            User.IP = claims.FirstOrDefault(e => e.Type.Equals("ip")).Value;
                            User.Expiry = claims.FirstOrDefault(e => e.Type.Equals("expire")).Value;
                            User.LastLogin = claims.FirstOrDefault(e => e.Type.Equals("LastLogin")).Value;
                            User.RegisterDate = claims.FirstOrDefault(e => e.Type.Equals("RegDate")).Value;
                            string Variables = claims.FirstOrDefault(e => e.Type.Equals("server_var")).Value;
                            User.ProfilePicture = claims.FirstOrDefault(e => e.Type.Equals("picture")).Value;
                            
                            foreach (string var in Variables.Split('~'))
                            {
                                string[] items = var.Split('^');
                                try
                                {
                                    App.Variables.Add(items[0], items[1]);
                                }
                                catch
                                {
                                   // If some are null or not loaded, just ignore.
                                 //   Error will be shown when loading the variable anyways
                                }
                            }
                            Security.End();
                            return true;
                        case "invalid_details":
                            MessageBox.Show("Incorrect Details, Please Check you're username and password", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            Security.End();
                            return false;
                        case "time_expired":
                            MessageBox.Show("Your subscription has expired!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            Security.End();
                            return false;
                        case "hwid_updated":
                            MessageBox.Show("New machine has been binded, re-open the application!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                            Security.End();
                            return false;
                        case "invalid_hwid":
                            Constants.hwidcheckvalid = true;
                            MessageBox.Show("This user is binded to another computer, please contact support!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                        case "banned":
                            User.Ban_Reason = claims.FirstOrDefault(e => e.Type.Equals("banreason")).Value;
                            MessageBox.Show("This user is banned, please contact support on discord if you believe this is a mistake!" + Environment.NewLine + "Reason: " + User.Ban_Reason, ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            Application.Exit();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Security.End();
                    Process.GetCurrentProcess().Kill();
                }
                return false;

            }
        }
        public static bool ResetHwid(string username, string password)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                MessageBox.Show("Missing user login information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = (Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["username"] = Encryption.APIService(username),
                        ["password"] = Encryption.APIService(password),
                        ["hwid"] = Encryption.APIService(Constants.HWID()),
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("resethwid")

                    }))).Split("|".ToCharArray()));

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    if (response[0] != Constants.Token)
                    {
                        MessageBox.Show(response[0]);
                        MessageBox.Show("Security error has been triggered!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Security.MaliciousCheck(response[1]))
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Constants.Breached)
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    switch (response[2])
                    {
                        case "hwid_reset":
                            MessageBox.Show("Your HWID has been resetted!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            Security.End();
                            return true;
                        case "invalid_details":
                            Security.End();
                            return false;
                        case "hwid_wait":
                            MessageBox.Show("Please wait 24 hours before resetting your hwid!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Security.End();
                    Process.GetCurrentProcess().Kill();
                }
                return false;

            }
        }

        public static bool Register(string username, string password, string email, string license)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Security.End();
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(license))
            {
                MessageBox.Show("Invalid registrar information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }

            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;

                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("register"),
                        ["username"] = Encryption.APIService(username),
                        ["password"] = Encryption.APIService(password),
                        ["email"] = Encryption.APIService(email),
                        ["license"] = Encryption.APIService(license),
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["hwid"] = Encryption.APIService(Constants.HWID()),

                    }))).Split("|".ToCharArray());

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }

                    if (response[0] != Constants.Token)
                    {
                        MessageBox.Show("Security error has been triggered!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Security.End();
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Security.MaliciousCheck(response[1]))
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Constants.Breached)
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    switch (response[2])
                    {
                        case "success":
                            Security.End();
                            return true;
                        case "invalid_license":
                            MessageBox.Show("License does not exist!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                        case "email_used":
                            MessageBox.Show("Email has already been used!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                        case "invalid_username":
                            MessageBox.Show("You entered an invalid/used username!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
                return false;
            }
        }
        public static bool ExtendSubscription(string username, string password, string license)
        {
            if (!Constants.Initialized)
            {
                MessageBox.Show("Please initialize your application first!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Security.End();
                Process.GetCurrentProcess().Kill();
            }
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(license))
            {
                MessageBox.Show("Invalid registrar information!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            string[] response = new string[] { };
            using (StackWebClient wc = new StackWebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl, new NameValueCollection
                    {
                        ["token"] = Encryption.EncryptService(Constants.Token),
                        ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                        ["aid"] = Encryption.APIService(OnProgramStart.AID),
                        ["session_id"] = Constants.IV,
                        ["api_id"] = Constants.APIENCRYPTSALT,
                        ["api_key"] = Constants.APIENCRYPTKEY,
                        ["session_key"] = Constants.Key,
                        ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                        ["type"] = Encryption.APIService("extend"),
                        ["username"] = Encryption.APIService(username),
                        ["password"] = Encryption.APIService(password),
                        ["license"] = Encryption.APIService(license),

                    }))).Split("|".ToCharArray());

                    if (wc.ResponseUri.ToString() != Constants.ApiUrl)
                    {
                        MessageBox.Show("Possible Domain hijack detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (response[0] != Constants.Token)
                    {
                        MessageBox.Show("Security error has been triggered!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Security.End();
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Security.MaliciousCheck(response[1]))
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    if (Constants.Breached)
                    {
                        MessageBox.Show("Possible malicious activity detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        Process.GetCurrentProcess().Kill();
                    }
                    switch (response[2])
                    {
                        case "success":
                            Security.End();
                            return true;
                        case "invalid_token":
                            MessageBox.Show("Token does not exist!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                        case "invalid_details":
                            MessageBox.Show("Your user details are invalid!", ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, ApplicationSettings.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Process.GetCurrentProcess().Kill();
                }
                return false;
            }
        }

    }
    public static class ProcessExtensions
    {
        private static string FindIndexedProcessName(int pid)
        {
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
                if ((int)processId.NextValue() == pid)
                {
                    return processIndexdName;
                }
            }

            return processIndexdName;
        }

        private static Process FindPidFromIndexedProcessName(string indexedProcessName)
        {
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
            return Process.GetProcessById((int)parentId.NextValue());
        }

        public static Process Parent(this Process process)
        {
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        }
    }
    internal class Security
    {
        [DllImport("Kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, long count);
        [DllImport("User32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBoxDisplay(IntPtr h, string m, string c, int type);
 
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        public enum ProcessInfo : uint
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }
        public static void DebugandProcessCheck()
        {
            try
            {

                bool isDebuggerPresent = false;
                CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
                if (Debugger.IsAttached || isDebuggerPresent)
                    Abandon();

                string[] IllegalProcessName = { "Fiddler", "Wireshark", "dumpcap", "dnSpy", "dnSpy-x86", "cheatengine-x86_64", "HTTPDebuggerUI", "Procmon", "Procmon64", "Procmon64a", "ProcessHacker", "x32dbg", "x64dbg", "DotNetDataCollector32", "DotNetDataCollector64" };
                string[] IllegalWindowName = { "Progress Telerik Fiddler Web Debugger", "Wireshark" };
                string[] VmProcess = { "VBoxService", "VBoxTray" };
                string[] VmDriver = { "VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys", "VBoxWddm.sys" };
                string[] IllegalContains = { "dumper", "debugger", "http" };

                Process[] ProcessList = Process.GetProcesses();
                foreach (Process proc in ProcessList)
                {
                    for (int i = 0; i < IllegalContains.Length; i++)
                    {
                        if (proc.ProcessName.ToLower().Contains(IllegalContains[i].ToLower()))
                        {
                            StackAPI.Ban("illegalprocess");
                        }
                    }

                    for (int i = 0; i < IllegalProcessName.Length; i++)
                    {
                        //check process name
                        if (proc.ProcessName == IllegalProcessName[i])
                        {
                            StackAPI.Ban("illegalprocess");
                        }
                    }

                    for (int i = 0; i < IllegalWindowName.Length; i++)
                    {
                        //check process window title
                        if (proc.MainWindowTitle == IllegalWindowName[i])
                        {
                            StackAPI.Ban("illegalprocess");
                        }
                    }

                    for (int i = 0; i < VmProcess.Length; i++)
                    {
                        //check process name
                        if (proc.ProcessName == VmProcess[i])
                        {
                            StackAPI.Ban("vmprocess");
                        }
                    }

                    for (int i = 0; i < VmDriver.Length; i++)
                    {
                        if (Directory.Exists("C:\\Windows\\System32\\drivers\\" + VmDriver[i]))
                        {
                            StackAPI.Ban("vmdrivers");
                        }
                    }


                }
            }
            catch { }

        }
        public static bool AntiDebugger()
        {
            bool DebuggerPresent = false;
            CheckRemoteDebuggerPresent(OpenProcess(ProcessAccessFlags.All, false, Process.GetCurrentProcess().Id), ref DebuggerPresent);
            if (DebuggerPresent == false)
            {
                //if check debugger is false, make more check
                IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, Process.GetCurrentProcess().Id);
                IntPtr dwReturnLength = Marshal.AllocHGlobal(sizeof(long));
                IntPtr dwDebugPort = IntPtr.Zero;

                if (NtQueryInformationProcess(hProc, (int)ProcessInfo.ProcessDebugPort, dwReturnLength, (uint)Marshal.SizeOf(dwDebugPort), dwReturnLength) >= 0)
                {
                    CloseHandle(hProc);
                    if (dwDebugPort == (IntPtr)(-1))
                    {
                        Marshal.FreeHGlobal(dwReturnLength);
                        DebuggerPresent = true;
                    }
                }
                //if someone is debugging the process the parent process will be the debugger and not explorer like almost every process in your computer
                if (!Process.GetCurrentProcess().Parent().ProcessName.Contains("explorer"))
                    DebuggerPresent = true;
            }
            return DebuggerPresent;
        }
        public static bool AntiSandboxie()
        {
            //get handle of this dll (this dll is used when someone launch your software with sandboxie)
            //If the dll doesn't exist the handle will be NULL
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;


            return false;
        }

        public static bool AntiHttpDebugger()
        {
            if (CheckLibrary("pssdk.dll"))
                return true;

            if (CheckLibrary("ws2_32.dll"))
                return true;

            return false;
        }

        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        static bool CheckLibrary(string fileName)
        {
            return LoadLibrary(fileName) == IntPtr.Zero;
        }

        public static IntPtr OpenProcess(ProcessAccessFlags flags1, Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }
        public static string Signature(string value)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] input = Encoding.UTF8.GetBytes(value);
                byte[] hash = md5.ComputeHash(input);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }
        private static string Session(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            return new string(Enumerable.Repeat(chars, length)
             .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string Obfuscate(int length)
        {
            Random random = new Random();
            const string chars = "gd8JQ57nxXzLLMPrLylVhxoGnWGCFjO4knKTfRE6mVvdjug2NF/4aptAsZcdIGbAPmcx0O+ftU/KvMIjcfUnH3j+IMdhAW5OpoX3MrjQdf5AAP97tTB5g1wdDSAqKpq9gw06t3VaqMWZHKtPSuAXy0kkZRsc+DicpcY8E9+vWMHXa3jMdbPx4YES0p66GzhqLd/heA2zMvX8iWv4wK7S3QKIW/a9dD4ALZJpmcr9OOE=";
            return new string(Enumerable.Repeat(chars, length)
             .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public static void Start()
        {
            string drive = Path.GetPathRoot(Environment.SystemDirectory);
            if (Constants.Started)
            {
                MessageBox.Show("A session has already been started, please end the previous one!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                using (StreamReader sr = new StreamReader($@"{drive}Windows\System32\drivers\etc\hosts"))
                {
                    string contents = sr.ReadToEnd();
                    if (contents.Contains("stackworkshop.com"))
                    {
                        Constants.Breached = true;
                        StackAPI.Ban("dnsredirect");
                        MessageBox.Show("DNS redirecting has been detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Process.GetCurrentProcess().Kill();
                    }
                }
                InfoManager infoManager = new InfoManager();
                infoManager.StartListener();
                Constants.Token = Guid.NewGuid().ToString();
                ServicePointManager.ServerCertificateValidationCallback += PinPublicKey;
                Constants.APIENCRYPTKEY = Convert.ToBase64String(Encoding.Default.GetBytes(Session(32)));
                Constants.APIENCRYPTSALT = Convert.ToBase64String(Encoding.Default.GetBytes(Session(16)));
                Constants.IV = Convert.ToBase64String(Encoding.Default.GetBytes(Constants.RandomString(16)));
                Constants.Key = Convert.ToBase64String(Encoding.Default.GetBytes(Constants.RandomString(32)));
                Constants.Started = true;

                if (OnProgramStart.ProcessCheck)
                {
                    Security.DebugandProcessCheck();
                }
            }
        }
        public static void End()
        {
            if (!Constants.Started)
            {
                MessageBox.Show("No session has been started, closing for security reasons!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                Constants.Token = null;
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                Constants.APIENCRYPTKEY = null;
                Constants.APIENCRYPTSALT = null;
                Constants.IV = null;
                Constants.Key = null;
                Constants.Started = false;
            }
        }
        public static void Abandon()
        {
            Constants.Token = null;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            Constants.APIENCRYPTKEY = null;
            Constants.APIENCRYPTSALT = null;
            Constants.IV = null;
            Constants.Key = null;
            Constants.Started = false;
            User.UserVariable = null;
            OnProgramStart.AID = null;
            OnProgramStart.Secret = null;
            OnProgramStart.Version = "8.1.9.2";
            OnProgramStart.Salt = null;
        }
        private static bool PinPublicKey(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if ((!certificate.Issuer.Contains("Cloudflare Inc") && !certificate.Issuer.Contains("Google Trust Services") && !certificate.Issuer.Contains("Let's Encrypt")) || sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            return certificate != null;
        }
        public static string Integrity(string filename)
        {
            string result;
            using (MD5 md = MD5.Create())
            {
                using (FileStream fileStream = File.OpenRead(filename))
                {
                    byte[] value = md.ComputeHash(fileStream);
                    result = BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
                }
            }
            return result;
        }
        public static bool MaliciousCheck(string date)
        {
            DateTime dt1 = DateTime.Parse(date); //time sent
            DateTime dt2 = DateTime.Now; //time received
            TimeSpan d3 = dt1 - dt2;
            if (Convert.ToInt32(d3.Seconds.ToString().Replace("-", "")) >= 5 || Convert.ToInt32(d3.Minutes.ToString().Replace("-", "")) >= 1)
            {
                Constants.Breached = true;
                return true;
            }
            else
            {
                return false;
            }
        }
        public static void HashCheck(string dllpath, string dllstoredhash)
        {
            if (File.Exists(dllpath))
            {
                if (CalculateMD5(dllpath) != dllstoredhash)
                {
                    StackAPI.Ban("Tampered File: " + dllpath);
                    End();
                    Process.GetCurrentProcess().Kill();
                }
            }
        }
        public static string GetHash(string dllpath)
        {
            return CalculateMD5(dllpath);
        }
        private static string CalculateMD5(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }
    }
    internal class Encryption
    {
        public static string APIService(string value)
        {
            string message = value;
            string password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            string encrypted = EncryptString(message, key, iv);
            return encrypted;
        }
        public static string EncryptService(string value)
        {
            string message = value;
            string password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            string encrypted = EncryptString(message, key, iv);
            int property = Int32.Parse((OnProgramStart.AID.Substring(0, 1)));
            string final = encrypted + Security.Obfuscate(property);
            return final;
        }
        public static string DecryptService(string value)
        {
            string message = value;
            string password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            string decrypted = DecryptString(message, key, iv);
            return decrypted;
        }
        public static string EncryptString(string plainText, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);
            byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] cipherBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);
            return cipherText;
        }

        public static string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);
            string plainText = String.Empty;
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                cryptoStream.FlushFinalBlock();
                byte[] plainBytes = memoryStream.ToArray();
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                memoryStream.Close();
                cryptoStream.Close();
            }
            return plainText;
        }
        public static string Decode(string text)
        {
            text = text.Replace('_', '/').Replace('-', '+');
            switch (text.Length % 4)
            {
                case 2:
                    text += "==";
                    break;
                case 3:
                    text += "=";
                    break;
            }
            return Encoding.UTF8.GetString(Convert.FromBase64String(text));
        }


    }
    class InfoManager
    {
        private System.Threading.Timer timer;
        private string lastGateway;

        public InfoManager()
        {
            lastGateway = GetGatewayMAC();
        }

        public void StartListener()
        {
            timer = new System.Threading.Timer(_ => OnCallBack(), null, 5000, Timeout.Infinite);
        }

        private void OnCallBack()
        {
            timer.Dispose();
            if (!(GetGatewayMAC() == lastGateway))
            {
                Constants.Breached = true;
                MessageBox.Show("ARP Cache poisoning has been detected!", OnProgramStart.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                lastGateway = GetGatewayMAC();
            }
            timer = new System.Threading.Timer(_ => OnCallBack(), null, 5000, Timeout.Infinite);
        }

        public static IPAddress GetDefaultGateway()
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                .FirstOrDefault();
        }

        private string GetArpTable()
        {
            string drive = Path.GetPathRoot(Environment.SystemDirectory);
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = $@"{drive}Windows\System32\arp.exe";
            start.Arguments = "-a";
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.CreateNoWindow = true;

            using (Process process = Process.Start(start))
            {
                using (StreamReader reader = process.StandardOutput)
                {
                    return reader.ReadToEnd();
                }
            }
        }

        private string GetGatewayMAC()
        {
            string routerIP = GetDefaultGateway().ToString();
            string regx = String.Format(@"({0} [\W]*) ([a-z0-9-]*)", routerIP);
            Regex regex = new Regex(@regx);
            Match matches = regex.Match(GetArpTable());
            return matches.Groups[2].ToString();
        }
    }
    class StackUtities
    {
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string LoadStringFromURL(string url)
        {
            string DResponse;
            using (WebClient GData = new WebClient())
                DResponse = GData.DownloadString(url).ToString();
            return DResponse;
        }
        public string[] CreateArrayFromTxtFile(string txtfile)
        {
            if (File.Exists(txtfile))
            {
                return File.ReadAllLines(txtfile);

            }
            else
            {
                MessageBox.Show("File don't exist");
                return "File don't exist".Split('|');
            }
        }

        public static string OpenFileDialog(string title, string filter = "Text Files|*.txt|All Files|*.*")
        {
            OpenFileDialog openFileDialog = new OpenFileDialog()
            {
                Title = title,
                Filter = filter
            };

            if (openFileDialog.ShowDialog() != DialogResult.OK) return null;

            return openFileDialog.FileName;
        }
    }

}
