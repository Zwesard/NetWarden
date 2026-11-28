// NetWarden 0.5 - сетевой сканер уязвимостей и аудит безопасности сети для Windows.
// Один файл, C# 5, компилируется встроенным в Windows csc.exe. Сканируйте только свои системы или с разрешения владельца.
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace NetWarden
{
    // ===================== МОДЕЛИ =====================
    class PortInfo
    {
        public int Port;
        public string Proto = "tcp";
        public string Service = "", Product = "", Version = "", Banner = "";
        public bool Tls;
    }

    class Finding
    {
        public string Id = "", Title = "", Severity = "info", Desc = "", Rec = "", Cve = "", Conf = "confirmed", Evidence = "", Attack = "", Source = "";
        public double Cvss;
        public int Port;
    }

    class HostInfo
    {
        public string Ip = "", Name = "", Mac = "", Vendor = "", MacInfo = "", Os = "", OsBasis = "", Descr = "";
        public int Ttl;
        public List<PortInfo> Ports = new List<PortInfo>();
        public List<Finding> Findings = new List<Finding>();
    }

    class ScanResult
    {
        public string Id = "", Targets = "", Ports = "";
        public DateTime Started, Finished;
        public List<HostInfo> Hosts = new List<HostInfo>();
    }

    static class Refs
    {
        public static string Bdu(string query)
        {
            return "https://bdu.fstec.ru/vul?text=" + Uri.EscapeDataString(query);
        }
        public static string Nvd(string cve)
        {
            return "https://nvd.nist.gov/vuln/detail/" + cve;
        }
    }

    // Портативный режим: если рядом с NetWarden.exe лежит файл portable.txt, все данные программы
    // (журнал исправлений, пользовательская база MAC, скрипты) хранятся в подпапке Data рядом с exe,
    // а не в профиле пользователя (%APPDATA%). Это позволяет носить программу на флешке без следов
    // на компьютере. Удалите portable.txt, чтобы вернуться к обычному хранению в %APPDATA%.
    static class AppPaths
    {
        static bool? portable;
        static string exeDir;

        public static bool IsPortable
        {
            get
            {
                if (portable == null)
                {
                    try { exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location); }
                    catch (Exception) { exeDir = AppDomain.CurrentDomain.BaseDirectory; }
                    portable = exeDir != null && File.Exists(Path.Combine(exeDir, "portable.txt"));
                }
                return portable.Value;
            }
        }

        // Папка данных программы: Data рядом с exe в портативном режиме, иначе %APPDATA%\NetWarden.
        public static string DataDir()
        {
            string d = IsPortable
                ? Path.Combine(exeDir, "Data")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetWarden");
            try { Directory.CreateDirectory(d); } catch (Exception) { }
            return d;
        }
    }

    static class Sev
    {
        public static readonly string[] Order = new string[] { "critical", "high", "medium", "low", "info" };
        public static int Idx(string s) { int i = Array.IndexOf(Order, s); return i < 0 ? 99 : i; }
        public static string Ru(string s)
        {
            switch (s)
            {
                case "critical": return "Критический";
                case "high": return "Высокий";
                case "medium": return "Средний";
                case "low": return "Низкий";
                default: return "Информация";
            }
        }
        // Палитра без жёлтого: красный -> оранжевый -> фиолетовый -> голубой -> серо-синий.
        public static Color Col(string s)
        {
            switch (s)
            {
                case "critical": return Color.FromArgb(255, 61, 90);
                case "high": return Color.FromArgb(255, 122, 61);
                case "medium": return Color.FromArgb(157, 127, 255);
                case "low": return Color.FromArgb(56, 189, 248);
                default: return Color.FromArgb(120, 134, 155);
            }
        }
    }

    // ===================== ТЕМА: "ВОЕННО-ФУТУРИСТИЧЕСКАЯ ПАНЕЛЬ УПРАВЛЕНИЯ" =====================
    static class Theme
    {
        public static readonly Color BgDeep = Color.FromArgb(10, 14, 23);        // глубокий фон окна
        public static readonly Color BgPanelTop = Color.FromArgb(22, 30, 46);    // верх градиента панели
        public static readonly Color BgPanelBot = Color.FromArgb(14, 19, 31);    // низ градиента панели
        public static readonly Color BgCardTop = Color.FromArgb(26, 35, 54);
        public static readonly Color BgCardBot = Color.FromArgb(16, 22, 36);
        public static readonly Color BorderDim = Color.FromArgb(70, 56, 102, 158);   // тонкая голубая окантовка (полупрозрачная)
        public static readonly Color BorderCyan = Color.FromArgb(120, 94, 234, 255);
        public static readonly Color Accent = Color.FromArgb(64, 224, 208);      // бирюзовый акцент
        public static readonly Color AccentDim = Color.FromArgb(70, 64, 224, 208);
        public static readonly Color Electric = Color.FromArgb(56, 189, 248);    // электрик-блю
        public static readonly Color TextMain = Color.FromArgb(214, 226, 240);
        public static readonly Color TextMuted = Color.FromArgb(122, 138, 158);
        public static readonly Color TextDim = Color.FromArgb(82, 96, 116);
        public static readonly Color Danger = Color.FromArgb(255, 77, 109);

        public static GraphicsPath RoundRect(RectangleF r, float rad)
        {
            float d = rad * 2f;
            GraphicsPath p = new GraphicsPath();
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // Полупрозрачная панель с мягким вертикальным градиентом, тонкой окантовкой и лёгким свечением.
        public static void PaintGlass(Graphics g, Rectangle bounds, Color top, Color bot, Color border, bool glow)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            RectangleF r = new RectangleF(bounds.X + 1, bounds.Y + 1, bounds.Width - 2, bounds.Height - 2);
            if (r.Width <= 0 || r.Height <= 0) return;
            using (GraphicsPath path = RoundRect(r, 10f))
            {
                // Мягкое единое свечение вплотную к самой окантовке (а не отдельные вынесенные кольца -
                // именно они на маленькой панели выглядели как "уголки" по краям).
                if (glow)
                    using (Pen gp = new Pen(Color.FromArgb(70, Accent), 2.2f))
                        g.DrawPath(gp, path);
                using (LinearGradientBrush grad = new LinearGradientBrush(new PointF(0, r.Y), new PointF(0, r.Bottom), top, bot))
                    g.FillPath(grad, path);
                using (Pen pen = new Pen(border, 1.1f)) g.DrawPath(pen, path);
            }
        }

        static RectangleF Inflate(RectangleF r, float d) { RectangleF x = r; x.Inflate(d, d); return x; }
    }

    // ===================== ЦЕЛИ И ПОРТЫ =====================
    static class Targets
    {
        public const int MaxTargets = 65536;
        public static readonly int[] Common = new int[] {
            20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995,
            1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 7001, 8000, 8080,
            8081, 8088, 8443, 8888, 9000, 9090, 9200, 9443, 11211, 27017 };

        public static long ToUInt(string ip)
        {
            byte[] b = IPAddress.Parse(ip).GetAddressBytes();
            return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | (long)b[3];
        }

        public static string ToIp(long v)
        {
            return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
        }

        static void Add(List<string[]> res, HashSet<string> seen, string ip, string name)
        {
            if (seen.Add(ip))
            {
                res.Add(new string[] { ip, name });
                if (res.Count > MaxTargets) throw new Exception("Слишком много целей (больше " + MaxTargets + ")");
            }
        }

        public static List<string[]> Expand(string spec)
        {
            List<string[]> res = new List<string[]>();
            HashSet<string> seen = new HashSet<string>();
            ExpandInto(spec, res, seen);
            if (res.Count == 0) throw new Exception("Не указаны цели сканирования");
            return res;
        }

        static void ExpandInto(string spec, List<string[]> res, HashSet<string> seen)
        {
            string[] toks = Regex.Split(spec.Trim(), @"[,\s;]+");
            foreach (string raw in toks)
            {
                string tok = raw.Trim();
                if (tok.Length == 0) continue;
                if (tok[0] == '@')
                {
                    foreach (string line in File.ReadAllLines(tok.Substring(1)))
                    {
                        string l = line;
                        int hash = l.IndexOf('#');
                        if (hash >= 0) l = l.Substring(0, hash);
                        if (l.Trim().Length > 0) ExpandInto(l, res, seen);
                    }
                    continue;
                }
                Match m;
                if (tok.Contains("/"))
                {
                    string[] parts = tok.Split('/');
                    long ip = ToUInt(parts[0]);
                    int bits = int.Parse(parts[1]);
                    if (bits < 0 || bits > 32) throw new Exception("Неверная маска: " + tok);
                    long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                    long net = ip & mask;
                    long bc = net | (~mask & 0xFFFFFFFFL);
                    long first = net, last = bc;
                    if (bits < 31) { first = net + 1; last = bc - 1; }
                    for (long a = first; a <= last; a++) Add(res, seen, ToIp(a), "");
                    continue;
                }
                m = Regex.Match(tok, @"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$");
                if (m.Success)
                {
                    int a1 = int.Parse(m.Groups[2].Value), b1 = int.Parse(m.Groups[3].Value);
                    for (int i = a1; i <= b1 && i <= 255; i++) Add(res, seen, m.Groups[1].Value + i, "");
                    continue;
                }
                m = Regex.Match(tok, @"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$");
                if (m.Success)
                {
                    long a2 = ToUInt(m.Groups[1].Value), b2 = ToUInt(m.Groups[2].Value);
                    for (long i = a2; i <= b2; i++) Add(res, seen, ToIp(i), "");
                    continue;
                }
                IPAddress parsed;
                if (IPAddress.TryParse(tok, out parsed) && parsed.AddressFamily == AddressFamily.InterNetwork)
                {
                    Add(res, seen, parsed.ToString(), "");
                    continue;
                }
                IPAddress found = null;
                try
                {
                    foreach (IPAddress a in Dns.GetHostAddresses(tok))
                        if (a.AddressFamily == AddressFamily.InterNetwork) { found = a; break; }
                }
                catch (Exception) { }
                if (found == null) throw new Exception("Не удалось разобрать или разрешить цель: " + tok);
                Add(res, seen, found.ToString(), tok);
            }
        }

        public static int[] ParsePorts(string spec)
        {
            spec = (spec ?? "common").Trim().ToLower();
            if (spec == "" || spec == "common") return Common;
            if (spec == "full") return Enumerable.Range(1, 65535).ToArray();
            List<int> list = new List<int>();
            foreach (string part in spec.Split(','))
            {
                string p = part.Trim();
                if (p.Length == 0) continue;
                if (p.Contains("-"))
                {
                    string[] ab = p.Split('-');
                    int a = int.Parse(ab[0]), b = int.Parse(ab[1]);
                    if (a < 1 || b > 65535 || a > b) throw new Exception("Неверный диапазон портов: " + p);
                    for (int i = a; i <= b; i++) list.Add(i);
                }
                else
                {
                    int one = int.Parse(p);
                    if (one < 1 || one > 65535) throw new Exception("Неверный порт: " + p);
                    list.Add(one);
                }
            }
            int[] arr = list.Distinct().ToArray();
            Array.Sort(arr);
            return arr;
        }
    }

    // ===================== СЕТЕВЫЕ ПОМОЩНИКИ =====================
    static class NetUtil
    {
        public static TcpClient Connect(string ip, int port, int timeoutMs, out bool refused)
        {
            refused = false;
            TcpClient c = new TcpClient();
            try
            {
                IAsyncResult ar = c.BeginConnect(IPAddress.Parse(ip), port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs, false)) { c.Close(); return null; }
                c.EndConnect(ar);
                return c;
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionRefused) refused = true;
                c.Close();
                return null;
            }
            catch (Exception)
            {
                c.Close();
                return null;
            }
        }

        public static bool AcceptAll(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors err)
        {
            return true;
        }

        public static Stream Open(TcpClient c, bool tls, string host)
        {
            Stream s = c.GetStream();
            if (!tls) return s;
            SslStream ss = new SslStream(s, false, new RemoteCertificateValidationCallback(AcceptAll));
            ss.AuthenticateAsClient(host);
            return ss;
        }

        public static string ReadSome(Stream s, int timeoutMs)
        {
            try
            {
                s.ReadTimeout = timeoutMs;
                byte[] buf = new byte[2048];
                int n = s.Read(buf, 0, buf.Length);
                if (n <= 0) return "";
                return Encoding.GetEncoding(28591).GetString(buf, 0, n);
            }
            catch (Exception) { return ""; }
        }
    }

    // ===================== СЕРВИСЫ И ВЕРСИИ =====================
    class Pat
    {
        public Regex Rx;
        public string Svc, Prod;
        public Pat(string rx, string svc, string prod)
        {
            Rx = new Regex(rx, RegexOptions.None);
            Svc = svc;
            Prod = prod;
        }
    }

    static class Services
    {
        static readonly Dictionary<int, string> Default = new Dictionary<int, string>
        {
            {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},{80,"http"},{110,"pop3"},{111,"rpcbind"},
            {135,"msrpc"},{139,"netbios-ssn"},{143,"imap"},{389,"ldap"},{443,"https"},{445,"smb"},{465,"smtps"},
            {587,"smtp"},{636,"ldaps"},{993,"imaps"},{995,"pop3s"},{1433,"mssql"},{1521,"oracle"},{2049,"nfs"},
            {2375,"docker"},{3306,"mysql"},{3389,"rdp"},{5432,"postgresql"},{5900,"vnc"},{5985,"winrm"},
            {5986,"winrm"},{6379,"redis"},{8080,"http"},{8443,"https"},{9200,"elasticsearch"},{11211,"memcached"},
            {27017,"mongodb"}
        };

        static readonly HashSet<int> TlsPorts = new HashSet<int> { 443, 465, 636, 993, 995, 5986, 8443, 9443 };

        static readonly Pat[] Patterns = new Pat[]
        {
            new Pat(@"^SSH-\d\.\d+-OpenSSH_(?<v>[\w.]+)", "ssh", "OpenSSH"),
            new Pat(@"^SSH-\d\.\d+-dropbear_(?<v>[\w.]+)", "ssh", "Dropbear"),
            new Pat(@"^SSH-\d\.\d+-(?<v>\S+)", "ssh", "SSH"),
            new Pat(@"^220.*vsFTPd (?<v>[\d.]+)", "ftp", "vsFTPd"),
            new Pat(@"^220.*ProFTPD (?<v>[\w.]+)", "ftp", "ProFTPD"),
            new Pat(@"^220.*FileZilla Server", "ftp", "FileZilla Server"),
            new Pat(@"^220.*Microsoft FTP", "ftp", "Microsoft FTP"),
            new Pat(@"^220.*FTP", "ftp", "FTP"),
            new Pat(@"^220.*Postfix", "smtp", "Postfix"),
            new Pat(@"^220.*Exim (?<v>[\d.]+)", "smtp", "Exim"),
            new Pat(@"^220.*Microsoft ESMTP", "smtp", "Microsoft ESMTP"),
            new Pat(@"^220.*SMTP", "smtp", "SMTP"),
            new Pat(@"^\+OK.*Dovecot", "pop3", "Dovecot"),
            new Pat(@"^\* OK.*Dovecot", "imap", "Dovecot"),
            new Pat(@"(?im)^Server:\s*Apache/(?<v>[\d.]+)", "http", "Apache"),
            new Pat(@"(?im)^Server:\s*nginx/(?<v>[\d.]+)", "http", "nginx"),
            new Pat(@"(?im)^Server:\s*Microsoft-IIS/(?<v>[\d.]+)", "http", "IIS"),
            new Pat(@"(?im)^Server:\s*lighttpd/(?<v>[\d.]+)", "http", "lighttpd"),
            new Pat(@"(?im)^Server:\s*Microsoft-HTTPAPI/(?<v>[\d.]+)", "http", "Microsoft HTTPAPI"),
            new Pat(@"^[\s\S]{3}\x00\n(?<v>[0-9][\w.\-+~]+)\x00", "mysql", "MySQL"),
            new Pat(@"^-ERR|^-NOAUTH|^\+PONG|redis_version", "redis", "Redis"),
            new Pat(@"^HTTP/1\.[01] ", "http", ""),
            new Pat(@"^RFB (?<v>\d+\.\d+)", "vnc", "VNC")
        };

        static string Grab(string ip, int port, int timeout, bool tls)
        {
            bool refused;
            TcpClient c = NetUtil.Connect(ip, port, timeout, out refused);
            if (c == null) return null;
            try
            {
                c.ReceiveTimeout = timeout;
                c.SendTimeout = timeout;
                Stream s = NetUtil.Open(c, tls, ip);
                string data = "";
                if (!tls) data = NetUtil.ReadSome(s, 800);
                if (data.Length == 0)
                {
                    byte[] probe = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: NetWarden\r\n\r\n");
                    s.Write(probe, 0, probe.Length);
                    s.Flush();
                    data = NetUtil.ReadSome(s, timeout);
                }
                return data;
            }
            catch (Exception) { return null; }
            finally { c.Close(); }
        }

        static string CleanBanner(string raw)
        {
            if (raw == null) return "";
            if (raw.Length > 300) raw = raw.Substring(0, 300);
            StringBuilder sb = new StringBuilder();
            foreach (char ch in raw)
            {
                if (ch == '\r') continue;
                if (ch == '\n') sb.Append(" | ");
                else if (ch >= 32 && ch < 127) sb.Append(ch);
                else sb.Append('.');
            }
            string r = sb.ToString().Trim();
            return r.Length > 200 ? r.Substring(0, 200) : r;
        }

        public static void Identify(string ip, PortInfo p, int timeout)
        {
            int t = Math.Max(timeout, 2000);
            bool tls = TlsPorts.Contains(p.Port);
            string data = Grab(ip, p.Port, t, tls);
            if (string.IsNullOrEmpty(data) && !tls)
            {
                string d2 = Grab(ip, p.Port, t, true);
                if (!string.IsNullOrEmpty(d2)) { data = d2; tls = true; }
            }
            data = data ?? "";
            string svc = "", prod = "", ver = "";
            foreach (Pat pt in Patterns)
            {
                Match m = pt.Rx.Match(data);
                if (m.Success)
                {
                    svc = pt.Svc;
                    prod = pt.Prod;
                    Group g = m.Groups["v"];
                    if (g != null && g.Success) ver = g.Value;
                    break;
                }
            }
            if (svc == "")
            {
                string d;
                svc = Default.TryGetValue(p.Port, out d) ? d : "";
            }
            if (tls && svc == "http") svc = "https";
            p.Service = svc;
            p.Product = prod;
            p.Version = ver;
            p.Banner = CleanBanner(data);
            p.Tls = tls;
        }
    }

    // ===================== ПРАВИЛА УЯЗВИМОСТЕЙ =====================
    class Rule
    {
        public string Id, Title, Sev, Cve, Desc, Rec, Attack = "";
        public double Cvss;
        public Dictionary<string, string> M = new Dictionary<string, string>();
    }

    static class Rules
    {
        static void A(List<Rule> l, string id, string title, string sev, double cvss, string cve, string match, string desc, string rec)
        {
            Rule r = new Rule();
            r.Id = id; r.Title = title; r.Sev = sev; r.Cvss = cvss; r.Cve = cve; r.Desc = desc; r.Rec = rec;
            string ex;
            r.Attack = Exploit.TryGetValue(id, out ex) ? ex : "";
            foreach (string kv in match.Split(';'))
            {
                int k = kv.IndexOf('=');
                if (k > 0) r.M[kv.Substring(0, k)] = kv.Substring(k + 1);
            }
            l.Add(r);
        }

        static readonly Dictionary<string, string> Exploit = BuildExploit();

        static void M(Dictionary<string, string> d, string k, string v) { d[k] = v.Trim(); }

        static Dictionary<string, string> BuildExploit()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            M(d, "SSH-USERENUM", "Злоумышленник посылает специально подобранные пакеты аутентификации и по разнице во времени ответа или типу ошибки определяет, существует ли на сервере указанное имя пользователя. Так составляется список реальных учётных записей для последующего подбора паролей.");
            M(d, "SSH-REGRESSHION", "Удалённый злоумышленник без учётных данных многократно (иногда часы) посылает запросы на подключение, вызывая состояние гонки в обработчике сигналов sshd; в случае успеха получает выполнение кода с правами root. Атака сложная и шумная, но полностью автоматизируема.");
            M(d, "FTP-VSFTPD-BACKDOOR", "Подключившись к FTP и передав в имени пользователя символы \":)\", злоумышленник активирует встроенный в скомпрометированную сборку бэкдор, который открывает командную оболочку на TCP-порту 6200 с правами сервиса - полный удалённый доступ без пароля.");
            M(d, "HTTP-APACHE-PATHTRAV", "Специально оформленный URL с последовательностями вида /.%2e/ позволяет выйти за пределы корневого каталога сайта и прочитать произвольные файлы сервера (пароли, конфигурации), а при включённом mod_cgi - выполнить команды на сервере.");
            M(d, "HTTP-NGINX-RESOLVER", "Злоумышленник, способный повлиять на ответы DNS-резолвера (например, через подконтрольный DNS-сервер, указанный в конфигурации), посылает специально сформированный DNS-ответ, вызывающий повреждение памяти рабочего процесса nginx - возможен отказ в обслуживании или выполнение кода.");
            M(d, "HTTP-IIS-OLD", "Снятая с поддержки версия IIS не получает исправлений безопасности. Злоумышленник ищет в открытых базах публичные эксплойты под конкретную версию и применяет их напрямую, без разведки.");
            M(d, "EXP-TELNET", "Весь трафик, включая пароли, передаётся открытым текстом. Любой, кто прослушивает сеть между клиентом и сервером (общий Wi-Fi, скомпрометированный коммутатор, ARP-спуфинг), перехватывает учётные данные и получает полный доступ.");
            M(d, "EXP-SMB", "SMB исторически был целью крупных червей (WannaCry, NotPetya) через уязвимости вроде EternalBlue, а также используется для сбора информации об общих папках, пользователях и групповых политиках для дальнейшего продвижения по сети (lateral movement).");
            M(d, "EXP-RDP", "Основной вектор - автоматизированный подбор паролей (credential stuffing/brute force) ботами, сканирующими весь интернет по порту 3389; при успехе - полный интерактивный доступ к рабочему столу. Также периодически публикуются критические уязвимости в самом протоколе RDP (например, BlueKeep), позволяющие выполнение кода без аутентификации.");
            M(d, "EXP-VNC", "Многие реализации VNC допускают вход без пароля или с паролем, ограниченным 8 символами (протокольное ограничение DES). Сканеры интернета (Shodan и подобные) индексируют такие хосты, после чего по ним идёт автоматический подбор или прямое подключение.");
            M(d, "EXP-REDIS", "Без аутентификации любой в сети может прочитать и изменить все данные, а также - классическая техника - записать в базу специально оформленный ключ и через настройку репликации или конфигурации записать SSH-ключ в authorized_keys жертвы, получив выполнение кода на сервере.");
            M(d, "EXP-MONGODB", "Открытая без аутентификации MongoDB позволяет скачать, изменить или удалить все данные без каких-либо учётных данных; массово применяется в автоматических атаках 'хранилище удалено, заплатите выкуп' (ransom note в пустой базе).");
            M(d, "EXP-ELASTIC", "Без включённой безопасности Elasticsearch отдаёт все проиндексированные данные любому запросу; известны массовые утечки из-за открытых инстансов, а также атаки через REST API на выполнение сценариев (script engine) для получения доступа к серверу.");
            M(d, "EXP-DOCKER", "Доступ к Docker API по сети без аутентификации равносилен root-доступу к хосту: достаточно запустить контейнер с примонтированным корнем файловой системы хоста (-v /:/host), чтобы получить полный контроль над сервером.");
            M(d, "EXP-MEMCACHED", "Открытый Memcached используется для чтения кэшированных (иногда чувствительных) данных, а также как усилитель в DDoS-атаках: короткий запрос с подменённым обратным адресом жертвы вызывает ответ в тысячи раз большего размера.");
            M(d, "EXP-MYSQL", "Доступность порта СУБД из сети используется для подбора паролей учётных записей и для попыток эксплуатации известных уязвимостей конкретной версии сервера.");
            return d;
        }

        public static readonly List<Rule> All = Build();

        static List<Rule> Build()
        {
            List<Rule> l = new List<Rule>();
            A(l, "SSH-USERENUM", "OpenSSH: перечисление пользователей (CVE-2018-15473)", "medium", 5.3, "CVE-2018-15473",
              "product=OpenSSH;version_lt=7.7", "Старые версии OpenSSH позволяют определить существование учётной записи.", "Обновите OpenSSH до актуальной версии.");
            A(l, "SSH-REGRESSHION", "OpenSSH: regreSSHion (CVE-2024-6387)", "high", 8.1, "CVE-2024-6387",
              "product=OpenSSH;version_gte=8.5;version_lt=9.8", "Состояние гонки в обработчике сигналов sshd. Дистрибутивы часто бэкпортируют исправления - проверьте версию пакета.", "Обновите OpenSSH до 9.8p1 или пакет дистрибутива с исправлением.");
            A(l, "FTP-VSFTPD-BACKDOOR", "vsFTPd 2.3.4: известный бэкдор (CVE-2011-2523)", "critical", 9.8, "CVE-2011-2523",
              "product=vsFTPd;versions=2.3.4", "В скомпрометированной сборке vsFTPd 2.3.4 присутствует бэкдор.", "Немедленно замените ПО на чистую актуальную версию.");
            A(l, "HTTP-APACHE-PATHTRAV", "Apache 2.4.49/2.4.50: обход пути (CVE-2021-41773/42013)", "critical", 9.8, "CVE-2021-41773, CVE-2021-42013",
              "product=Apache;versions=2.4.49,2.4.50", "Обход каталога и возможное выполнение кода.", "Обновите Apache HTTP Server до 2.4.51 и выше.");
            A(l, "HTTP-NGINX-RESOLVER", "nginx < 1.20.1: ошибка в резолвере (CVE-2021-23017)", "high", 7.7, "CVE-2021-23017",
              "product=nginx;version_lt=1.20.1", "Уязвимость в DNS-резолвере nginx.", "Обновите nginx до 1.20.1+ / 1.21.0+.");
            A(l, "HTTP-IIS-OLD", "Устаревшая версия Microsoft IIS", "high", 7.5, "",
              "product=IIS;version_lt=8.5", "IIS 8.0 и старше не поддерживаются и содержат множество известных уязвимостей.", "Перейдите на поддерживаемую версию Windows Server/IIS.");
            A(l, "EXP-TELNET", "Открыт Telnet", "high", 7.5, "", "service=telnet",
              "Telnet передаёт данные и пароли открытым текстом.", "Отключите службу Telnet (Windows: Панель управления - Программы и компоненты - Включение или отключение компонентов - снять Telnet; Linux: systemctl disable --now telnet.socket) и работайте по SSH.");
            // Примечание: отдельного правила "порт 445 открыт" больше нет - само по себе это не уязвимость
            // (порт обязан быть открыт, пока нужен общий доступ к файлам). Вместо этого Checks.Smb() по-настоящему
            // проверяет по протоколу, согласен ли сервер работать по устаревшему и опасному SMBv1.
            A(l, "EXP-RDP", "RDP доступен по сети", "medium", 5.0, "", "service=rdp",
              "Доступный из сети RDP - частая цель подбора паролей и эксплойтов.", "Не публикуйте RDP в интернет: давайте доступ через VPN или шлюз удалённых рабочих столов. Включите проверку подлинности на уровне сети (NLA), блокировку учётных записей при подборе паролей и многофакторную аутентификацию.");
            A(l, "EXP-VNC", "VNC доступен по сети", "medium", 5.5, "", "service=vnc",
              "VNC часто слабо защищён.", "Ограничьте доступ, используйте туннель.");
            A(l, "EXP-REDIS", "Redis доступен по сети", "high", 7.5, "", "service=redis",
              "Redis по умолчанию без аутентификации.", "В redis.conf задайте bind 127.0.0.1, protected-mode yes и requirepass с длинным паролем; закройте порт 6379 на межсетевом экране.");
            A(l, "EXP-MONGODB", "MongoDB доступна по сети", "high", 7.5, "", "service=mongodb",
              "Открытая БД может быть без аутентификации.", "Включите аутентификацию и ограничьте доступ.");
            A(l, "EXP-ELASTIC", "Elasticsearch доступен по сети", "high", 7.5, "", "service=elasticsearch",
              "Часто доступен без аутентификации.", "Включите security и ограничьте доступ.");
            A(l, "EXP-DOCKER", "Docker API доступен по сети", "critical", 9.8, "", "service=docker",
              "Неаутентифицированный Docker API равносилен root-доступу к хосту.", "Уберите прослушивание tcp://0.0.0.0:2375 в настройках dockerd либо включите --tlsverify с клиентскими сертификатами; закройте порт на межсетевом экране.");
            A(l, "EXP-MEMCACHED", "Memcached доступен по сети", "medium", 6.0, "", "service=memcached",
              "Утечка данных и использование в DDoS-усилении.", "Ограничьте доступ.");
            A(l, "EXP-MYSQL", "СУБД MySQL доступна по сети", "low", 3.7, "", "service=mysql",
              "Доступность СУБД из сети увеличивает поверхность атаки.", "Ограничьте доступ только доверенными адресами.");
            return l;
        }

        static int[] Ver(string v)
        {
            List<int> r = new List<int>();
            foreach (Match m in Regex.Matches(v ?? "", @"\d+"))
            {
                int n;
                if (int.TryParse(m.Value, out n)) r.Add(n);
            }
            return r.ToArray();
        }

        static int Cmp(int[] a, int[] b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++)
                if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
            return a.Length.CompareTo(b.Length);
        }

        public static List<Finding> Eval(PortInfo p)
        {
            List<Finding> res = new List<Finding>();
            foreach (Rule r in All)
            {
                string v;
                if (r.M.TryGetValue("service", out v) && v != p.Service) continue;
                if (r.M.TryGetValue("port", out v) && v != p.Port.ToString()) continue;
                if (r.M.TryGetValue("product", out v) && !v.Equals(p.Product, StringComparison.OrdinalIgnoreCase)) continue;
                bool versioned = r.M.ContainsKey("versions") || r.M.ContainsKey("version_lt") ||
                                 r.M.ContainsKey("version_lte") || r.M.ContainsKey("version_gte");
                if (versioned)
                {
                    if (p.Version == "") continue;
                    int[] pv = Ver(p.Version);
                    if (r.M.TryGetValue("versions", out v))
                    {
                        bool any = false;
                        foreach (string x in v.Split(',')) if (Cmp(pv, Ver(x)) == 0) any = true;
                        if (!any) continue;
                    }
                    if (r.M.TryGetValue("version_lt", out v) && !(Cmp(pv, Ver(v)) < 0)) continue;
                    if (r.M.TryGetValue("version_lte", out v) && !(Cmp(pv, Ver(v)) <= 0)) continue;
                    if (r.M.TryGetValue("version_gte", out v) && !(Cmp(pv, Ver(v)) >= 0)) continue;
                }
                Finding f = new Finding();
                f.Id = r.Id; f.Title = r.Title; f.Severity = r.Sev; f.Cvss = r.Cvss; f.Cve = r.Cve;
                f.Desc = r.Desc; f.Rec = r.Rec; f.Attack = r.Attack; f.Port = p.Port; f.Source = "Встроенная база NetWarden";
                f.Conf = versioned ? "probable" : "confirmed";
                f.Evidence = (p.Product + " " + p.Version).Trim();
                if (f.Evidence.Length == 0) f.Evidence = p.Banner;
                res.Add(f);
            }
            return res;
        }
    }

    // ===================== ПРОВЕРКИ =====================
    class SensItem
    {
        public string Path, Title, Sev, Conf;
        public double Cvss;
        public Func<string, bool> Test;
    }

    // ===================== ПРОВЕРКА СЛАБЫХ ПАРОЛЕЙ (ограниченный встроенный словарь) =====================
    // Используется только при включённой галочке "Слабые пароли" и только для систем, на сканирование которых есть разрешение.
    // Полноценные протоколы SSH/RDP/большинства СУБД в этой сборке не реализованы (нет сторонних библиотек) - см. README.
    static class Brute
    {
        static readonly string[,] Creds = new string[,] {
            {"admin","admin"}, {"admin","password"}, {"admin","admin123"}, {"admin",""},
            {"root","root"}, {"root","toor"}, {"root",""},
            {"administrator","administrator"}, {"administrator","password"},
            {"user","user"}, {"test","test"}, {"guest","guest"}, {"guest",""},
            {"ftp","ftp"}, {"anonymous","anonymous"}
        };

        static void Add(HostInfo h, int port, string id, string title, string user, string pass)
        {
            string masked = pass.Length <= 2 ? new string('*', pass.Length) : pass.Substring(0, 1) + new string('*', pass.Length - 2) + pass.Substring(pass.Length - 1);
            Finding f = new Finding();
            f.Id = id; f.Title = title; f.Severity = "critical"; f.Cvss = 9.8; f.Conf = "confirmed";
            f.Desc = "Подобрана пара логин/пароль из короткого встроенного словаря типовых значений. Злоумышленник, проводящий массовое сканирование интернета, находит такие сервисы за минуты той же техникой.";
            f.Rec = "Немедленно смените пароль на длинный и уникальный, включите блокировку после неудачных попыток входа, по возможности отключите учётную запись или включите многофакторную аутентификацию.";
            f.Attack = "Автоматические боты непрерывно сканируют весь интернет и перебирают именно такие типовые пары логин/пароль по всем найденным открытым сервисам; подбор занимает секунды и полностью скриптуется.";
            f.Source = "Проверка слабых паролей NetWarden";
            f.Port = port;
            f.Evidence = "логин: " + user + "  пароль: " + masked;
            lock (h.Findings) { h.Findings.Add(f); }
        }

        public static void Ftp(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 2500);
            for (int i = 0; i < Creds.GetLength(0); i++)
            {
                string user = Creds[i, 0], pass = Creds[i, 1];
                if (user == "anonymous" || user == "ftp") continue; // это отдельная проверка EXP/FTP-ANON
                bool refused;
                TcpClient c = NetUtil.Connect(h.Ip, p.Port, timeout, out refused);
                if (c == null) return;
                try
                {
                    c.ReceiveTimeout = timeout; c.SendTimeout = timeout;
                    NetworkStream ns = c.GetStream();
                    StreamReader r = new StreamReader(ns, Encoding.ASCII);
                    StreamWriter w = new StreamWriter(ns, Encoding.ASCII);
                    w.NewLine = "\r\n"; w.AutoFlush = true;
                    r.ReadLine();
                    w.WriteLine("USER " + user);
                    string resp = r.ReadLine();
                    bool ok = resp != null && resp.StartsWith("230");
                    if (resp != null && resp.StartsWith("331"))
                    {
                        w.WriteLine("PASS " + pass);
                        resp = r.ReadLine();
                        ok = resp != null && resp.StartsWith("230");
                    }
                    if (ok) { Add(h, p.Port, "WEAK-CREDS-FTP", "Слабый пароль FTP подобран по словарю", user, pass); return; }
                }
                catch (Exception) { }
                finally { c.Close(); }
            }
        }

        public static void HttpBasic(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 2500);
            int status; Dictionary<string, string> hd; string body;
            bool need;
            try { need = Web_HttpGetProbe(h.Ip, p.Port, "/", p.Tls, timeout, out status, out hd, out body) && status == 401 && hd.ContainsKey("www-authenticate") && hd["www-authenticate"].ToLower().Contains("basic"); }
            catch (Exception) { return; }
            if (!need) return;
            for (int i = 0; i < Creds.GetLength(0); i++)
            {
                string user = Creds[i, 0], pass = Creds[i, 1];
                string auth = Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass));
                try
                {
                    if (Web_HttpGetAuth(h.Ip, p.Port, "/", p.Tls, timeout, auth, out status) && status != 401)
                    { Add(h, p.Port, "WEAK-CREDS-HTTP", "Слабый пароль HTTP Basic Auth подобран по словарю", user, pass); return; }
                }
                catch (Exception) { }
            }
        }

        static bool Web_HttpGetProbe(string ip, int port, string path, bool tls, int timeout,
                                     out int status, out Dictionary<string, string> headers, out string body)
        { return Web_Http(ip, port, path, tls, timeout, null, out status, out headers, out body); }

        static bool Web_HttpGetAuth(string ip, int port, string path, bool tls, int timeout, string auth, out int status)
        {
            Dictionary<string, string> hd; string body;
            return Web_Http(ip, port, path, tls, timeout, auth, out status, out hd, out body);
        }

        static bool Web_Http(string ip, int port, string path, bool tls, int timeout, string basicAuth,
                             out int status, out Dictionary<string, string> headers, out string body)
        {
            status = 0; headers = new Dictionary<string, string>(); body = "";
            bool refused;
            TcpClient c = NetUtil.Connect(ip, port, timeout, out refused);
            if (c == null) return false;
            try
            {
                c.ReceiveTimeout = timeout; c.SendTimeout = timeout;
                Stream s = NetUtil.Open(c, tls, ip);
                string extra = basicAuth != null ? "Authorization: Basic " + basicAuth + "\r\n" : "";
                byte[] req = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: NetWarden\r\n" + extra + "Connection: close\r\n\r\n");
                s.Write(req, 0, req.Length); s.Flush();
                MemoryStream ms = new MemoryStream(); byte[] buf = new byte[4096];
                try { while (ms.Length < 16384) { int n = s.Read(buf, 0, buf.Length); if (n <= 0) break; ms.Write(buf, 0, n); } }
                catch (IOException) { }
                string all = Encoding.GetEncoding(28591).GetString(ms.ToArray());
                int idx = all.IndexOf("\r\n\r\n");
                if (idx < 0) return false;
                string head = all.Substring(0, idx);
                body = all.Substring(idx + 4);
                string[] lines = head.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                string[] st = lines[0].Split(' ');
                if (st.Length < 2 || !int.TryParse(st[1], out status)) return false;
                for (int i = 1; i < lines.Length; i++)
                {
                    int k = lines[i].IndexOf(':');
                    if (k > 0) headers[lines[i].Substring(0, k).Trim().ToLower()] = lines[i].Substring(k + 1).Trim();
                }
                return true;
            }
            catch (Exception) { return false; }
            finally { c.Close(); }
        }
    }

    static class Checks
    {
        static readonly Dictionary<string, string> Exploit = BuildExploit();
        static void M(Dictionary<string, string> d, string k, string v) { d[k] = v.Trim(); }

        static Dictionary<string, string> BuildExploit()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            M(d, "TLS-CERT-EXPIRED", "Формально это не даёт прямого доступа, но приучает пользователей нажимать 'продолжить, несмотря на предупреждение' в браузере - этим пользуются при последующей атаке 'человек посередине' с поддельным сертификатом.");
            M(d, "TLS-CERT-SOON", "Прямой угрозы нет; риск в том, что после истечения срока сертификат придётся менять в срочном порядке, а пользователи в это время будут видеть предупреждения и могут начать их игнорировать.");
            M(d, "TLS-SELF-SIGNED", "Браузер показывает предупреждение, которое приучает пользователей игнорировать такие предупреждения - это открывает путь для 'человека посередине' с поддельным сертификатом, который будет выглядеть так же 'подозрительно', как и легитимный.");
            M(d, "TLS-LEGACY-10", "Атака 'человек посередине' может принудить соединение использовать устаревший протокол (downgrade-атака) с известными слабостями шифрования (BEAST, POODLE) и затем расшифровать или подменить трафик.");
            M(d, "TLS-LEGACY-11", "Как и TLS 1.0, протокол подвержен downgrade-атакам и считается криптографически устаревшим; эксплуатация сложнее, чем TLS 1.0, но формально возможна в сочетании с другими слабостями.");
            M(d, "WEB-NO-XFO", "Злоумышленник встраивает сайт в невидимый iframe на своей странице (clickjacking) и обманом заставляет пользователя кликать по скрытым элементам - например, 'подтвердить перевод' или 'изменить email', думая, что кликает по безобидной кнопке.");
            M(d, "WEB-NO-XCTO", "Без этого заголовка некоторые старые браузеры могут 'угадывать' тип содержимого файла и исполнить как скрипт файл, загруженный как изображение (MIME-sniffing), что используется для обхода фильтров загрузки файлов.");
            M(d, "WEB-NO-HSTS", "Без HSTS первое обращение пользователя к сайту может пройти по незащищённому HTTP, и атакующий в той же сети (кафе, аэропорт) перехватывает и подменяет это соединение (SSL stripping), прежде чем произойдёт переход на HTTPS.");
            M(d, "WEB-POWERED-BY", "Раскрытая версия технологии позволяет злоумышленнику сразу подобрать точный набор публичных эксплойтов под неё, минуя этап разведки (fingerprinting).");
            M(d, "WEB-DIRLIST", "Злоумышленник просматривает структуру каталогов сайта и находит файлы, не предназначенные для публичного доступа: резервные копии (.zip, .bak), файлы конфигурации, исходный код, временные файлы с паролями.");
            M(d, "WEB-COOKIE-HTTPONLY", "Если на сайте есть хотя бы одна XSS-уязвимость, вредоносный JavaScript сможет прочитать cookie сессии через document.cookie и отправить его злоумышленнику, который использует его для входа от имени жертвы (угон сессии).");
            M(d, "WEB-EXPOSED-.GIT-HEAD", "Злоумышленник полностью скачивает репозиторий Git (инструментами вроде git-dumper) и получает исходный код приложения, включая закомментированные пароли, ключи API и историю изменений - это резко упрощает поиск других уязвимостей.");
            M(d, "WEB-EXPOSED-.ENV", "Файл .env обычно содержит пароли от базы данных, ключи API, секреты для подписи сессий. Получив его, злоумышленник напрямую подключается к внутренним системам в обход веб-приложения.");
            M(d, "WEB-EXPOSED-PHPINFO.PHP", "Страница phpinfo() раскрывает версию PHP, установленные модули, пути на сервере и иногда переменные окружения - используется для точного подбора эксплойта под конкретную конфигурацию.");
            M(d, "WEB-EXPOSED-SERVER-STATUS", "Страница показывает текущие запросы к серверу (включая внутренние IP-адреса, URL с параметрами сессий и иногда учётные данные в URL), что помогает в разведке и перехвате активных сессий.");
            M(d, "FTP-ANON", "Злоумышленник подключается без пароля и скачивает все доступные файлы; если каталог доступен на запись, туда можно загрузить вредоносные файлы (веб-шелл, если каталог виден через веб-сервер).");
            M(d, "SNMP-PUBLIC", "Через community 'public' злоумышленник читает таблицы маршрутизации, ARP, список интерфейсов, иногда версии прошивки и даже строки с паролями (на старом сетевом оборудовании) - это используется для карты сети перед целевой атакой.");
            M(d, "UPNP-SSDP", "UPnP может использоваться для автоматического открытия портов на домашнем маршрутизаторе вредоносными программами на устройствах внутри сети, а также для усиления в DDoS-атаках (SSDP amplification), аналогично SNMP.");
            M(d, "WEB-TRACE-ENABLED", "В сочетании с XSS-уязвимостью на том же сайте (или на другом сайте того же домена) метод TRACE позволяет обойти защиту HttpOnly и прочитать cookie сессии через технику Cross-Site Tracing.");
            M(d, "WEB-SQLI-SUSPECT", "При подтверждении SQL-инъекция позволяет обходить аутентификацию, читать и изменять любые данные в базе, а на некоторых СУБД (MySQL с правами FILE, MSSQL с xp_cmdshell) - читать файлы сервера или выполнять команды ОС.");
            M(d, "WEB-XSS-REFLECTED", "Злоумышленник отправляет жертве ссылку с вредоносным кодом в параметре; при переходе код выполняется в браузере жертвы от имени сайта - крадёт сессию, перенаправляет на фишинговую страницу или действует от имени жертвы (смена пароля, перевод средств).");
            M(d, "WEB-PATH-DISCLOSURE", "Раскрытые пути и трассировка стека показывают структуру сервера, используемые библиотеки и их версии - злоумышленник использует это для точного подбора эксплойтов и для построения дальнейших payload'ов для обхода пути.");
            M(d, "SMB-V1-ENABLED", "Червь вроде WannaCry или эксплойт EternalBlue подключается к порту 445, использует ошибку именно в обработке пакетов SMBv1 и выполняет код с правами системы без какого-либо пароля - просто за счёт того, что компьютер отвечает на этом устаревшем протоколе. Заражение одного компьютера в локальной сети обычно быстро распространяется на остальные хосты с открытым SMBv1.");
            M(d, "SMB-OPEN-MODERN", "Прямой уязвимости здесь нет: современный SMB2/3 не содержит известных дистанционных эксплойтов уровня EternalBlue. Практический вектор атаки - подбор пароля учётной записи Windows или использование уже украденных где-то credentials, поэтому основная защита - сложные пароли и ограничение сети, а не закрытие порта.");
            M(d, "SMB-OPEN-UNKNOWN", "Пока версия протокола не подтверждена, нельзя исключить, что сервер всё же отвечает по SMBv1 на запросы в другом формате (нестандартная реализация). Рекомендуется проверить вручную, не полагаясь только на этот результат.");
            return d;
        }

        static string ExploitFor(string id)
        {
            string ex;
            if (Exploit.TryGetValue(id, out ex)) return ex;
            foreach (string k in Exploit.Keys) if (id.StartsWith(k)) return Exploit[k];
            return "";
        }

        static void Add(HostInfo h, int port, string id, string title, string sev, double cvss, string conf, string desc, string rec, string ev)
        {
            Finding f = new Finding();
            f.Id = id; f.Title = title; f.Severity = sev; f.Cvss = cvss; f.Conf = conf;
            f.Desc = desc; f.Rec = rec; f.Evidence = ev; f.Port = port;
            f.Attack = ExploitFor(id); f.Source = "Встроенная база NetWarden";
            lock (h.Findings) { h.Findings.Add(f); }
        }

        public static void Run(HostInfo h, int timeout)
        {
            foreach (PortInfo p in h.Ports)
                if (p.Proto == "tcp") lock (h.Findings) { h.Findings.AddRange(Rules.Eval(p)); }
            foreach (PortInfo p in h.Ports)
            {
                try
                {
                    if (p.Proto == "udp")
                    {
                        if (p.Service == "snmp")
                            Add(h, p.Port, "SNMP-PUBLIC", "SNMP отвечает на community по умолчанию 'public'", "high", 7.5, "confirmed",
                                "Любой в сети может читать данные устройства (конфигурацию, таблицы маршрутов, имена, иногда пароли).",
                                "Отключите SNMP v1/v2c или смените community на длинное секретное значение; используйте SNMPv3 с аутентификацией и шифрованием; ограничьте доступ списком разрешённых адресов.", p.Banner);
                        if (p.Service == "ssdp")
                            Add(h, p.Port, "UPNP-SSDP", "Устройство отвечает по UPnP (SSDP)", "low", 3.1, "confirmed",
                                "UPnP позволяет программам менять настройки сети, а устройство раскрывает сведения о себе.",
                                "Отключите UPnP на маршрутизаторе и устройствах, если он не нужен; не открывайте UPnP во внешнюю сеть.", p.Banner);
                        continue;
                    }
                    if (p.Tls) Tls(h, p, timeout);
                    if (p.Service == "http" || p.Service == "https") { Web(h, p, timeout); Heuristics(h, p, timeout); }
                    if (p.Service == "ftp") Ftp(h, p, timeout);
                    if (p.Port == 445 && p.Proto == "tcp") Smb(h, p, timeout);
                }
                catch (Exception) { }
            }
            if (bruteEnabled)
                foreach (PortInfo p in h.Ports)
                {
                    try
                    {
                        if (p.Service == "ftp") Brute.Ftp(h, p, timeout);
                        if (p.Service == "http" || p.Service == "https") Brute.HttpBasic(h, p, timeout);
                    }
                    catch (Exception) { }
                }
        }

        [ThreadStatic] static bool bruteEnabledTls; // не используется, зарезервировано
        static bool bruteEnabled;
        public static void Run(HostInfo h, int timeout, bool brute) { bruteEnabled = brute; Run(h, timeout); }

        // ---- TLS ----
        static bool TryProto(string ip, int port, SslProtocols proto, int timeout)
        {
            bool refused;
            TcpClient c = NetUtil.Connect(ip, port, timeout, out refused);
            if (c == null) return false;
            try
            {
                c.ReceiveTimeout = timeout;
                c.SendTimeout = timeout;
                SslStream ss = new SslStream(c.GetStream(), false, new RemoteCertificateValidationCallback(NetUtil.AcceptAll));
                ss.AuthenticateAsClient(ip, null, proto, false);
                return true;
            }
            catch (Exception) { return false; }
            finally { c.Close(); }
        }

        static void Tls(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 3000);
            bool refused;
            TcpClient c = NetUtil.Connect(h.Ip, p.Port, timeout, out refused);
            if (c != null)
            {
                try
                {
                    c.ReceiveTimeout = timeout;
                    c.SendTimeout = timeout;
                    SslStream ss = new SslStream(c.GetStream(), false, new RemoteCertificateValidationCallback(NetUtil.AcceptAll));
                    ss.AuthenticateAsClient(h.Ip);
                    X509Certificate2 cert = new X509Certificate2(ss.RemoteCertificate);
                    double days = (cert.NotAfter - DateTime.Now).TotalDays;
                    string ev = "notAfter=" + cert.NotAfter.ToString("yyyy-MM-dd");
                    if (days < 0)
                        Add(h, p.Port, "TLS-CERT-EXPIRED", "Срок действия TLS-сертификата истёк", "high", 7.0, "confirmed",
                            "Клиенты не будут доверять сертификату.", "Перевыпустите сертификат.", ev);
                    else if (days < 30)
                        Add(h, p.Port, "TLS-CERT-SOON", "TLS-сертификат истекает через " + (int)days + " дн.", "low", 0, "confirmed",
                            "", "Запланируйте перевыпуск сертификата.", ev);
                    if (cert.Subject == cert.Issuer)
                        Add(h, p.Port, "TLS-SELF-SIGNED", "Самоподписанный TLS-сертификат", "low", 3.1, "confirmed",
                            "Сертификат не подписан доверенным удостоверяющим центром.", "Используйте сертификат доверенного УЦ.", cert.Subject);
                }
                catch (Exception) { }
                finally { c.Close(); }
            }
            if (TryProto(h.Ip, p.Port, SslProtocols.Tls, timeout))
                Add(h, p.Port, "TLS-LEGACY-10", "Поддерживается устаревший протокол TLS 1.0", "medium", 5.9, "confirmed",
                    "Протокол считается небезопасным (RFC 8996).", "Оставьте только TLS 1.2/1.3. nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; Windows и IIS: отключите TLS 1.0/1.1 в SCHANNEL (реестр или утилита IIS Crypto).", "");
            if (TryProto(h.Ip, p.Port, SslProtocols.Tls11, timeout))
                Add(h, p.Port, "TLS-LEGACY-11", "Поддерживается устаревший протокол TLS 1.1", "medium", 5.9, "confirmed",
                    "Протокол считается небезопасным (RFC 8996).", "Оставьте только TLS 1.2/1.3. nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; Windows и IIS: отключите TLS 1.0/1.1 в SCHANNEL (реестр или утилита IIS Crypto).", "");
        }


        // ---- ЭВРИСТИКА: нестандартные запросы, пассивные признаки SQLi/XSS, раскрытие путей ----
        static readonly string[] SqlErrMarkers = new string[] {
            "sql syntax", "mysql_fetch", "mysqli_", "you have an error in your sql",
            "odbc sql server driver", "sqlstate", "unclosed quotation mark", "pg_query",
            "postgresql.*error", "sqlite3.operationalerror", "ora-01756", "microsoft ole db provider for odbc" };
        static readonly string[] PathMarkers = new string[] {
            "c:\\\\inetpub", "c:\\\\windows", "c:\\\\users", "c:\\\\xampp", "/var/www", "/home/", "/etc/passwd",
            "stack trace", "fatal error:", "warning: include", "at System.", "in /usr/", "traceback (most recent" };
        const string XssMarker = "<svg/onload=NwXss163>";

        static bool ContainsAny(string hay, string[] needles)
        {
            foreach (string n in needles) if (Regex.IsMatch(hay, n, RegexOptions.IgnoreCase)) return true;
            return false;
        }

        static void Heuristics(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 3000);
            int st; Dictionary<string, string> hd; string body;

            // 1) TRACE / Cross-Site Tracing
            try
            {
                if (HttpGet(h.Ip, p.Port, "/", p.Tls, timeout, out st, out hd, out body, "TRACE") && st == 200 &&
                    (body.IndexOf("TRACE /", StringComparison.OrdinalIgnoreCase) >= 0 || (hd.ContainsKey("content-length") && hd["content-length"] != "0")))
                    Add(h, p.Port, "WEB-TRACE-ENABLED", "Включён метод HTTP TRACE (Cross-Site Tracing)", "low", 4.3, "confirmed",
                        "Метод TRACE отражает заголовки запроса в ответе и в сочетании с XSS на другой странице может использоваться для кражи куки, недоступных для JavaScript (обход HttpOnly).",
                        "Отключите метод TRACE. Apache: TraceEnable off; IIS: установите URLScan/Request Filtering и запретите verb TRACE; nginx по умолчанию TRACE не поддерживает дальше проксирования - проверьте бэкенд.", "");
            }
            catch (Exception) { }

            // 2) пассивный признак SQL-инъекции: одиночная кавычка в параметре
            try
            {
                if (HttpGet(h.Ip, p.Port, "/?id=1%27", p.Tls, timeout, out st, out hd, out body) && ContainsAny(body, SqlErrMarkers))
                    Add(h, p.Port, "WEB-SQLI-SUSPECT", "Признак возможной SQL-инъекции (ошибка СУБД в ответе)", "high", 8.2, "probable",
                        "Одиночная кавычка в параметре запроса вызвала в ответе текст, похожий на ошибку базы данных. Это пассивный тест без подтверждения - возможна SQL-инъекция, либо просто отображается необработанное исключение.",
                        "Используйте параметризованные запросы (prepared statements) вместо конкатенации строк в SQL; отключите вывод подробных ошибок СУБД пользователю (производственный режим приложения); проверьте находку вручную инструментом класса sqlmap на выделенном тестовом стенде.", "");
            }
            catch (Exception) { }

            // 3) отражённый XSS: маркер без экранирования
            try
            {
                string path = "/?q=" + Uri.EscapeDataString(XssMarker);
                if (HttpGet(h.Ip, p.Port, path, p.Tls, timeout, out st, out hd, out body) && body.Contains(XssMarker))
                    Add(h, p.Port, "WEB-XSS-REFLECTED", "Отражённый межсайтовый скриптинг (XSS) в параметре запроса", "high", 7.4, "confirmed",
                        "Безопасный тестовый маркер, переданный в параметре q, вернулся в теле страницы без HTML-экранирования. Реальная полезная нагрузка на этом месте выполнилась бы в браузере жертвы по присланной ссылке.",
                        "Экранируйте пользовательский ввод при выводе в HTML (HtmlEncode / функции шаблонизатора с автоэкранированием), добавьте заголовок Content-Security-Policy, используйте HttpOnly для куки сессии.", "параметр q, путь " + path);
            }
            catch (Exception) { }

            // 4) раскрытие путей/трассировки через заведомо отсутствующую страницу
            try
            {
                if (HttpGet(h.Ip, p.Port, "/NwMissing_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".aspx", p.Tls, timeout, out st, out hd, out body) &&
                    ContainsAny(body, PathMarkers))
                    Add(h, p.Port, "WEB-PATH-DISCLOSURE", "Раскрытие путей файловой системы / трассировки стека в странице ошибки", "medium", 5.3, "probable",
                        "Страница ошибки показывает внутренние пути сервера или трассировку стека. Это помогает злоумышленнику понять структуру сервера, используемый стек технологий и версии компонентов для подбора точных эксплойтов.",
                        "Включите производственный режим с общими страницами ошибок (ASP.NET: customErrors mode=\"On\"; PHP: display_errors=Off и log_errors=On; Django: DEBUG=False). Подробности ошибок пишите только в серверный журнал.", "");
            }
            catch (Exception) { }
        }

        // ---- WEB ----
        static bool HttpGet(string ip, int port, string path, bool tls, int timeout,
                            out int status, out Dictionary<string, string> headers, out string body)
        { return HttpGet(ip, port, path, tls, timeout, out status, out headers, out body, "GET"); }

        static bool HttpGet(string ip, int port, string path, bool tls, int timeout,
                            out int status, out Dictionary<string, string> headers, out string body, string method)
        {
            status = 0;
            headers = new Dictionary<string, string>();
            body = "";
            bool refused;
            TcpClient c = NetUtil.Connect(ip, port, timeout, out refused);
            if (c == null) return false;
            try
            {
                c.ReceiveTimeout = timeout;
                c.SendTimeout = timeout;
                Stream s = NetUtil.Open(c, tls, ip);
                byte[] req = Encoding.ASCII.GetBytes(method + " " + path + " HTTP/1.1\r\nHost: " + ip +
                    "\r\nUser-Agent: NetWarden\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                s.Write(req, 0, req.Length);
                s.Flush();
                MemoryStream ms = new MemoryStream();
                byte[] buf = new byte[8192];
                try
                {
                    while (ms.Length < 32768)
                    {
                        int n = s.Read(buf, 0, buf.Length);
                        if (n <= 0) break;
                        ms.Write(buf, 0, n);
                    }
                }
                catch (IOException) { }
                string all = Encoding.GetEncoding(28591).GetString(ms.ToArray());
                int idx = all.IndexOf("\r\n\r\n");
                if (idx < 0) return false;
                string head = all.Substring(0, idx);
                body = all.Substring(idx + 4);
                string[] lines = head.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                string[] st = lines[0].Split(' ');
                if (st.Length < 2 || !int.TryParse(st[1], out status)) return false;
                for (int i = 1; i < lines.Length; i++)
                {
                    int k = lines[i].IndexOf(':');
                    if (k > 0) headers[lines[i].Substring(0, k).Trim().ToLower()] = lines[i].Substring(k + 1).Trim();
                }
                return true;
            }
            catch (Exception) { return false; }
            finally { c.Close(); }
        }

        static readonly List<SensItem> Sens = new List<SensItem>
        {
            new SensItem { Path = "/.git/HEAD", Title = "Открыт каталог .git (исходный код)", Sev = "high", Cvss = 7.5, Conf = "confirmed",
                Test = delegate(string b) { return b.StartsWith("ref:"); } },
            new SensItem { Path = "/.env", Title = "Возможно доступен файл .env (секреты)", Sev = "critical", Cvss = 9.1, Conf = "probable",
                Test = delegate(string b) { return b.Contains("=") && !b.Substring(0, Math.Min(200, b.Length)).ToLower().Contains("<html"); } },
            new SensItem { Path = "/phpinfo.php", Title = "Доступна страница phpinfo()", Sev = "medium", Cvss = 5.3, Conf = "confirmed",
                Test = delegate(string b) { return b.Contains("phpinfo()"); } },
            new SensItem { Path = "/server-status", Title = "Открыт Apache server-status", Sev = "medium", Cvss = 5.3, Conf = "confirmed",
                Test = delegate(string b) { return b.Contains("Apache Server Status"); } },
            new SensItem { Path = "/.DS_Store", Title = "Доступен файл .DS_Store", Sev = "low", Cvss = 3.1, Conf = "confirmed",
                Test = delegate(string b) { return b.StartsWith("\0\0\0\u0001Bud1"); } }
        };

        static void Web(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 3000);
            int status;
            Dictionary<string, string> hd;
            string body;
            if (!HttpGet(h.Ip, p.Port, "/", p.Tls, timeout, out status, out hd, out body)) return;
            string v;
            if (!hd.ContainsKey("x-frame-options") &&
                !(hd.TryGetValue("content-security-policy", out v) && v.Contains("frame-ancestors")))
                Add(h, p.Port, "WEB-NO-XFO", "Нет защиты от clickjacking (X-Frame-Options / CSP frame-ancestors)", "low", 3.1, "confirmed",
                    "", "Добавьте заголовок X-Frame-Options: DENY или CSP frame-ancestors. nginx: add_header X-Frame-Options DENY always; Apache: Header always set X-Frame-Options DENY; IIS: раздел customHeaders в web.config.", "");
            if (!hd.ContainsKey("x-content-type-options"))
                Add(h, p.Port, "WEB-NO-XCTO", "Нет заголовка X-Content-Type-Options", "info", 0, "confirmed",
                    "", "Добавьте X-Content-Type-Options: nosniff.", "");
            if (p.Tls && !hd.ContainsKey("strict-transport-security"))
                Add(h, p.Port, "WEB-NO-HSTS", "Нет заголовка HSTS", "low", 3.1, "confirmed",
                    "", "Добавьте заголовок Strict-Transport-Security. nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;", "");
            if (hd.TryGetValue("x-powered-by", out v))
                Add(h, p.Port, "WEB-POWERED-BY", "Раскрытие технологии через X-Powered-By", "info", 0, "confirmed",
                    "", "Уберите заголовок.", v);
            if (body.Contains("<title>Index of /") || body.Contains("<h1>Index of /"))
                Add(h, p.Port, "WEB-DIRLIST", "Включён листинг каталогов", "medium", 5.3, "confirmed",
                    "", "Отключите листинг каталогов. nginx: autoindex off; Apache: Options -Indexes; IIS: выключите Directory Browsing.", "");
            if (hd.TryGetValue("set-cookie", out v) && !v.ToLower().Contains("httponly"))
                Add(h, p.Port, "WEB-COOKIE-HTTPONLY", "Cookie без флага HttpOnly", "low", 3.1, "confirmed",
                    "", "Установите флаг HttpOnly.", "");
            foreach (SensItem it in Sens)
            {
                int st2;
                Dictionary<string, string> h2;
                string b2;
                if (HttpGet(h.Ip, p.Port, it.Path, p.Tls, timeout, out st2, out h2, out b2) && st2 == 200 && it.Test(b2))
                    Add(h, p.Port, "WEB-EXPOSED" + it.Path.ToUpper().Replace("/", "-"), it.Title, it.Sev, it.Cvss, it.Conf,
                        "", "Удалите файл с рабочего сервера или запретите доступ к нему (nginx: location ~ /[.] { deny all; }). Если в файле были пароли или ключи - считайте их скомпрометированными и смените.", it.Path);
            }
        }

        // ---- FTP ----
        static string FtpResp(StreamReader r)
        {
            string line = r.ReadLine();
            while (line != null && line.Length >= 4 && line[3] == '-') line = r.ReadLine();
            return line;
        }

        static void Ftp(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 3000);
            bool refused;
            TcpClient c = NetUtil.Connect(h.Ip, p.Port, timeout, out refused);
            if (c == null) return;
            try
            {
                c.ReceiveTimeout = timeout;
                c.SendTimeout = timeout;
                NetworkStream ns = c.GetStream();
                StreamReader r = new StreamReader(ns, Encoding.ASCII);
                StreamWriter w = new StreamWriter(ns, Encoding.ASCII);
                w.NewLine = "\r\n";
                w.AutoFlush = true;
                FtpResp(r);
                w.WriteLine("USER anonymous");
                string resp = FtpResp(r);
                bool ok = resp != null && resp.StartsWith("230");
                if (resp != null && resp.StartsWith("331"))
                {
                    w.WriteLine("PASS audit@example.com");
                    string r2 = FtpResp(r);
                    ok = r2 != null && r2.StartsWith("230");
                }
                if (ok)
                    Add(h, p.Port, "FTP-ANON", "FTP разрешает анонимный вход", "medium", 5.3, "confirmed",
                        "Анонимные пользователи могут получить доступ к файлам.", "Отключите анонимный вход. vsftpd: anonymous_enable=NO; IIS FTP: отключите Anonymous authentication; перезапустите службу.", "");
            }
            catch (Exception) { }
            finally { c.Close(); }
        }

        // ---- SMB: настоящая проверка версии протокола (а не просто "порт открыт") ----
        // Отправляем SMB1 Negotiate Request, в котором перечислены ТОЛЬКО диалекты SMBv1 (без строк,
        // переключающих на SMB2/3). Если сервер отвечает валидным DialectIndex - он реально умеет SMBv1,
        // это настоящая уязвимость (EternalBlue/WannaCry). Если отвечает "нет подходящего диалекта" (0xFFFF)
        // или не отвечает в этом формате вовсе - SMBv1 отключён, порт 445 при этом может оставаться открытым
        // совершенно законно (например, для общих папок по SMB2/3), и находка создаваться не должна.
        static readonly string[] Smb1OnlyDialects = new string[] {
            "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1", "NT LM 0.12"
        };

        static byte[] BuildSmb1Negotiate(string[] dialects)
        {
            List<byte> dl = new List<byte>();
            foreach (string d in dialects) { dl.Add(0x02); dl.AddRange(Encoding.ASCII.GetBytes(d)); dl.Add(0x00); }
            byte[] bc = dl.ToArray();
            List<byte> smb = new List<byte>();
            smb.Add(0xFF); smb.Add((byte)'S'); smb.Add((byte)'M'); smb.Add((byte)'B');
            smb.Add(0x72);                                   // команда: Negotiate
            smb.AddRange(new byte[] { 0, 0, 0, 0 });          // статус
            smb.Add(0x18);                                    // флаги
            smb.AddRange(new byte[] { 0x00, 0x00 });          // флаги2
            smb.AddRange(new byte[] { 0x00, 0x00 });          // PID High
            smb.AddRange(new byte[8]);                        // security features
            smb.AddRange(new byte[] { 0x00, 0x00 });          // reserved
            smb.AddRange(new byte[] { 0xFF, 0xFF });          // TID
            smb.AddRange(new byte[] { 0xFE, 0xFF });          // PID Low
            smb.AddRange(new byte[] { 0x00, 0x00 });          // UID
            smb.AddRange(new byte[] { 0x00, 0x00 });          // MID
            smb.Add(0x00);                                    // WordCount
            smb.Add((byte)(bc.Length & 0xFF));
            smb.Add((byte)((bc.Length >> 8) & 0xFF));          // ByteCount (LE)
            smb.AddRange(bc);
            byte[] payload = smb.ToArray();
            byte[] packet = new byte[4 + payload.Length];
            packet[0] = 0x00;
            packet[1] = (byte)((payload.Length >> 16) & 0xFF);
            packet[2] = (byte)((payload.Length >> 8) & 0xFF);
            packet[3] = (byte)(payload.Length & 0xFF);
            Array.Copy(payload, 0, packet, 4, payload.Length);
            return packet;
        }

        static int ReadExact(NetworkStream ns, byte[] buf, int count)
        {
            int off = 0;
            try { while (off < count) { int n = ns.Read(buf, off, count - off); if (n <= 0) break; off += n; } }
            catch (Exception) { }
            return off;
        }

        static void Smb(HostInfo h, PortInfo p, int timeout)
        {
            timeout = Math.Max(timeout, 3000);
            bool refused;
            TcpClient c = NetUtil.Connect(h.Ip, p.Port, timeout, out refused);
            if (c == null) return;
            bool smb1 = false, detected = false;
            try
            {
                c.ReceiveTimeout = timeout; c.SendTimeout = timeout;
                NetworkStream ns = c.GetStream();
                byte[] req = BuildSmb1Negotiate(Smb1OnlyDialects);
                ns.Write(req, 0, req.Length); ns.Flush();
                byte[] hdr = new byte[4];
                if (ReadExact(ns, hdr, 4) == 4 && hdr[0] == 0x00)
                {
                    int len = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
                    if (len > 0 && len < 65536)
                    {
                        byte[] body = new byte[len];
                        if (ReadExact(ns, body, len) == len && body.Length >= 35 &&
                            body[0] == 0xFF && body[1] == (byte)'S' && body[2] == (byte)'M' && body[3] == (byte)'B')
                        {
                            detected = true;
                            int dialectIndex = body[33] | (body[34] << 8);
                            smb1 = dialectIndex != 0xFFFF && dialectIndex < Smb1OnlyDialects.Length;
                        }
                    }
                }
            }
            catch (Exception) { }
            finally { c.Close(); }

            if (smb1)
                Add(h, p.Port, "SMB-V1-ENABLED", "Включён устаревший протокол SMBv1", "critical", 9.8, "confirmed",
                    "Проверка по протоколу подтвердила: сервер согласился работать по SMBv1 образца 1990-х годов. Именно через уязвимости в SMBv1 (в частности EternalBlue) распространялись черви WannaCry и NotPetya.",
                    "Отключите только SMBv1 - это НЕ закрывает порт 445 и НЕ отключает общий доступ к файлам/принтерам; современные Windows, macOS и Linux подключаются по SMB2/3 без каких-либо изменений для пользователей. PowerShell от администратора: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force. Дополнительно: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart. Подробности - в кнопке \"Исправить\".", "");
            else if (detected)
                Add(h, p.Port, "SMB-OPEN-MODERN", "SMB доступен по сети (работает только современный SMB2/3, SMBv1 отключён)", "info", 0, "confirmed",
                    "Порт 445 открыт - это ожидаемо и нормально, если в сети используется общий доступ к файлам или принтерам. Проверка по протоколу показала, что сервер НЕ согласился работать по устаревшему SMBv1, то есть главный исторический риск (EternalBlue/WannaCry) для этого хоста неактуален.",
                    "Специальных действий не требуется. Дополнительно для усиления защиты можно включить обязательное подписывание пакетов: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force, и использовать длинные пароли учётных записей Windows.", "");
            else
                Add(h, p.Port, "SMB-OPEN-UNKNOWN", "SMB доступен по сети (версию протокола определить не удалось)", "low", 2.0, "probable",
                    "Порт 445 открыт, но сервер не ответил на тестовый запрос согласования протокола в ожидаемом формате (нестандартная реализация SMB, таймаут или фильтрация пакетов). Поддержка SMBv1 не подтверждена, но и не исключена.",
                    "Проверьте вручную на самом компьютере (PowerShell от администратора): Get-SmbServerConfiguration | Select EnableSMB1Protocol. Если выводится True - отключите: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force. Порт 445 при этом должен оставаться открытым, пока нужен общий доступ к файлам.", "");
        }
    }

    // ===================== ДВИЖОК СКАНИРОВАНИЯ =====================
    // ===================== ЛОКАЛЬНАЯ СЕТЬ, ARP, MAC =====================
    class LocalNet { public long Ip, Mask, Net; public int Prefix; }

    static class LocalNets
    {
        static List<LocalNet> cache;

        public static List<LocalNet> All()
        {
            if (cache != null) return cache;
            List<LocalNet> l = new List<LocalNet>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask == null) continue;
                        string ip = ua.Address.ToString();
                        if (ip.StartsWith("169.254.")) continue;
                        LocalNet n = new LocalNet();
                        n.Ip = Targets.ToUInt(ip);
                        n.Mask = Targets.ToUInt(ua.IPv4Mask.ToString());
                        n.Net = n.Ip & n.Mask;
                        int bits = 0;
                        for (long m = n.Mask; (m & 0x80000000L) != 0; m = (m << 1) & 0xFFFFFFFFL) bits++;
                        n.Prefix = bits;
                        l.Add(n);
                    }
                }
            }
            catch (Exception) { }
            cache = l;
            return l;
        }

        public static bool IsLocal(string ip)
        {
            long v = Targets.ToUInt(ip);
            foreach (LocalNet n in All()) if ((v & n.Mask) == n.Net) return true;
            return false;
        }

        public static bool IsOwnIp(string ip)
        {
            if (ip.StartsWith("127.")) return true;
            long v = Targets.ToUInt(ip);
            foreach (LocalNet n in All()) if (n.Ip == v) return true;
            return false;
        }

        public static string DefaultCidr()
        {
            foreach (LocalNet n in All())
            {
                if (n.Prefix < 8 || n.Prefix > 30) continue;
                int pr = n.Prefix < 22 ? 24 : n.Prefix;
                long mask = (0xFFFFFFFFL << (32 - pr)) & 0xFFFFFFFFL;
                return Targets.ToIp(n.Ip & mask) + "/" + pr;
            }
            return "192.168.1.0/24";
        }
    }

    static class Arp
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int destIp, int srcIp, byte[] mac, ref int macLen);

        public static string Resolve(string ip)
        {
            try
            {
                byte[] mac = new byte[6];
                int len = 6;
                int dest = BitConverter.ToInt32(IPAddress.Parse(ip).GetAddressBytes(), 0);
                if (SendARP(dest, 0, mac, ref len) != 0 || len < 6) return "";
                string s = BitConverter.ToString(mac, 0, 6).Replace('-', ':');
                return s == "00:00:00:00:00:00" ? "" : s;
            }
            catch (Exception) { return ""; }
        }
    }

    // Запись о производителе по префиксу MAC (OUI): короткое имя для таблиц, полное имя и страна
    // регистрации (по данным IEEE, приблизительно), и типичная категория устройства с этим префиксом.
    class OuiInfo
    {
        public string Vendor, Full, Country, Category;
        public OuiInfo(string vendor, string full, string country, string category)
        { Vendor = vendor; Full = full; Country = country; Category = category; }
    }

    static class Oui
    {
        static Dictionary<string, OuiInfo> db;
        static readonly object Sync = new object();

        static void Add(string prefix, string vendor, string full, string country, string category)
        { db[prefix] = new OuiInfo(vendor, full, country, category); }

        static void Init()
        {
            lock (Sync)
            {
                if (db != null) return;
                db = new Dictionary<string, OuiInfo>();

                // ---- виртуализация ----
                foreach (string p in new[] { "000C29", "005056", "000569", "001C14" })
                    Add(p, "VMware", "VMware, Inc.", "США", "виртуальная машина (VMware ESXi/Workstation)");
                Add("00155D", "Hyper-V", "Microsoft Corporation", "США", "виртуальная машина (Hyper-V)");
                Add("080027", "VirtualBox", "Oracle Corporation", "США", "виртуальная машина (Oracle VirtualBox)");
                Add("525400", "QEMU/KVM", "QEMU/KVM (открытый проект)", "международный", "виртуальная машина (QEMU/KVM)");
                Add("001C42", "Parallels", "Parallels International", "США", "виртуальная машина (Parallels Desktop, обычно на Mac)");

                // ---- одноплатные компьютеры / IoT ----
                foreach (string p in new[] { "B827EB", "DCA632", "E45F01", "D83ADD", "2CCF67" })
                    Add(p, "Raspberry Pi", "Raspberry Pi Foundation / Trading Ltd.", "Великобритания", "одноплатный компьютер Raspberry Pi");
                Add("A4CF12", "Espressif", "Espressif Systems", "Китай", "IoT-модуль Wi-Fi (ESP8266/ESP32) - умная розетка, датчик и т.п.");
                Add("246F28", "Espressif", "Espressif Systems", "Китай", "IoT-модуль Wi-Fi (ESP8266/ESP32) - умная розетка, датчик и т.п.");
                Add("18FE34", "Espressif", "Espressif Systems", "Китай", "IoT-модуль Wi-Fi (ESP8266/ESP32) - умная розетка, датчик и т.п.");

                // ---- сетевое оборудование ----
                Add("00000C", "Cisco", "Cisco Systems, Inc.", "США", "сетевое оборудование Cisco (коммутатор/маршрутизатор)");
                Add("002722", "Ubiquiti", "Ubiquiti Inc.", "США", "точка доступа/маршрутизатор Ubiquiti (UniFi)");
                foreach (string p in new[] { "24A43C", "44D9E7", "FCECDA" })
                    Add(p, "Ubiquiti", "Ubiquiti Inc.", "США", "точка доступа/маршрутизатор Ubiquiti (UniFi)");
                foreach (string p in new[] { "000C42", "4C5E0C", "B869F4", "E48D8C" })
                    Add(p, "MikroTik", "Mikrotikls SIA", "Латвия", "маршрутизатор/коммутатор MikroTik (RouterOS)");
                foreach (string p in new[] { "001D0F", "50C7BF", "14CC20", "EC086B" })
                    Add(p, "TP-Link", "TP-Link Technologies", "Китай", "бытовой Wi-Fi роутер или устройство TP-Link");
                foreach (string p in new[] { "000FB5", "00095B", "001F33" })
                    Add(p, "Netgear", "NETGEAR, Inc.", "США", "сетевое оборудование Netgear (роутер/коммутатор)");
                foreach (string p in new[] { "001E58", "0050BA", "00179A", "000D88" })
                    Add(p, "D-Link", "D-Link Corporation", "Тайвань", "сетевое оборудование D-Link (роутер/камера/коммутатор)");
                Add("A0F3C1", "ASUS", "ASUSTeK Computer Inc.", "Тайвань", "роутер или компьютер ASUS");
                Add("1C872C", "ASUS", "ASUSTeK Computer Inc.", "Тайвань", "роутер или компьютер ASUS");
                Add("B0B98A", "Zyxel", "Zyxel Communications", "Тайвань", "сетевое оборудование Zyxel (роутер/модем)");

                // ---- компьютеры, ОС, комплектующие ----
                Add("0050F2", "Microsoft", "Microsoft Corporation", "США", "устройство/адаптер Microsoft (ПК, Surface, Xbox)");
                Add("00E04C", "Realtek", "Realtek Semiconductor", "Тайвань", "сетевой адаптер на чипе Realtek (обычно ПК/ноутбук)");
                Add("001B21", "Intel", "Intel Corporation", "США", "сетевой адаптер Intel (обычно ПК/ноутбук/сервер)");
                foreach (string p in new[] { "001422", "001AA0" })
                    Add(p, "Dell", "Dell Inc.", "США", "компьютер или сервер Dell");
                Add("3417EB", "Lenovo", "Lenovo Group", "Китай", "компьютер или ноутбук Lenovo");
                Add("D43D7E", "HP", "HP Inc.", "США", "компьютер или принтер HP");

                // ---- NAS / хранилища ----
                Add("001132", "Synology", "Synology Inc.", "Тайвань", "сетевое хранилище (NAS) Synology");
                Add("245EBE", "QNAP", "QNAP Systems, Inc.", "Тайвань", "сетевое хранилище (NAS) QNAP");

                // ---- смартфоны, ноутбуки, умный дом ----
                foreach (string p in new[] { "001B63", "000393", "0017F2", "F01898" })
                    Add(p, "Apple", "Apple Inc.", "США", "устройство Apple (iPhone, iPad или Mac)");
                foreach (string p in new[] { "3C5AB4", "F4F5D8" })
                    Add(p, "Google", "Google LLC", "США", "устройство Google (Chromecast, Nest, Android-телефон)");
                Add("4CE676", "Samsung", "Samsung Electronics", "Республика Корея", "устройство Samsung (телефон или телевизор)");
                Add("8C7967", "Samsung", "Samsung Electronics", "Республика Корея", "устройство Samsung (телефон или телевизор)");
                Add("6CADF8", "Xiaomi", "Xiaomi Communications", "Китай", "устройство Xiaomi (телефон или умный дом)");
                Add("34CE00", "Huawei", "Huawei Technologies", "Китай", "устройство Huawei");
                Add("4CB199", "Amazon", "Amazon Technologies", "США", "устройство Amazon (Echo, Fire TV, Kindle)");
                Add("68FB7E", "Sonos", "Sonos, Inc.", "США", "беспроводная колонка Sonos");
                Add("B8E937", "Roku", "Roku, Inc.", "США", "медиаплеер Roku");

                // ---- IP-камеры видеонаблюдения ----
                Add("4C11BF", "Hikvision", "Hangzhou Hikvision", "Китай", "IP-камера видеонаблюдения Hikvision");
                Add("8CE748", "Hikvision", "Hangzhou Hikvision", "Китай", "IP-камера видеонаблюдения Hikvision");
                Add("00124B", "Dahua", "Zhejiang Dahua Technology", "Китай", "IP-камера видеонаблюдения Dahua");

                // ---- принтеры ----
                Add("3063C4", "Brother", "Brother Industries", "Япония", "сетевой принтер Brother");
                Add("5C7297", "Epson", "Seiko Epson Corporation", "Япония", "сетевой принтер Epson");
                Add("0080F0", "Canon", "Canon Inc.", "Япония", "сетевой принтер Canon");

                // пользовательская база: %APPDATA%\NetWarden\oui.txt, строки "AABBCC Название производителя"
                // (для таких записей полное название и страна совпадают с коротким именем - своих категорий нет)
                try
                {
                    string f = Path.Combine(AppPaths.DataDir(), "oui.txt");
                    if (File.Exists(f))
                        foreach (string line in File.ReadAllLines(f, Encoding.UTF8))
                        {
                            string l = line.Trim().Replace(":", "").Replace("-", "");
                            if (l.Length > 7)
                            {
                                string name = l.Substring(6).Trim(' ', ';', ',', '\t');
                                db[l.Substring(0, 6).ToUpper()] = new OuiInfo(name, name, "", "");
                            }
                        }
                }
                catch (Exception) { }
            }
        }

        // WebClient не умеет сам ограничивать таймаут запроса - без этого один зависший онлайн-запрос
        // мог бы надолго задержать всё сканирование.
        class TimedWebClient : WebClient
        {
            public int Timeout = 1500;
            protected override WebRequest GetWebRequest(Uri address)
            {
                WebRequest r = base.GetWebRequest(address);
                r.Timeout = Timeout;
                return r;
            }
        }

        static readonly object OnlineSync = new object();
        static readonly Dictionary<string, string> OnlineCache = new Dictionary<string, string>();

        // Онлайн-поиск производителя по MAC в нескольких открытых базах, когда префикса нет во встроенном
        // локальном списке. Результат кэшируется на время работы программы, чтобы не ходить в сеть повторно
        // за тем же префиксом. Используется только для реальных (не случайных) MAC-адресов.
        static string OnlineLookup(string mac)
        {
            string prefix = mac.Substring(0, 8).Replace(":", "").ToUpper();
            lock (OnlineSync) { string cached; if (OnlineCache.TryGetValue(prefix, out cached)) return cached; }
            string result = "";

            // База 1: api.macvendors.com - при успехе отвечает простым текстом с названием производителя.
            try
            {
                using (TimedWebClient wc = new TimedWebClient())
                {
                    wc.Timeout = 1500;
                    wc.Headers.Add("User-Agent", "NetWarden (security scanner)");
                    string body = wc.DownloadString("https://api.macvendors.com/" + Uri.EscapeDataString(mac)).Trim();
                    if (body != "" && body.Length < 200 && !body.StartsWith("{") && !body.StartsWith("<"))
                        result = body;
                }
            }
            catch (Exception) { }

            // База 2: api.maclookup.app - JSON с полем company, если в первой базе ничего не нашлось.
            if (result == "")
            {
                try
                {
                    string json;
                    using (TimedWebClient wc = new TimedWebClient())
                    {
                        wc.Timeout = 1500;
                        wc.Headers.Add("User-Agent", "NetWarden (security scanner)");
                        wc.Headers.Add("Accept", "application/json");
                        json = wc.DownloadString("https://api.maclookup.app/v2/macs/" + Uri.EscapeDataString(mac));
                    }
                    JavaScriptSerializer js = new JavaScriptSerializer();
                    Dictionary<string, object> d = js.DeserializeObject(json) as Dictionary<string, object>;
                    object found, company;
                    if (d != null && d.TryGetValue("found", out found) && Convert.ToBoolean(found) &&
                        d.TryGetValue("company", out company) && company != null && Convert.ToString(company) != "")
                        result = Convert.ToString(company);
                }
                catch (Exception) { }
            }

            lock (OnlineSync) { OnlineCache[prefix] = result; }
            return result;
        }

        public static string Lookup(string mac)
        {
            OuiInfo i = Find(mac);
            if (i != null) return i.Vendor;
            if (IsRandom(mac)) return "случайный MAC";
            string online = OnlineLookup(mac);
            return online != "" ? online : "";
        }

        static OuiInfo Find(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return null;
            Init();
            OuiInfo i;
            return db.TryGetValue(mac.Substring(0, 8).Replace(":", "").ToUpper(), out i) ? i : null;
        }

        static bool IsRandom(string mac)
        {
            try { return (Convert.ToInt32(mac.Substring(0, 2), 16) & 2) != 0; }
            catch (Exception) { return false; }
        }

        // Человекочитаемое описание устройства по MAC: чей это производитель, из какой он страны
        // и какое устройство с таким MAC-префиксом обычно встречается. Используется в карточке хоста.
        public static string Describe(string mac)
        {
            if (string.IsNullOrEmpty(mac)) return "";
            OuiInfo i = Find(mac);
            if (i != null)
            {
                string who = i.Full + (i.Country != "" ? " (" + i.Country + ")" : "");
                return i.Category != "" ? who + " - " + i.Category : who;
            }
            if (IsRandom(mac))
                return "MAC-адрес случайный (локально назначенный) - так современные телефоны и ноутбуки скрывают " +
                       "настоящего производителя сетевого чипа ради приватности; определить по нему реальную модель устройства нельзя.";
            string online = OnlineLookup(mac);
            if (online != "")
                return online + " (найдено в открытой онлайн-базе MAC-адресов, не во встроенном локальном списке)";
            return "Производитель по базе MAC-адресов не определён (префикс отсутствует ни во встроенной базе, ни в доступных онлайн-базах - возможно, нет интернета).";
        }
    }

    // ===================== UDP-СЛУЖБЫ И NETBIOS =====================
    static class Udp
    {
        public static byte[] Send(string ip, int port, byte[] payload, int timeoutMs)
        {
            UdpClient u = null;
            try
            {
                u = new UdpClient();
                u.Client.ReceiveTimeout = timeoutMs;
                u.Client.SendTimeout = timeoutMs;
                u.Connect(IPAddress.Parse(ip), port);
                u.Send(payload, payload.Length);
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                return u.Receive(ref ep);
            }
            catch (Exception) { return null; }
            finally { if (u != null) u.Close(); }
        }
    }

    class UdpProbe { public int Port; public string Svc; public byte[] Data; }

    static class UdpProbes
    {
        public static readonly List<UdpProbe> All = Build();

        static void A(List<UdpProbe> l, int port, string svc, byte[] data)
        {
            UdpProbe p = new UdpProbe();
            p.Port = port; p.Svc = svc; p.Data = data;
            l.Add(p);
        }

        static List<UdpProbe> Build()
        {
            List<UdpProbe> l = new List<UdpProbe>();
            List<byte> dns = new List<byte>();
            dns.AddRange(new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            dns.AddRange(Encoding.ASCII.GetBytes("\u0007example\u0003com\u0000"));
            dns.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 });
            A(l, 53, "dns", dns.ToArray());
            byte[] ntp = new byte[48];
            ntp[0] = 0x1B;
            A(l, 123, "ntp", ntp);
            A(l, 161, "snmp", new byte[] {
                0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
                0xa0, 0x1c, 0x02, 0x04, 0x71, 0x5e, 0x3e, 0x5a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00 });
            A(l, 1900, "ssdp", Encoding.ASCII.GetBytes(
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"));
            return l;
        }

        public static string Describe(string svc, byte[] r)
        {
            try
            {
                if (svc == "dns") return "DNS-сервер (рекурсия " + ((r.Length > 3 && (r[3] & 0x80) != 0) ? "доступна" : "недоступна") + ")";
                if (svc == "ntp") return "NTP-сервер" + (r.Length > 1 ? ", stratum " + r[1] : "");
                if (svc == "snmp")
                {
                    string best = "", cur = "";
                    for (int i = 0; i <= r.Length; i++)
                    {
                        if (i < r.Length && r[i] >= 32 && r[i] < 127) cur += (char)r[i];
                        else { if (cur.Length > best.Length && cur != "public") best = cur; cur = ""; }
                    }
                    return best != "" ? "SNMP sysDescr: " + best : "SNMP (community public принята)";
                }
                if (svc == "ssdp")
                {
                    string txt = Encoding.ASCII.GetString(r);
                    foreach (string line in txt.Split(new string[] { "\r\n" }, StringSplitOptions.None))
                        if (line.ToUpper().StartsWith("SERVER:")) return "UPnP: " + line.Substring(7).Trim();
                    return "UPnP/SSDP отвечает";
                }
            }
            catch (Exception) { }
            return "ответ " + r.Length + " байт";
        }
    }

    static class NetBios
    {
        static readonly byte[] Query = BuildQuery();

        static byte[] BuildQuery()
        {
            List<byte> q = new List<byte>();
            q.AddRange(new byte[] { 0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B });
            for (int i = 0; i < 30; i++) q.Add(0x41);
            q.AddRange(new byte[] { 0x00, 0x00, 0x21, 0x00, 0x01 });
            return q.ToArray();
        }

        public static void Enrich(HostInfo h, bool addPort)
        {
            byte[] r = Udp.Send(h.Ip, 137, Query, 700);
            if (r == null || r.Length < 57) return;
            int count = r[56];
            int off = 57;
            if (r.Length < off + count * 18 + 6) return;
            string name = "";
            for (int i = 0; i < count; i++)
            {
                int o = off + i * 18;
                int flags = (r[o + 16] << 8) | r[o + 17];
                if (r[o + 15] == 0x00 && (flags & 0x8000) == 0 && name == "") name = Encoding.ASCII.GetString(r, o, 15).Trim();
            }
            if (h.Name == "" && name != "") h.Name = name;
            string mac = BitConverter.ToString(r, off + count * 18, 6).Replace('-', ':');
            if (h.Mac == "" && mac != "00:00:00:00:00:00") h.Mac = mac;
            if (addPort)
            {
                PortInfo p = new PortInfo();
                p.Port = 137; p.Proto = "udp"; p.Service = "netbios-ns";
                p.Banner = name != "" ? "NetBIOS: " + name : "NetBIOS";
                lock (h.Ports) { h.Ports.Add(p); }
            }
        }
    }

    // ===================== ОПРЕДЕЛЕНИЕ ОС =====================
    static class OsDetect
    {
        static bool Has(string t, params string[] keys)
        {
            foreach (string k in keys) if (t.Contains(k)) return true;
            return false;
        }

        static string WinByIis(string v)
        {
            if (v.StartsWith("10.")) return "Windows 10/11 или Server 2016+";
            if (v.StartsWith("8.5")) return "Windows Server 2012 R2 / 8.1";
            if (v.StartsWith("8.0")) return "Windows Server 2012 / 8";
            if (v.StartsWith("7.5")) return "Windows 7 / Server 2008 R2";
            if (v.StartsWith("7.0")) return "Windows Vista / Server 2008";
            if (v.StartsWith("6.0")) return "Windows Server 2003";
            return "";
        }

        public static void Guess(HostInfo h)
        {
            StringBuilder sb = new StringBuilder();
            foreach (PortInfo p in h.Ports) sb.Append(p.Banner).Append(' ').Append(p.Product).Append(' ');
            sb.Append(h.Descr);
            string t = sb.ToString().ToLower();
            string os = "", basis = "";

            if (Has(t, "ubuntu")) os = "Linux (Ubuntu)";
            else if (Has(t, "raspbian", "raspberry")) os = "Linux (Raspberry Pi OS)";
            else if (Has(t, "debian")) os = "Linux (Debian)";
            else if (Has(t, "centos")) os = "Linux (CentOS)";
            else if (Has(t, "red hat", "rhel", "rocky", "almalinux")) os = "Linux (семейство RHEL)";
            else if (Has(t, "fedora")) os = "Linux (Fedora)";
            else if (Has(t, "freebsd")) os = "FreeBSD";
            else if (Has(t, "openbsd")) os = "OpenBSD";
            else if (Has(t, "routeros", "mikrotik")) os = "RouterOS (MikroTik)";
            else if (Has(t, "cisco")) os = "Cisco IOS / сетевое оборудование";
            else if (Has(t, "synology", "diskstation")) os = "Synology DSM (Linux)";
            else if (Has(t, "darwin", "macos", "mac os")) os = "macOS";
            else if (Has(t, "windows", "microsoft", "win32", "win64")) os = "Windows";
            else if (Has(t, "linux")) os = "Linux";
            if (os != "") basis = "по баннерам служб";

            if (os == "Windows")
                foreach (PortInfo p in h.Ports)
                    if (p.Product == "IIS") { string w = WinByIis(p.Version); if (w != "") os = w; }

            if (os == "")
            {
                foreach (PortInfo p in h.Ports)
                    if (p.Proto == "tcp" && (p.Port == 135 || p.Port == 139 || p.Port == 445 || p.Port == 3389 || p.Port == 5985))
                    { os = "Windows"; basis = "по открытым портам (RPC/SMB/RDP)"; break; }
            }
            if (os == "" && h.Ttl > 0)
            {
                if (h.Ttl <= 64) os = "Linux / Unix / macOS / Android (вероятно)";
                else if (h.Ttl <= 128) os = "Windows (вероятно)";
                else os = "Сетевое оборудование (TTL 255)";
                basis = "по TTL=" + h.Ttl;
            }
            string v = (h.Vendor ?? "").ToLower();
            if (Has(v, "vmware", "virtualbox", "hyper-v", "qemu", "parallels"))
            {
                os = (os == "" ? "ОС не определена" : os) + " [виртуальная машина]";
                if (basis == "") basis = "по MAC";
            }
            else if (os == "" && v.Contains("raspberry")) { os = "Linux (Raspberry Pi)"; basis = "по MAC"; }
            else if (os == "" && Has(v, "mikrotik", "cisco", "ubiquiti", "tp-link", "d-link", "netgear"))
            { os = "Сетевое оборудование (" + h.Vendor + ")"; basis = "по производителю MAC"; }
            if (os == "") os = "не определена";
            h.Os = os;
            h.OsBasis = basis;
        }
    }

    class Scanner
    {
        public string TargetsSpec = "", PortsSpec = "";
        public List<string[]> Targets;
        public int[] Ports;
        public int Timeout = 1500, Threads = 300;
        public bool SkipDiscovery;
        public bool ScanUdp = true;
        public bool ScanBrute;
        public volatile bool Cancel;
        public volatile bool Done;
        public string Stage = "";
        public long StageDone, StageTotal;
        public ConcurrentQueue<string> Log = new ConcurrentQueue<string>();
        public ConcurrentQueue<HostInfo> Finished = new ConcurrentQueue<HostInfo>();
        public ScanResult Result;

        static readonly int[] DiscPorts = new int[] { 80, 443, 22, 445, 135, 139, 3389, 21, 25, 8080 };

        void RunIndexed(long total, int threads, Action<long> body)
        {
            StageDone = 0;
            StageTotal = total;
            long next = -1;
            int n = (int)Math.Max(1, Math.Min((long)threads, total));
            List<Thread> ts = new List<Thread>();
            for (int i = 0; i < n; i++)
            {
                Thread t = new Thread(() =>
                {
                    while (!Cancel)
                    {
                        long idx = Interlocked.Increment(ref next);
                        if (idx >= total) break;
                        try { body(idx); } catch (Exception) { }
                        Interlocked.Increment(ref StageDone);
                    }
                }, 262144);
                t.IsBackground = true;
                t.Start();
                ts.Add(t);
            }
            foreach (Thread t in ts) t.Join();
        }

        bool Discover(HostInfo h)
        {
            string ip = h.Ip;
            bool alive = false;
            bool local = LocalNets.IsLocal(ip);
            if (local)
            {
                string mac = Arp.Resolve(ip);
                if (mac != "") { h.Mac = mac; alive = true; }
            }
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply r = ping.Send(ip, alive ? 400 : 700);
                    if (r != null && r.Status == IPStatus.Success)
                    {
                        alive = true;
                        if (r.Options != null) h.Ttl = r.Options.Ttl;
                    }
                }
            }
            catch (Exception) { }
            if (alive) return true;
            if (local) return false;
            foreach (int port in DiscPorts)
            {
                if (Cancel) return false;
                bool refused;
                TcpClient c = NetUtil.Connect(ip, port, 600, out refused);
                if (c != null) { c.Close(); return true; }
                if (refused) return true;
            }
            return false;
        }

        public void Run()
        {
            try
            {
                Result = new ScanResult();
                Result.Id = DateTime.Now.ToString("yyyyMMdd-HHmmss");
                Result.Started = DateTime.Now;
                Result.Targets = TargetsSpec;
                Result.Ports = PortsSpec;
                Log.Enqueue("Старт: целей " + Targets.Count + ", портов " + Ports.Length);

                HostInfo[] all = new HostInfo[Targets.Count];
                for (int i = 0; i < all.Length; i++)
                {
                    all[i] = new HostInfo();
                    all[i].Ip = Targets[i][0];
                    all[i].Name = Targets[i][1];
                }
                bool[] isAlive = new bool[all.Length];

                Stage = "1/4 Обнаружение хостов (ARP, ping)";
                if (SkipDiscovery)
                {
                    for (int i = 0; i < isAlive.Length; i++) isAlive[i] = true;
                }
                else
                {
                    RunIndexed(all.Length, Math.Min(Threads, 128), delegate(long i)
                    {
                        isAlive[i] = Discover(all[i]);
                        if (isAlive[i]) Log.Enqueue("[+] Хост активен: " + all[i].Ip);
                    });
                }
                List<HostInfo> alive = new List<HostInfo>();
                for (int i = 0; i < all.Length; i++) if (isAlive[i]) alive.Add(all[i]);

                if (!Cancel && alive.Count > 0)
                {
                    Stage = "2/4 TCP-порты и сервисы";
                    int pl = Ports.Length;
                    RunIndexed((long)alive.Count * pl, Threads, delegate(long i)
                    {
                        HostInfo h = alive[(int)(i / pl)];
                        int port = Ports[(int)(i % pl)];
                        bool refused;
                        TcpClient c = NetUtil.Connect(h.Ip, port, Timeout, out refused);
                        if (c == null) return;
                        c.Close();
                        PortInfo p = new PortInfo();
                        p.Port = port;
                        Services.Identify(h.Ip, p, Timeout);
                        lock (h.Ports) { h.Ports.Add(p); }
                        Log.Enqueue("    " + h.Ip + ":" + port + " открыт - " + (p.Service + " " + p.Product + " " + p.Version).Trim());
                    });
                }

                if (!Cancel && ScanUdp && alive.Count > 0)
                {
                    Stage = "3/4 UDP-службы (DNS, NTP, SNMP, SSDP)";
                    int up = UdpProbes.All.Count;
                    RunIndexed((long)alive.Count * up, Threads, delegate(long i)
                    {
                        HostInfo h = alive[(int)(i / up)];
                        UdpProbe pr = UdpProbes.All[(int)(i % up)];
                        byte[] resp = Udp.Send(h.Ip, pr.Port, pr.Data, 900);
                        if (resp == null || resp.Length == 0) return;
                        PortInfo p = new PortInfo();
                        p.Port = pr.Port; p.Proto = "udp"; p.Service = pr.Svc;
                        p.Banner = UdpProbes.Describe(pr.Svc, resp);
                        if (pr.Svc == "snmp") p.Product = "SNMP v1";
                        if (pr.Svc == "snmp" || pr.Svc == "ssdp") lock (h) { h.Descr += p.Banner + " "; }
                        lock (h.Ports) { h.Ports.Add(p); }
                        Log.Enqueue("    " + h.Ip + ":" + pr.Port + "/udp - " + pr.Svc + " " + p.Banner);
                    });
                }

                if (!Cancel)
                {
                    Stage = "4/4 ОС, имена, уязвимости";
                    RunIndexed(alive.Count, 16, delegate(long i)
                    {
                        HostInfo h = alive[(int)i];
                        if (h.Name == "")
                        {
                            try { h.Name = Dns.GetHostEntry(h.Ip).HostName; } catch (Exception) { }
                        }
                        NetBios.Enrich(h, ScanUdp);
                        h.Ports.Sort(delegate(PortInfo a, PortInfo b)
                        {
                            int c = a.Port.CompareTo(b.Port);
                            return c != 0 ? c : string.CompareOrdinal(a.Proto, b.Proto);
                        });
                        h.Vendor = Oui.Lookup(h.Mac);
                        h.MacInfo = Oui.Describe(h.Mac);
                        OsDetect.Guess(h);
                        Checks.Run(h, Timeout, ScanBrute);
                        foreach (Finding f in h.Findings)
                            Log.Enqueue("    [" + f.Severity.ToUpper() + "] " + h.Ip + ":" + f.Port + " " + f.Title);
                        Finished.Enqueue(h);
                    });
                }
                else
                {
                    foreach (HostInfo h in alive) Finished.Enqueue(h);
                }

                alive.Sort(delegate(HostInfo a, HostInfo b) { return Targets_Key(a.Ip).CompareTo(Targets_Key(b.Ip)); });
                Result.Hosts = alive;
                Result.Finished = DateTime.Now;
                Log.Enqueue(Cancel ? "Сканирование остановлено" : "Сканирование завершено");
            }
            catch (Exception ex)
            {
                Log.Enqueue("ОШИБКА: " + ex.Message);
            }
            finally
            {
                Done = true;
            }
        }

        static long Targets_Key(string ip) { return NetWarden.Targets.ToUInt(ip); }
    }

    // ===================== ОТЧЁТЫ И ИСТОРИЯ =====================
    static class Report
    {
        static string E(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static List<KeyValuePair<HostInfo, Finding>> Pairs(ScanResult r)
        {
            List<KeyValuePair<HostInfo, Finding>> l = new List<KeyValuePair<HostInfo, Finding>>();
            foreach (HostInfo h in r.Hosts)
                foreach (Finding f in h.Findings) l.Add(new KeyValuePair<HostInfo, Finding>(h, f));
            l.Sort(delegate(KeyValuePair<HostInfo, Finding> a, KeyValuePair<HostInfo, Finding> b)
            {
                int c = Sev.Idx(a.Value.Severity).CompareTo(Sev.Idx(b.Value.Severity));
                return c != 0 ? c : string.CompareOrdinal(a.Key.Ip, b.Key.Ip);
            });
            return l;
        }

        static string Hex(Color c) { return "#" + c.R.ToString("x2") + c.G.ToString("x2") + c.B.ToString("x2"); }

        public static string Html(ScanResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\"><title>Отчёт NetWarden ").Append(E(r.Id)).Append("</title>");
            sb.Append("<style>body{font:14px Segoe UI,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1f2937}");
            sb.Append(".cards{display:flex;gap:12px}.card{flex:1;padding:12px;background:#f3f4f6;border-radius:6px;text-align:center}");
            sb.Append(".card b{display:block;font-size:26px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e5e7eb;padding:6px;text-align:left}");
            sb.Append(".f{border-left:3px solid #d1d5db;padding:4px 12px;margin:10px 0}.b{color:#fff;padding:1px 8px;border-radius:10px;font-size:12px}");
            sb.Append(".m{color:#6b7280;font-family:Consolas,monospace;font-size:12px}small{color:#6b7280;font-weight:400}</style>");
            sb.Append("<h1>Отчёт о сканировании</h1><p>Цели: <b>").Append(E(r.Targets)).Append("</b> · Порты: ").Append(E(r.Ports));
            sb.Append(" · Начало: ").Append(r.Started.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.Append(" · Конец: ").Append(r.Finished.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.Append(" · Активных хостов: ").Append(r.Hosts.Count).Append("</p><div class=\"cards\">");
            foreach (string s in Sev.Order)
            {
                int cnt = 0;
                foreach (KeyValuePair<HostInfo, Finding> kv in Pairs(r)) if (kv.Value.Severity == s) cnt++;
                sb.Append("<div class=\"card\" style=\"border-top:4px solid ").Append(Hex(Sev.Col(s))).Append("\"><b>").Append(cnt)
                  .Append("</b>").Append(Sev.Ru(s)).Append("</div>");
            }
            sb.Append("</div>");
            foreach (HostInfo h in r.Hosts)
            {
                sb.Append("<h2>").Append(E(h.Ip)).Append(" <small>").Append(E(h.Name)).Append("</small></h2>");
                sb.Append("<p class=\"m\">ОС: ").Append(E(h.Os)).Append(h.OsBasis != "" ? " (" + E(h.OsBasis) + ")" : "")
                  .Append(h.Mac != "" ? " · MAC: " + E(h.Mac) + (h.Vendor != "" ? " (" + E(h.Vendor) + ")" : "") : "").Append("</p>")
                  .Append(h.MacInfo != "" ? "<p class=\"m\">По MAC-адресу: " + E(h.MacInfo) + "</p>" : "");
                sb.Append("<table><tr><th>Порт</th><th>Сервис</th><th>Продукт / версия</th><th>Баннер</th></tr>");
                foreach (PortInfo p in h.Ports)
                    sb.Append("<tr><td>").Append(p.Port).Append("/").Append(p.Proto).Append("</td><td>").Append(E(p.Service)).Append(p.Tls ? " (TLS)" : "")
                      .Append("</td><td>").Append(E((p.Product + " " + p.Version).Trim()))
                      .Append("</td><td class=\"m\">").Append(E(p.Banner.Length > 80 ? p.Banner.Substring(0, 80) : p.Banner)).Append("</td></tr>");
                sb.Append("</table>");
                List<Finding> fl = new List<Finding>(h.Findings);
                fl.Sort(delegate(Finding a, Finding b) { return Sev.Idx(a.Severity).CompareTo(Sev.Idx(b.Severity)); });
                foreach (Finding f in fl)
                {
                    sb.Append("<div class=\"f\"><span class=\"b\" style=\"background:").Append(Hex(Sev.Col(f.Severity))).Append("\">")
                      .Append(Sev.Ru(f.Severity)).Append("</span> <b>").Append(E(f.Title)).Append("</b> <i>(порт ").Append(f.Port)
                      .Append(", CVSS ").Append(f.Cvss.ToString("0.0", CultureInfo.InvariantCulture)).Append(", ")
                      .Append(f.Conf == "confirmed" ? "подтверждено" : "вероятно - по версии").Append(")</i>");
                    if (f.Desc != "") sb.Append("<p>").Append(E(f.Desc)).Append("</p>");
                    if (f.Cve != "") sb.Append("<p><b>CVE:</b> ").Append(E(f.Cve)).Append("</p>");
                    if (f.Attack != "") sb.Append("<p><b>Как может воспользоваться злоумышленник:</b> ").Append(E(f.Attack)).Append("</p>");
                    if (f.Rec != "") sb.Append("<p><b>Рекомендация:</b> ").Append(E(f.Rec)).Append("</p>");
                    if (f.Evidence != "") sb.Append("<p class=\"m\">Свидетельство: ").Append(E(f.Evidence)).Append("</p>");
                    sb.Append("<p class=\"m\">Источник: ").Append(E(f.Source != "" ? f.Source : "Встроенная база NetWarden"))
                      .Append(" · <a href=\"").Append(Refs.Bdu(f.Title)).Append("\">проверить в БДУ ФСТЭК</a></p>");
                    sb.Append("</div>");
                }
            }
            sb.Append("<p class=\"m\">Сформировано NetWarden. Находки со статусом «вероятно» основаны на версии сервиса и требуют ручной проверки: дистрибутивы могут бэкпортировать исправления.</p></html>");
            return sb.ToString();
        }

        static string Q(string s) { return "\"" + (s ?? "").Replace("\"", "\"\"") + "\""; }

        public static string Csv(ScanResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("host;hostname;os;mac;port;severity;cvss;id;title;cve;confidence;recommendation;attack;source\r\n");
            foreach (KeyValuePair<HostInfo, Finding> kv in Pairs(r))
            {
                Finding f = kv.Value;
                sb.Append(Q(kv.Key.Ip)).Append(';').Append(Q(kv.Key.Name)).Append(';').Append(Q(kv.Key.Os)).Append(';').Append(Q(kv.Key.Mac)).Append(';').Append(f.Port).Append(';')
                  .Append(f.Severity).Append(';').Append(f.Cvss.ToString("0.0", CultureInfo.InvariantCulture)).Append(';')
                  .Append(Q(f.Id)).Append(';').Append(Q(f.Title)).Append(';').Append(Q(f.Cve)).Append(';')
                  .Append(f.Conf).Append(';').Append(Q(f.Rec)).Append(';').Append(Q(f.Attack)).Append(';').Append(Q(f.Source)).Append("\r\n");
            }
            return sb.ToString();
        }
    }

    // ===================== ОБНОВЛЕНИЕ БАЗ УЯЗВИМОСТЕЙ (NVD) =====================
    // Встроенные правила (Rules.Build) обновляются вместе с программой. Эта функция дополнительно опрашивает
    // публичный API Национальной базы уязвимостей США (NVD) по найденным продуктам и версиям - без ключа,
    // поэтому с намеренной паузой между запросами. Для российской базы БДУ ФСТЭК стабильного публичного API
    // нет, поэтому вместо автоматической проверки для каждой находки формируется ссылка на поиск по ней на bdu.fstec.ru.
    static class NvdUpdate
    {
        const int MaxQueries = 12;
        const int PauseMs = 6500;

        static double Score(Dictionary<string, object> cve, out string sev)
        {
            sev = "medium";
            try
            {
                object metricsObj;
                if (!cve.TryGetValue("metrics", out metricsObj)) return 0;
                Dictionary<string, object> metrics = (Dictionary<string, object>)metricsObj;
                foreach (string key in new string[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
                {
                    object arrObj;
                    if (!metrics.TryGetValue(key, out arrObj)) continue;
                    object[] arr = (object[])arrObj;
                    if (arr.Length == 0) continue;
                    Dictionary<string, object> m0 = (Dictionary<string, object>)arr[0];
                    Dictionary<string, object> data = (Dictionary<string, object>)m0["cvssData"];
                    double score = Convert.ToDouble(data["baseScore"], CultureInfo.InvariantCulture);
                    if (score >= 9.0) sev = "critical"; else if (score >= 7.0) sev = "high"; else if (score >= 4.0) sev = "medium"; else sev = "low";
                    return score;
                }
            }
            catch (Exception) { }
            return 0;
        }

        static string Descr(Dictionary<string, object> cve)
        {
            try
            {
                object[] arr = (object[])cve["descriptions"];
                foreach (object o in arr)
                {
                    Dictionary<string, object> d = (Dictionary<string, object>)o;
                    if ((string)d["lang"] == "en")
                    {
                        string t = (string)d["value"];
                        return t.Length > 320 ? t.Substring(0, 320) + "..." : t;
                    }
                }
            }
            catch (Exception) { }
            return "";
        }

        // Возвращает (summaryText, добавленоНаходок)
        public static string Run(List<HostInfo> hosts, out int added)
        {
            added = 0;
            Dictionary<string, List<PortInfo>> byKeyPorts = new Dictionary<string, List<PortInfo>>();
            Dictionary<string, List<HostInfo>> byKeyHosts = new Dictionary<string, List<HostInfo>>();
            foreach (HostInfo h in hosts)
                foreach (PortInfo p in h.Ports)
                {
                    if (p.Product == "" || p.Version == "") continue;
                    string key = p.Product.Trim() + " " + p.Version.Trim();
                    if (!byKeyPorts.ContainsKey(key)) { byKeyPorts[key] = new List<PortInfo>(); byKeyHosts[key] = new List<HostInfo>(); }
                    byKeyPorts[key].Add(p);
                    if (!byKeyHosts[key].Contains(h)) byKeyHosts[key].Add(h);
                }
            if (byKeyPorts.Count == 0) return "В результатах сканирования нет служб с определённой версией ПО - обновлять нечего. Сначала выполните сканирование.";

            try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls; }
            catch (Exception) { }

            List<string> keys = new List<string>(byKeyPorts.Keys);
            int limit = Math.Min(keys.Count, MaxQueries);
            int okQueries = 0, errQueries = 0, totalCve = 0, zeroResultQueries = 0;
            List<string> errorDetails = new List<string>();
            JavaScriptSerializer js = new JavaScriptSerializer();
            js.MaxJsonLength = 20 * 1024 * 1024;

            for (int i = 0; i < limit; i++)
            {
                string key = keys[i];
                string url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
                             Uri.EscapeDataString(key) + "&resultsPerPage=5";
                string json = null;

                try
                {
                    using (WebClient wc = new WebClient())
                    {
                        wc.Headers.Add("User-Agent", "NetWarden/0.5 (security scanner)");
                        wc.Headers.Add("Accept", "application/json");
                        json = wc.DownloadString(url);
                    }
                    okQueries++;
                }
                catch (WebException wex)
                {
                    errQueries++;
                    string detail = key + ": сетевая ошибка - " + wex.Message;
                    try
                    {
                        if (wex.Response != null)
                        {
                            HttpWebResponse hr = wex.Response as HttpWebResponse;
                            string code = hr != null ? ((int)hr.StatusCode) + " " + hr.StatusCode : "";
                            string body = "";
                            using (Stream st = wex.Response.GetResponseStream())
                            using (StreamReader sr = new StreamReader(st, Encoding.UTF8))
                                body = sr.ReadToEnd();
                            if (body.Length > 200) body = body.Substring(0, 200) + "...";
                            detail = key + ": HTTP " + code + (body != "" ? " - " + body : "");
                        }
                    }
                    catch (Exception) { }
                    if (errorDetails.Count < 3) errorDetails.Add(detail);
                }
                catch (Exception ex) { errQueries++; if (errorDetails.Count < 3) errorDetails.Add(key + ": " + ex.Message); }

                if (json != null)
                {
                    json = json.Trim();
                    // снять BOM, если он есть - иначе JavaScriptSerializer иногда не распознаёт начало объекта
                    if (json.Length > 0 && json[0] == '\uFEFF') json = json.Substring(1);
                    if (json.Length == 0)
                    {
                        errQueries++; if (errorDetails.Count < 3) errorDetails.Add(key + ": сервер вернул пустой ответ");
                    }
                    else
                    {
                        try
                        {
                            object parsed = js.DeserializeObject(json);
                            Dictionary<string, object> root = parsed as Dictionary<string, object>;
                            if (root == null)
                            {
                                errQueries++;
                                if (errorDetails.Count < 3) errorDetails.Add(key + ": ответ не похож на JSON-объект NVD (начало: " +
                                    (json.Length > 120 ? json.Substring(0, 120) + "..." : json) + ")");
                            }
                            else if (!root.ContainsKey("vulnerabilities"))
                            {
                                // NVD иногда отвечает 200 OK с текстом ошибки/лимита вместо данных - покажем его как есть
                                object msg;
                                string why = root.TryGetValue("message", out msg) ? Convert.ToString(msg) :
                                             root.TryGetValue("error", out msg) ? Convert.ToString(msg) : "";
                                errQueries++;
                                if (errorDetails.Count < 3)
                                    errorDetails.Add(key + ": NVD не вернул результаты" + (why != "" ? " - " + why : " (возможно, временное ограничение частоты запросов NVD)"));
                            }
                            else
                            {
                                object[] vulns = (object[])root["vulnerabilities"];
                                if (vulns.Length == 0) zeroResultQueries++;
                                foreach (object vo in vulns)
                                {
                                    try
                                    {
                                        Dictionary<string, object> vdict = (Dictionary<string, object>)vo;
                                        Dictionary<string, object> cve = (Dictionary<string, object>)vdict["cve"];
                                        string id = Convert.ToString(cve["id"]);
                                        string sev;
                                        double score = Score(cve, out sev);
                                        string desc = Descr(cve);
                                        foreach (PortInfo p in byKeyPorts[key])
                                        {
                                            HostInfo owner = null;
                                            foreach (HostInfo h in byKeyHosts[key]) if (h.Ports.Contains(p)) { owner = h; break; }
                                            if (owner == null) continue;
                                            bool already = false;
                                            foreach (Finding ex2 in owner.Findings) if (ex2.Id == "CVE-NVD-" + id && ex2.Port == p.Port) { already = true; break; }
                                            if (already) continue;
                                            Finding f = new Finding();
                                            f.Id = "CVE-NVD-" + id;
                                            f.Title = "Найдено в NVD по версии ПО: " + id + " (" + key + ")";
                                            f.Severity = sev; f.Cvss = score; f.Cve = id; f.Conf = "probable";
                                            f.Desc = (desc != "" ? desc : "Описание недоступно.") +
                                                     " [Подобрано автоматическим поиском по ключевым словам \"" + key + "\" в NVD - возможны ложные совпадения, сверьте вручную по ссылке CVE.]";
                                            f.Rec = "Обновите " + key + " до версии, в которой это CVE устранено. Проверьте официальный changelog/security advisory производителя.";
                                            f.Attack = "Подробности конкретной техники эксплуатации см. по ссылке на NVD/CVE ниже и в публичных базах эксплойтов (Exploit-DB, GitHub Advisory).";
                                            f.Source = "NVD (services.nvd.nist.gov), обновлено " + DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                                            f.Port = p.Port;
                                            lock (owner.Findings) { owner.Findings.Add(f); }
                                            added++; totalCve++;
                                        }
                                    }
                                    catch (Exception exItem)
                                    {
                                        errQueries++;
                                        if (errorDetails.Count < 3) errorDetails.Add(key + ": не удалось разобрать одну запись CVE - " + exItem.Message);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            errQueries++;
                            if (errorDetails.Count < 3) errorDetails.Add(key + ": ошибка разбора ответа NVD - " + ex.Message);
                        }
                    }
                }
                if (i < limit - 1) Thread.Sleep(PauseMs);
            }

            string nl = "\r\n";
            StringBuilder sb = new StringBuilder();
            sb.Append("Проверено продуктов/версий: " + limit + " из " + keys.Count +
                      (keys.Count > limit ? " (ограничение " + MaxQueries + " запросов за один раз, чтобы не превышать лимиты NVD API без ключа - запустите обновление ещё раз для остальных)" : "") + nl);
            sb.Append("Успешных запросов: " + okQueries + ", ошибок: " + errQueries +
                      (zeroResultQueries > 0 ? " (совпадений не найдено: " + zeroResultQueries + ")" : "") + nl);
            sb.Append("Добавлено новых находок из NVD: " + added + nl);
            if (errorDetails.Count > 0)
            {
                sb.Append(nl + "Подробности ошибок:" + nl);
                foreach (string d in errorDetails) sb.Append("  - " + d + nl);
                sb.Append(nl);
            }
            else sb.Append(nl);
            sb.Append("Для российской базы БДУ ФСТЭК стабильного публичного API нет: вместо автоматической сверки для каждой находки добавлена ссылка " +
                      "на поиск по её названию на bdu.fstec.ru (см. кнопку \"Исправить\" / подробности находки).");
            return sb.ToString();
        }
    }

    static class Store
    {
        static string Dir()
        {
            string d = Path.Combine(AppPaths.DataDir(), "scans");
            Directory.CreateDirectory(d);
            return d;
        }

        static string Esc(string s) { return (s ?? "").Replace("\r", " ").Replace("\n", " ").Replace("|", "/"); }

        public static void Save(ScanResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("M|" + r.Id + "|" + Esc(r.Targets) + "|" + Esc(r.Ports) + "|" + r.Started.Ticks + "|" + r.Finished.Ticks);
            foreach (HostInfo h in r.Hosts)
            {
                sb.AppendLine("H|" + h.Ip + "|" + Esc(h.Name) + "|" + Esc(h.Mac) + "|" + Esc(h.Vendor) + "|" + Esc(h.Os) + "|" + h.Ttl + "|" + Esc(h.Descr) + "|" + Esc(h.OsBasis));
                foreach (PortInfo p in h.Ports)
                    sb.AppendLine("P|" + h.Ip + "|" + p.Port + "|" + Esc(p.Service) + "|" + Esc(p.Product) + "|" + Esc(p.Version) + "|" + (p.Tls ? "1" : "0") + "|" + Esc(p.Banner) + "|" + p.Proto);
                foreach (Finding f in h.Findings)
                    sb.AppendLine("F|" + h.Ip + "|" + f.Port + "|" + Esc(f.Id) + "|" + f.Severity + "|" + f.Cvss.ToString("0.0", CultureInfo.InvariantCulture) +
                                  "|" + f.Conf + "|" + Esc(f.Title) + "|" + Esc(f.Cve) + "|" + Esc(f.Desc) + "|" + Esc(f.Rec) + "|" + Esc(f.Evidence) +
                                  "|" + Esc(f.Attack) + "|" + Esc(f.Source));
            }
            File.WriteAllText(Path.Combine(Dir(), r.Id + ".txt"), sb.ToString(), new UTF8Encoding(false));
        }

        public static List<string> Ids()
        {
            List<string> l = new List<string>();
            foreach (string f in Directory.GetFiles(Dir(), "*.txt")) l.Add(Path.GetFileNameWithoutExtension(f));
            l.Sort();
            l.Reverse();
            return l;
        }

        public static ScanResult Load(string id)
        {
            ScanResult r = new ScanResult();
            Dictionary<string, HostInfo> map = new Dictionary<string, HostInfo>();
            foreach (string line in File.ReadAllLines(Path.Combine(Dir(), id + ".txt"), Encoding.UTF8))
            {
                string[] f = line.Split('|');
                try
                {
                    if (f[0] == "M")
                    {
                        r.Id = f[1]; r.Targets = f[2]; r.Ports = f[3];
                        r.Started = new DateTime(long.Parse(f[4])); r.Finished = new DateTime(long.Parse(f[5]));
                    }
                    else if (f[0] == "H")
                    {
                        HostInfo h = new HostInfo();
                        h.Ip = f[1]; h.Name = f[2];
                        if (f.Length > 8) { h.Mac = f[3]; h.Vendor = f[4]; h.Os = f[5]; int.TryParse(f[6], out h.Ttl); h.Descr = f[7]; h.OsBasis = f[8]; }
                        map[h.Ip] = h;
                        r.Hosts.Add(h);
                    }
                    else if (f[0] == "P")
                    {
                        PortInfo p = new PortInfo();
                        p.Port = int.Parse(f[2]); p.Service = f[3]; p.Product = f[4]; p.Version = f[5];
                        p.Tls = f[6] == "1"; p.Banner = f[7];
                        if (f.Length > 8) p.Proto = f[8];
                        map[f[1]].Ports.Add(p);
                    }
                    else if (f[0] == "F")
                    {
                        Finding x = new Finding();
                        x.Port = int.Parse(f[2]); x.Id = f[3]; x.Severity = f[4];
                        x.Cvss = double.Parse(f[5], CultureInfo.InvariantCulture);
                        x.Conf = f[6]; x.Title = f[7]; x.Cve = f[8]; x.Desc = f[9]; x.Rec = f[10]; x.Evidence = f[11];
                        if (f.Length > 13) { x.Attack = f[12]; x.Source = f[13]; }
                        map[f[1]].Findings.Add(x);
                    }
                }
                catch (Exception) { }
            }
            if (r.Id == "") r.Id = id;
            return r;
        }

        static void Index(ScanResult r, HashSet<string> hosts, HashSet<string> ports, Dictionary<string, Finding> finds)
        {
            foreach (HostInfo h in r.Hosts)
            {
                hosts.Add(h.Ip);
                foreach (PortInfo p in h.Ports) ports.Add(h.Ip + ":" + p.Port);
                foreach (Finding f in h.Findings) finds[h.Ip + ":" + f.Port + " " + f.Id] = f;
            }
        }

        static void Section(StringBuilder sb, string title, IEnumerable<string> items)
        {
            List<string> l = items.ToList();
            sb.AppendLine(title + ": " + l.Count);
            foreach (string s in l) sb.AppendLine("    " + s);
        }

        public static string Diff(ScanResult a, ScanResult b)
        {
            HashSet<string> ha = new HashSet<string>(), hb = new HashSet<string>(), pa = new HashSet<string>(), pb = new HashSet<string>();
            Dictionary<string, Finding> fa = new Dictionary<string, Finding>(), fb = new Dictionary<string, Finding>();
            Index(a, ha, pa, fa);
            Index(b, hb, pb, fb);
            StringBuilder sb = new StringBuilder();
            Section(sb, "Новые хосты", hb.Where(x => !ha.Contains(x)));
            Section(sb, "Исчезнувшие хосты", ha.Where(x => !hb.Contains(x)));
            Section(sb, "Новые открытые порты", pb.Where(x => !pa.Contains(x)));
            Section(sb, "Закрытые порты", pa.Where(x => !pb.Contains(x)));
            Section(sb, "Новые уязвимости", fb.Where(kv => !fa.ContainsKey(kv.Key)).Select(kv => kv.Key + "  [" + kv.Value.Severity + "] " + kv.Value.Title));
            Section(sb, "Устранённые уязвимости", fa.Where(kv => !fb.ContainsKey(kv.Key)).Select(kv => kv.Key + "  [" + kv.Value.Severity + "] " + kv.Value.Title));
            return sb.ToString();
        }
    }

    // ===================== ИСПРАВЛЕНИЯ =====================
    class FixStep
    {
        public string Name, Cmd;
        public FixStep(string n, string c) { Name = n; Cmd = c; }
    }

    class FixAction
    {
        public string Title = "", Details = "", Undo = "", After = "";
        public List<FixStep> Steps = new List<FixStep>();
    }

    static class Fixes
    {
        static readonly Dictionary<string, string> Man = BuildManual();

        static FixStep S(string name, string cmd) { return new FixStep(name, cmd); }

        static FixAction Act(string title, string details, string undo, string after, params FixStep[] steps)
        {
            FixAction a = new FixAction();
            a.Title = title; a.Details = details; a.Undo = undo; a.After = after;
            a.Steps.AddRange(steps);
            return a;
        }

        static FixAction BlockPort(string title, int port, string proto, string extra)
        {
            string pr = proto.ToUpper();
            string rule = "NetWarden: block inbound " + pr + " " + port;
            return Act(title,
                "Будет создано правило брандмауэра Windows, блокирующее все входящие подключения к порту " + pr + " " + port +
                " (в том числе из локальной сети). " + extra +
                " Сама служба не удаляется и не останавливается: при необходимости настройте её отдельно (см. подробную инструкцию).",
                "Remove-NetFirewallRule -DisplayName '" + rule + "'", "",
                S("Заблокировать входящий " + pr + " " + port + " в брандмауэре Windows",
                  "New-NetFirewallRule -DisplayName '" + rule + "' -Direction Inbound -Protocol " + pr + " -LocalPort " + port + " -Action Block -Profile Any | Out-Null"));
        }

        // Автоматическое исправление (только для компьютера, на котором запущена программа). null - недоступно.
        public static FixAction Auto(Finding f)
        {
            switch (f.Id)
            {
                case "SMB-V1-ENABLED":
                    return Act("Отключить SMBv1",
                        "Будет отключён только устаревший протокол SMBv1. Порт 445 НЕ закрывается, общий доступ к вашим папкам по сети продолжит " +
                        "работать как раньше - современные Windows, macOS и Linux используют SMB2/3 и этого изменения даже не заметят. " +
                        "После этого при повторном сканировании находка должна исчезнуть или смениться на информационную \"SMB доступен (SMB2/3)\" - " +
                        "программа теперь реально проверяет версию протокола, а не просто факт, что порт открыт.",
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false",
                        "Для полного отключения SMBv1 может потребоваться перезагрузка компьютера.",
                        S("Отключить SMBv1 на сервере", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false"),
                        S("Отключить компонент Windows SMB1Protocol", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null"));
                case "EXP-TELNET":
                    return Act("Отключить сервер Telnet",
                        "Служба Telnet (tlntsvr) будет остановлена и отключена. Подключения по Telnet перестанут работать - используйте SSH.",
                        "Set-Service tlntsvr -StartupType Manual; Start-Service tlntsvr", "",
                        S("Остановить службу Telnet", "Stop-Service tlntsvr -Force"),
                        S("Отключить автозапуск службы Telnet", "Set-Service tlntsvr -StartupType Disabled"));
                case "EXP-RDP":
                    return Act("Защитить удалённый рабочий стол (RDP)",
                        "Будет включена проверка подлинности на уровне сети (NLA), а входящий RDP разрешён только из локальной подсети. " +
                        "Подключения к этому компьютеру из других сетей (в том числе из интернета) перестанут работать - используйте VPN. " +
                        "Порт 3389 останется открытым внутри локальной сети, поэтому повторное сканирование из этой сети может снова показать этот пункт.",
                        "Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress Any", "",
                        S("Включить проверку подлинности на уровне сети (NLA)",
                          "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"),
                        S("Разрешить входящий RDP только из локальной подсети",
                          "Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress LocalSubnet"));
                case "SNMP-PUBLIC":
                    return Act("Отключить службу SNMP",
                        "Служба SNMP будет остановлена и отключена. Системы мониторинга, опрашивающие этот компьютер по SNMP, перестанут получать данные. " +
                        "Если SNMP нужен - не отключайте, а смените community и ограничьте доступ (см. подробную инструкцию).",
                        "Set-Service SNMP -StartupType Automatic; Start-Service SNMP", "",
                        S("Остановить службу SNMP", "Stop-Service SNMP -Force"),
                        S("Отключить автозапуск службы SNMP", "Set-Service SNMP -StartupType Disabled"));
                case "UPNP-SSDP":
                    return Act("Отключить службы обнаружения UPnP/SSDP",
                        "Будут остановлены и отключены службы «Обнаружение SSDP» (SSDPSRV) и «Узел универсальных PNP-устройств» (upnphost). " +
                        "Может перестать работать автоматическое обнаружение медиаустройств и некоторых принтеров/телевизоров в сети.",
                        "Set-Service SSDPSRV -StartupType Manual; Set-Service upnphost -StartupType Manual; Start-Service SSDPSRV", "",
                        S("Остановить службу SSDPSRV", "Stop-Service SSDPSRV -Force"),
                        S("Отключить автозапуск SSDPSRV", "Set-Service SSDPSRV -StartupType Disabled"),
                        S("Остановить службу upnphost", "Stop-Service upnphost -Force"),
                        S("Отключить автозапуск upnphost", "Set-Service upnphost -StartupType Disabled"));
                case "EXP-VNC":
                    return BlockPort("Закрыть порт VNC", f.Port, "tcp", "Удалённое управление через VNC перестанет работать.");
                case "EXP-REDIS":
                    return BlockPort("Закрыть порт Redis", f.Port, "tcp", "Приложения на других компьютерах потеряют доступ к Redis.");
                case "EXP-MONGODB":
                    return BlockPort("Закрыть порт MongoDB", f.Port, "tcp", "Приложения на других компьютерах потеряют доступ к базе.");
                case "EXP-ELASTIC":
                    return BlockPort("Закрыть порт Elasticsearch", f.Port, "tcp", "Приложения на других компьютерах потеряют доступ к Elasticsearch.");
                case "EXP-DOCKER":
                    return BlockPort("Закрыть порт Docker API", f.Port, "tcp", "Удалённое управление Docker по сети перестанет работать.");
                case "EXP-MEMCACHED":
                    return BlockPort("Закрыть порт Memcached", f.Port, "tcp", "Приложения на других компьютерах потеряют доступ к кэшу.");
                case "EXP-MYSQL":
                    return BlockPort("Закрыть порт MySQL", f.Port, "tcp", "Приложения на других компьютерах потеряют доступ к базе данных.");
            }
            if (f.Id.StartsWith("TLS-LEGACY"))
                return Act("Отключить TLS 1.0 и 1.1 (SCHANNEL)",
                    "В реестре Windows будут отключены серверные протоколы TLS 1.0 и TLS 1.1 для служб, использующих системную библиотеку SCHANNEL (IIS, RDP и др.). " +
                    "Старые клиенты (Windows XP, Android 4, старые версии Java) перестанут подключаться. Если порт обслуживает nginx, Apache или другая программа с собственной библиотекой TLS, " +
                    "это не поможет - настройте её по подробной инструкции.",
                    "Реестр: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server и TLS 1.1\\Server - удалите параметры Enabled и DisabledByDefault",
                    "Перезагрузите компьютер, чтобы изменения вступили в силу.",
                    S("Отключить серверные протоколы TLS 1.0 и 1.1",
                      "foreach ($p in 'TLS 1.0','TLS 1.1') { $k = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\' + $p + '\\Server'; New-Item -Path $k -Force | Out-Null; New-ItemProperty -Path $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null; New-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null }"));
            return null;
        }

        public static string Script(FixAction a)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("# Запускать в PowerShell от имени администратора");
            sb.AppendLine();
            foreach (FixStep st in a.Steps)
            {
                sb.AppendLine("# " + st.Name);
                sb.AppendLine(st.Cmd);
                sb.AppendLine();
            }
            sb.AppendLine("# Откат изменений:");
            sb.AppendLine("# " + a.Undo);
            return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
        }

        // Запуск исправления с правами администратора (запрос UAC). Возвращает текст результата.
        public static string Run(FixAction a, Finding f, HostInfo h)
        {
            string dir = AppPaths.DataDir();
            string log = Path.Combine(dir, "fix-result.txt");
            string ps1 = Path.Combine(dir, "fix-run.ps1");
            if (File.Exists(log)) File.Delete(log);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("$ErrorActionPreference = 'Stop'");
            sb.AppendLine("$out = @()");
            foreach (FixStep st in a.Steps)
                sb.AppendLine("try { " + st.Cmd + "; $out += '[OK] " + st.Name + "' } catch { $out += '[ОШИБКА] " + st.Name + ": ' + $_.Exception.Message }");
            sb.AppendLine("$out | Out-File -FilePath '" + log.Replace("'", "''") + "' -Encoding UTF8");
            File.WriteAllText(ps1, sb.ToString(), new UTF8Encoding(true));

            ProcessStartInfo psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + ps1 + "\"");
            psi.Verb = "runas";
            psi.UseShellExecute = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            try
            {
                using (Process p = Process.Start(psi))
                {
                    if (p == null || !p.WaitForExit(180000))
                        return "Не удалось дождаться завершения скрипта. Проверьте результат вручную.";
                }
            }
            catch (Win32Exception ex)
            {
                if (ex.NativeErrorCode == 1223) return "Отменено: запрос прав администратора (UAC) не подтверждён. Ничего не изменено.";
                return "Не удалось запустить PowerShell: " + ex.Message;
            }
            string result = File.Exists(log) ? File.ReadAllText(log, Encoding.UTF8).Trim()
                                             : "Скрипт не вернул результат (возможно, выполнение запрещено политикой безопасности).";
            try
            {
                File.AppendAllText(Path.Combine(dir, "fixes.log"),
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + h.Ip + ":" + f.Port + "  " + f.Id + "\r\n" + result +
                    "\r\nОткат: " + a.Undo + "\r\n\r\n", new UTF8Encoding(true));
            }
            catch (Exception) { }
            string nl = "\r\n";
            return result + nl + nl + (a.After != "" ? a.After + nl + nl : "") +
                   "Чтобы отменить изменения, выполните в PowerShell от имени администратора:" + nl + a.Undo + nl + nl +
                   "Журнал исправлений: " + Path.Combine(dir, "fixes.log") + nl +
                   "Запустите повторное сканирование, чтобы убедиться в результате.";
        }

        // ---------- подробные инструкции ----------
        static string Lookup(string id)
        {
            string best = "";
            foreach (string k in Man.Keys)
                if (id.StartsWith(k) && k.Length > best.Length) best = k;
            return best == "" ? "" : Man[best];
        }

        public static string Manual(Finding f, HostInfo h)
        {
            string nl = "\r\n";
            StringBuilder sb = new StringBuilder();
            sb.Append(f.Title + nl + nl);
            sb.Append("Где: " + h.Ip + ":" + f.Port + (h.Name != "" ? " (" + h.Name + ")" : "") + (h.Os != "" ? ", ОС: " + h.Os : "") + nl);
            if (f.Desc != "") sb.Append("Почему это опасно: " + f.Desc + nl);
            sb.Append(nl + "КАК МОЖЕТ ВОСПОЛЬЗОВАТЬСЯ ЗЛОУМЫШЛЕННИК" + nl +
                      (f.Attack != "" ? f.Attack : "Описание сценария атаки для этой находки отсутствует.") + nl);
            sb.Append(nl + "ПОШАГОВАЯ ИНСТРУКЦИЯ" + nl + nl);
            string body = Lookup(f.Id);
            if (body == "")
                body = "Общая рекомендация: " + f.Rec + "\n\nЕсли сервис не нужен - остановите и отключите его. Если нужен - обновите ПО до актуальной версии, " +
                       "ограничьте доступ к нему межсетевым экраном только доверенными адресами и включите аутентификацию.";
            sb.Append(body.Replace("\r\n", "\n").Replace("\n", nl));
            sb.Append(nl + nl + "КАК ПРОВЕРИТЬ" + nl + "Повторите сканирование этого хоста в NetWarden: находка должна исчезнуть. Результаты можно сравнить на вкладке История.");
            sb.Append(nl + nl + "Проверить по российской базе уязвимостей БДУ ФСТЭК: " + Refs.Bdu(f.Title));
            if (f.Cve != "") sb.Append(nl + "Подробности в NVD: " + Refs.Nvd(f.Cve.Split(',')[0].Trim()));
            return sb.ToString();
        }

        static void M(Dictionary<string, string> d, string key, string text) { d[key] = text.Trim(); }

        static Dictionary<string, string> BuildManual()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            M(d, "SMB-V1-ENABLED", @"
Эта находка означает, что программа по-настоящему проверила протокол (не просто ""порт 445 открыт"") и сервер согласился
работать по устаревшему SMBv1. Это не связано с тем, нужен ли вам общий доступ к файлам - исправление ниже НЕ закрывает
порт 445 и НЕ отключает ваши общие папки, отключается только старый и опасный протокол. После этого шага повторное
сканирование должно показать уже не эту находку, а информационную ""SMB доступен (SMB2/3)"" - это и есть подтверждение,
что проблема решена, а не ""программа опять врёт"".

Windows (на самом компьютере, PowerShell от имени администратора: правый клик по кнопке Пуск - Терминал (администратор)):
1. Отключите устаревший SMBv1:
     Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
     Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
   Может потребоваться перезагрузка компьютера, чтобы изменение полностью применилось.
2. Проверьте результат командой:
     Get-SmbServerConfiguration | Select EnableSMB1Protocol
   должно быть False.
3. Общий доступ к вашим папкам трогать не нужно - он продолжит работать по SMB2/3 без каких-либо действий с вашей стороны.
   Дополнительно (необязательно, но полезно): включите обязательное подписывание пакетов -
     Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

Linux (Samba): в /etc/samba/smb.conf в разделе [global] добавьте
     server min protocol = SMB2
затем: sudo systemctl restart smbd  - это тоже отключает только SMBv1, общие папки Samba продолжат работать.

Маршрутизатор: независимо от этой находки хорошая практика - убедиться, что порты 445 и 139 не проброшены в интернет
(общий доступ к файлам не предназначен для прямого доступа из внешней сети).");
            M(d, "SMB-OPEN-MODERN", @"
Это информационная находка, а не уязвимость, которую нужно устранять. Порт 445 открыт - это нормально и ожидаемо, если
в сети используется общий доступ к файлам или принтерам (в том числе ваши общие папки). Проверка по протоколу показала,
что сервер НЕ отвечает на устаревший SMBv1, то есть главный исторический риск (EternalBlue/WannaCry) здесь не актуален.
Закрывать порт 445 не нужно - это отключит общий доступ к файлам.

Если хотите снизить риск дальше (необязательно):
1. Используйте длинные уникальные пароли для учётных записей Windows, у которых есть доступ к общим папкам.
2. Включите обязательное подписывание SMB-пакетов (защита от подмены трафика в сети):
     Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
3. Если доступ к папкам нужен только определённым людям - используйте права доступа NTFS/общего ресурса, а не общий
   доступ 'для всех'.
4. На домашнем/офисном маршрутизаторе убедитесь, что порт 445 не проброшен в интернет - общий доступ к файлам
   предназначен для локальной сети.");
            M(d, "SMB-OPEN-UNKNOWN", @"
Порт 445 открыт, но программа не смогла однозначно определить версию протокола (сервер ответил не в ожидаемом формате,
либо не ответил вовсе на тестовый запрос - такое бывает из-за нестандартной реализации SMB, антивируса или фильтрации
пакетов). Это не обязательно означает проблему - проверьте вручную, не закрывая порт заранее:

Windows (PowerShell от администратора):
     Get-SmbServerConfiguration | Select EnableSMB1Protocol
Если выводится False - всё в порядке, общий доступ к файлам можно не трогать.
Если True - отключите так же, как описано для находки ""Включён устаревший протокол SMBv1"":
     Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

Linux (Samba): проверьте /etc/samba/smb.conf на строку 'server min protocol' - если её нет или она ниже SMB2,
добавьте 'server min protocol = SMB2' и перезапустите: sudo systemctl restart smbd");
            M(d, "EXP-TELNET", @"
Windows: Win+R - optionalfeatures - снимите галочки 'Клиент Telnet' и 'Сервер Telnet'. Или в PowerShell (администратор):
     Stop-Service tlntsvr -Force; Set-Service tlntsvr -StartupType Disabled
Linux: sudo systemctl disable --now telnet.socket   (или отключите службу telnet в xinetd/inetd), затем удалите пакет:
     sudo apt remove telnetd     /     sudo dnf remove telnet-server
Сетевое оборудование (коммутатор, маршрутизатор, IP-камера): в веб-интерфейсе или командной строке отключите Telnet и включите SSH.
     Пример для Cisco:  line vty 0 4  /  transport input ssh
Для управления используйте SSH:  ssh пользователь@адрес");
            M(d, "EXP-RDP", @"
1. Включите проверку подлинности на уровне сети (NLA): Win+R - SystemPropertiesRemote - отметьте 'Разрешить подключения только с компьютеров с проверкой подлинности на уровне сети'.
2. Если удалённый рабочий стол не нужен - выключите его в том же окне ('Не разрешать удалённые подключения к этому компьютеру').
3. Ограничьте доступ своей подсетью (PowerShell от администратора):
     Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress LocalSubnet
4. Никогда не пробрасывайте порт 3389 в интернет на маршрутизаторе. Для доступа извне используйте VPN или шлюз удалённых рабочих столов.
5. Используйте длинные пароли и включите блокировку учётной записи после неудачных попыток: secpol.msc - Политики учётных записей - Политика блокировки учётных записей. По возможности включите многофакторную аутентификацию.
6. Установите все обновления Windows.");
            M(d, "EXP-VNC", @"
1. Если VNC не нужен - остановите и отключите службу (Windows: services.msc - служба VNC Server - Тип запуска: Отключена; Linux: sudo systemctl disable --now vncserver@:1).
2. Если нужен - не оставляйте его открытым в сеть: пускайте через SSH-туннель (ssh -L 5901:localhost:5901 пользователь@сервер) или через VPN.
3. Закройте порты 5900-5910 в брандмауэре для всех, кроме доверенных адресов.
4. Задайте длинный пароль и включите шифрование соединения. Либо замените VNC на RDP/SSH через VPN.");
            M(d, "EXP-REDIS", @"
1. Откройте redis.conf (Linux: /etc/redis/redis.conf; Windows: redis.windows.conf).
2. Слушайте только локальный адрес:   bind 127.0.0.1
3. Включите защищённый режим:         protected-mode yes
4. Задайте пароль:                    requirepass <длинный_случайный_пароль>   (в Redis 6+ лучше использовать ACL)
5. Перезапустите службу:              sudo systemctl restart redis
6. Закройте порт 6379 в брандмауэре (sudo ufw deny 6379  или  firewall-cmd --remove-port=6379/tcp).
7. Если Redis был доступен из сети - проверьте сервер на следы взлома: чужие ключи, изменённые задания cron, лишние ключи в ~/.ssh/authorized_keys.");
            M(d, "EXP-MONGODB", @"
1. В /etc/mongod.conf задайте:   net:  bindIp: 127.0.0.1   (или внутренний адрес сервера приложений).
2. Включите авторизацию:         security:  authorization: enabled
3. Создайте администратора (mongosh):  use admin  /  db.createUser({user:'admin', pwd:passwordPrompt(), roles:['root']})
4. Перезапустите: sudo systemctl restart mongod
5. Закройте порт 27017 в брандмауэре для внешних адресов.
6. Проверьте базы на признаки взлома: вымогательские записи, незнакомые пользователи.");
            M(d, "EXP-ELASTIC", @"
1. В elasticsearch.yml:   network.host: 127.0.0.1   (или внутренний адрес)   и   xpack.security.enabled: true
2. Задайте пароли: bin/elasticsearch-reset-password -u elastic
3. Включите TLS: xpack.security.http.ssl.enabled: true
4. Закройте порты 9200 и 9300 для внешних адресов; для доступа приложений используйте прокси с аутентификацией.
5. Перезапустите службу и проверьте журналы на подозрительные запросы.");
            M(d, "EXP-DOCKER", @"
1. Откройте настройки демона: Linux - /etc/docker/daemon.json (и каталог /etc/systemd/system/docker.service.d/); Windows - %programdata%\docker\config\daemon.json.
2. Уберите адрес tcp://0.0.0.0:2375 из параметра hosts (или ключа -H). Оставьте только unix-сокет.
3. Если удалённый доступ нужен - включите TLS-аутентификацию клиентов (tlsverify, tlscacert, tlscert, tlskey, порт 2376) или используйте доступ по SSH:  docker -H ssh://пользователь@хост
4. Перезапустите: sudo systemctl daemon-reload && sudo systemctl restart docker
5. Закройте порты 2375 и 2376 в брандмауэре для внешних адресов.
6. Если API был открыт, считайте хост потенциально скомпрометированным: проверьте контейнеры (docker ps -a), образы, смонтированные каталоги, задания cron.");
            M(d, "EXP-MEMCACHED", @"
1. В /etc/memcached.conf:   -l 127.0.0.1   (слушать только локальный адрес)   и   -U 0   (отключить UDP).
2. Перезапустите: sudo systemctl restart memcached
3. Закройте порт 11211 (TCP и UDP) в брандмауэре для внешних адресов.
4. Если доступ по сети нужен - включите SASL-аутентификацию и используйте изолированную внутреннюю сеть.");
            M(d, "EXP-MYSQL", @"
1. В my.cnf / mysqld.cnf:   bind-address = 127.0.0.1   (или внутренний адрес сервера приложений).
2. Удалите анонимных пользователей и ограничьте учётные записи конкретными адресами вместо '%'.
3. Перезапустите: sudo systemctl restart mysql
4. Закройте порт 3306 в брандмауэре для недоверенных адресов; включите шифрование: require_secure_transport = ON.
5. Используйте сложные пароли и отдельные учётные записи приложений с минимальными правами.");
            M(d, "SSH-", @"
1. Узнайте версию: ssh -V   (или  dpkg -l openssh-server  /  rpm -q openssh-server).
2. Обновите пакет:
     Debian/Ubuntu:        sudo apt update && sudo apt install --only-upgrade openssh-server
     RHEL/CentOS/Fedora:   sudo dnf upgrade openssh-server
     Windows (OpenSSH):    Параметры - Приложения - Дополнительные компоненты, либо  winget upgrade Microsoft.OpenSSH.Beta
3. Перезапустите службу: sudo systemctl restart ssh   (или sshd).
4. Важно: дистрибутивы часто исправляют уязвимости, не меняя номер версии (backport). Если версия в баннере старая, а пакет свежий
   (проверьте: apt changelog openssh-server | grep CVE), угроза может быть уже закрыта - NetWarden судит только по баннеру.
5. Дополнительно: отключите вход по паролю (PasswordAuthentication no) и входите по ключам; ограничьте доступ брандмауэром.
   Для regreSSHion временная мера - LoginGraceTime 0 в sshd_config (есть риск отказа в обслуживании, поэтому обновление предпочтительнее).");
            M(d, "FTP-VSFTPD-BACKDOOR", @"
1. Считайте сервер потенциально скомпрометированным: бэкдор даёт удалённую оболочку.
2. Изолируйте сервер от сети и сохраните журналы (/var/log/vsftpd.log, /var/log/auth.log).
3. Удалите ПО и поставьте чистую версию из официального репозитория дистрибутива:
     sudo apt remove --purge vsftpd && sudo apt install vsftpd      (проверьте: vsftpd -v  - версия не должна быть 2.3.4)
4. Проверьте систему: неизвестные пользователи (cat /etc/passwd), открытые порты (ss -tulpn), задания cron, ключи в ~/.ssh/authorized_keys.
5. Смените все пароли и ключи, которые хранились на сервере. При сомнениях - переустановите систему.");
            M(d, "HTTP-APACHE-PATHTRAV", @"
1. Проверьте версию: apache2 -v   (или httpd -v).
2. Обновите до 2.4.51 или новее:
     sudo apt update && sudo apt install --only-upgrade apache2      (RHEL: sudo dnf upgrade httpd)
   Для Windows (XAMPP, Apache Lounge) скачайте актуальную сборку и замените файлы.
3. Временная защита до обновления: запретите доступ к корню файловой системы и разрешайте только нужные каталоги:
     <Directory />
         Require all denied
     </Directory>
4. Перезапустите: sudo systemctl restart apache2
5. Проверьте access.log на запросы с последовательностями /.%2e/ - это следы эксплуатации. При подозрении считайте сервер скомпрометированным.");
            M(d, "HTTP-NGINX-RESOLVER", @"
1. Проверьте версию: nginx -v
2. Обновите до 1.20.1+ (стабильная ветка) или 1.21.0+ (mainline):
     sudo apt install --only-upgrade nginx      /      sudo dnf upgrade nginx      (либо подключите репозиторий nginx.org)
3. Временная мера: если директива resolver не используется - уязвимость не эксплуатируется; если используется - указывайте только доверенный внутренний DNS-сервер.
4. Проверьте конфигурацию и перезапустите: sudo nginx -t && sudo systemctl restart nginx
5. Баннер может быть устаревшим при бэкпорте исправления - сверьтесь с changelog пакета.");
            M(d, "HTTP-IIS-OLD", @"
1. Версия IIS привязана к версии Windows: IIS 7.5 - Windows 7 / Server 2008 R2, 8.0 - Server 2012, 8.5 - Server 2012 R2.
2. Планируйте переход на поддерживаемую ОС (Windows Server 2019/2022 или новее) и перенос сайтов.
3. До миграции: установите все доступные обновления, удалите неиспользуемые роли и компоненты (Диспетчер сервера - Управление - Удалить роли и компоненты), ограничьте доступ брандмауэром.
4. Включите современный TLS (1.2+) и отключите старые протоколы (утилита IIS Crypto).");
            string tls = @"
Оставьте только TLS 1.2 и 1.3. Что именно делать, зависит от программы, которая слушает порт:
- nginx:    ssl_protocols TLSv1.2 TLSv1.3;     затем   sudo nginx -t && sudo systemctl reload nginx
- Apache:   SSLProtocol -all +TLSv1.2 +TLSv1.3   затем   sudo systemctl restart apache2
- HAProxy:  ssl-min-ver TLSv1.2
- IIS, RDP и другие службы Windows (SCHANNEL): запустите утилиту IIS Crypto (Nartac) и примените шаблон Best Practices, либо отключите протоколы в реестре:
     HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server  и  ...\TLS 1.1\Server:  Enabled = 0 (DWORD), DisabledByDefault = 1.
  Затем перезагрузите компьютер.
Перед отключением убедитесь, что старые клиенты (Windows XP, Android 4, Java 6) вам больше не нужны.
Проверка: openssl s_client -connect адрес:порт -tls1   - соединение должно завершиться ошибкой.";
            M(d, "TLS-LEGACY", tls);
            string cert = @"
1. Получите новый сертификат: Let's Encrypt (проверка: certbot renew --dry-run; продление: certbot renew), коммерческий УЦ или внутренний УЦ организации.
2. Установите сертификат:
     nginx/Apache - обновите пути ssl_certificate / SSLCertificateFile и перезагрузите службу;
     IIS - импортируйте сертификат в хранилище 'Личные' и выберите его в привязках сайта (Привязки - https - Изменить);
     RDP - оснастка certlm.msc.
3. Настройте автоматическое продление (для certbot - systemd timer certbot.timer) и мониторинг срока действия.
4. Самоподписанный сертификат для внутренних устройств допустим, если вы проверили его отпечаток вручную; для сервисов, доступных пользователям, применяйте сертификат доверенного УЦ.";
            M(d, "TLS-CERT", cert);
            M(d, "TLS-SELF-SIGNED", cert);
            M(d, "WEB-NO-XFO", @"
Добавьте заголовок X-Frame-Options: DENY (или SAMEORIGIN, если страницы встраиваются на вашем же сайте):
     nginx (в блок server):   add_header X-Frame-Options DENY always;
     Apache:                  Header always set X-Frame-Options DENY      (нужен модуль headers: sudo a2enmod headers)
     IIS (web.config):
         <system.webServer>
           <httpProtocol>
             <customHeaders>
               <add name=""X-Frame-Options"" value=""DENY"" />
             </customHeaders>
           </httpProtocol>
         </system.webServer>
Современная альтернатива: заголовок Content-Security-Policy: frame-ancestors 'none'
После изменения перезагрузите службу: nginx - sudo systemctl reload nginx; Apache - sudo systemctl reload apache2.");
            M(d, "WEB-NO-XCTO", @"
Добавьте заголовок X-Content-Type-Options: nosniff:
     nginx:    add_header X-Content-Type-Options nosniff always;
     Apache:   Header always set X-Content-Type-Options nosniff
     IIS:      в customHeaders (web.config) добавьте элемент add с именем X-Content-Type-Options и значением nosniff.");
            M(d, "WEB-NO-HSTS", @"
ВАЖНО: включайте HSTS только когда HTTPS работает на всём сайте и поддоменах - браузеры запомнят правило на указанный срок.
     nginx:    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;
     Apache:   Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'
     IIS:      Диспетчер IIS - Заголовки ответа HTTP - добавить Strict-Transport-Security со значением max-age=31536000
Начните с небольшого срока (max-age=300), проверьте работу и затем увеличьте.");
            M(d, "WEB-POWERED-BY", @"
Уберите заголовок, раскрывающий технологию и версию:
     PHP:        в php.ini задайте expose_php = Off
     IIS:        в web.config внутри customHeaders добавьте элемент remove с именем X-Powered-By
     ASP.NET:    в web.config - атрибут enableVersionHeader=false у элемента httpRuntime
     Express:    app.disable('x-powered-by')
     nginx:      server_tokens off;   (скрывает версию nginx)
     Apache:     ServerTokens Prod  и  ServerSignature Off");
            M(d, "WEB-DIRLIST", @"
Отключите листинг каталогов:
     nginx:    autoindex off;     (в блоке location или server)
     Apache:   Options -Indexes   (в <Directory> или .htaccess)
     IIS:      Диспетчер IIS - выберите сайт - 'Просмотр каталогов' - Отключить
Затем убедитесь, что в каталогах нет файлов, которые не должны быть публичными (резервные копии, конфигурации, выгрузки).");
            M(d, "WEB-COOKIE-HTTPONLY", @"
Установите для cookie сессии флаги HttpOnly, Secure (для HTTPS) и SameSite:
     PHP (php.ini):   session.cookie_httponly = 1   session.cookie_secure = 1   session.cookie_samesite = Lax
     ASP.NET:         в web.config - httpCookies httpOnlyCookies=true requireSSL=true
     Express:         res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'lax' })
Для других фреймворков найдите настройку cookie/session и включите те же флаги.");
            M(d, "WEB-EXPOSED", @"
1. Немедленно удалите файл с рабочего сервера или переместите его за пределы корня сайта.
2. Если это .env, .git, резервная копия или конфигурация - считайте, что содержащиеся пароли, ключи API и токены СКОМПРОМЕТИРОВАНЫ, и смените их.
3. Запретите отдачу скрытых файлов на уровне сервера:
     nginx:    location ~ /\. { deny all; }
     Apache:   <FilesMatch ^\.>  Require all denied  </FilesMatch>
     IIS:      Фильтрация запросов - Скрытые сегменты - добавьте .git, .env, .svn
4. Для .git: не разворачивайте сайт командой git clone в корень веб-сервера; публикуйте только собранные файлы (CI/CD, rsync).
5. server-status и phpinfo: удалите страницу или ограничьте доступ (Apache: <Location /server-status>  Require local  </Location>; PHP: удалите phpinfo.php и задайте expose_php = Off).
6. Проверьте журналы доступа: не скачивали ли файл посторонние.");
            M(d, "FTP-ANON", @"
Отключите анонимный вход:
     vsftpd:     в /etc/vsftpd.conf задайте anonymous_enable=NO и перезапустите: sudo systemctl restart vsftpd
     ProFTPD:    удалите или закомментируйте блок <Anonymous ...> в proftpd.conf, затем sudo systemctl restart proftpd
     IIS FTP:    Диспетчер IIS - сайт FTP - 'Проверка подлинности FTP' - отключите Анонимная проверка подлинности
Если FTP используется только для обмена файлами, лучше перейти на SFTP (входит в SSH) или FTPS.");
            M(d, "SNMP-PUBLIC", @"
1. Если SNMP не нужен - отключите:
     Windows (PowerShell, администратор):  Stop-Service SNMP -Force; Set-Service SNMP -StartupType Disabled
     Linux:                                sudo systemctl disable --now snmpd
2. Если нужен - замените community по умолчанию 'public' на длинное секретное значение и ограничьте источники:
     Windows:  services.msc - Служба SNMP - Свойства - вкладка 'Безопасность' - удалите public, добавьте свою community и разрешите только адреса системы мониторинга.
     Linux (/etc/snmp/snmpd.conf):  rocommunity <секрет> 192.168.1.10     (вместо строки rocommunity public)
3. Лучше перейти на SNMPv3 с аутентификацией и шифрованием:
     sudo net-snmp-create-v3-user -ro -A <пароль_аутентификации> -a SHA -X <пароль_шифрования> -x AES monitoruser
4. Для маршрутизаторов, принтеров и коммутаторов смените community в веб-интерфейсе устройства.
5. Закройте порт UDP 161 в брандмауэре для всех, кроме системы мониторинга.");
            M(d, "UPNP-SSDP", @"
1. Маршрутизатор: откройте веб-интерфейс - раздел 'Дополнительно / Переадресация / UPnP' - отключите UPnP, если он вам не нужен. Проверьте таблицу проброшенных портов UPnP и удалите лишнее.
2. Windows (PowerShell, администратор):
     Stop-Service SSDPSRV -Force; Set-Service SSDPSRV -StartupType Disabled
     Stop-Service upnphost -Force; Set-Service upnphost -StartupType Disabled
3. Linux: удалите или отключите minissdpd / miniupnpd:  sudo systemctl disable --now miniupnpd
4. Умные телевизоры, медиасерверы и принтеры: в их настройках отключите DLNA/UPnP, если функция не нужна.
5. Убедитесь, что UPnP не открыт во внешнюю сеть (порт UDP 1900 на WAN-интерфейсе).");
            return d;
        }
    }

    // ===================== КАРТА СЕТИ =====================
    class MapNode
    {
        public HostInfo Host;
        public MapNode Hub;
        public string Label = "";
        public int Count;
        public RectangleF Rect;
    }

    class NetMapPanel : Panel
    {
        public event Action<HostInfo> HostSelected;
        public event Action<HostInfo> HostActivated;

        List<HostInfo> hosts = new List<HostInfo>();
        List<MapNode> nodes = new List<MapNode>();
        List<MapNode> hubs = new List<MapNode>();
        string gateway = "";
        HostInfo hover, selected;
        ToolTip tip = new ToolTip();
        int contentW = 600, contentH = 400;
        const float NW = 64f, NH = 42f;

        static readonly Font FTag = new Font("Segoe UI", 9f, FontStyle.Bold);
        static readonly Font FIp = new Font("Segoe UI", 8f);
        static readonly Font FSmall = new Font("Segoe UI", 7f);
        static readonly Font FHub = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        static readonly StringFormat SfCenter = MakeCenter();

        static StringFormat MakeCenter()
        {
            StringFormat sf = new StringFormat();
            sf.Alignment = StringAlignment.Center;
            sf.LineAlignment = StringAlignment.Center;
            sf.Trimming = StringTrimming.EllipsisCharacter;
            sf.FormatFlags = StringFormatFlags.NoWrap;
            return sf;
        }

        public NetMapPanel()
        {
            AutoScroll = true;
            BackColor = Color.White;
            DoubleBuffered = true;
            ResizeRedraw = true;
            SetStyle(ControlStyles.Selectable, true);
            TabStop = true;
            tip.AutoPopDelay = 20000;
            gateway = FindGateway();
        }

        public string Gateway { get { return gateway; } }

        static string FindGateway()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (GatewayIPAddressInformation g in ni.GetIPProperties().GatewayAddresses)
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0")
                            return g.Address.ToString();
                }
            }
            catch (Exception) { }
            return "";
        }

        static string Prefix(string ip)
        {
            int k = ip.LastIndexOf('.');
            return k > 0 ? ip.Substring(0, k) : ip;
        }

        static bool HasPort(HostInfo h, params int[] ports)
        {
            foreach (PortInfo p in h.Ports) if (Array.IndexOf(ports, p.Port) >= 0) return true;
            return false;
        }

        static bool HasSvc(HostInfo h, params string[] svcs)
        {
            foreach (PortInfo p in h.Ports) if (Array.IndexOf(svcs, p.Service) >= 0) return true;
            return false;
        }

        public static string[] DevType(HostInfo h, string gw)
        {
            string os = (h.Os ?? "").ToLower();
            if (h.Ip == gw) return new string[] { "GW", "Шлюз по умолчанию (маршрутизатор)" };
            if (os.Contains("windows") || HasPort(h, 135, 139, 445, 3389, 5985)) return new string[] { "WIN", "Windows-хост" };
            if (os.Contains("routeros") || os.Contains("cisco") || os.Contains("сетевое")) return new string[] { "NET", "Сетевое оборудование" };
            if (os.Contains("linux") || os.Contains("unix") || os.Contains("bsd") || os.Contains("macos") || HasPort(h, 22))
                return new string[] { "NIX", "Linux/Unix/macOS-хост" };
            if (HasSvc(h, "mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "elasticsearch")) return new string[] { "DB", "Сервер базы данных" };
            if (HasSvc(h, "http", "https")) return new string[] { "WEB", "Веб-сервер" };
            return new string[] { "HOST", "Сетевое устройство" };
        }

        static string Worst(HostInfo h)
        {
            int best = 99;
            foreach (Finding f in h.Findings) { int i = Sev.Idx(f.Severity); if (i < best) best = i; }
            return best == 99 ? "" : Sev.Order[best];
        }

        static List<int> Rings(int n, out float outer)
        {
            List<int> caps = new List<int>();
            int left = n, r = 0;
            outer = 120f;
            while (left > 0)
            {
                float radius = 120f + 100f * r;
                int cap = (int)(2 * Math.PI * radius / 92f);
                if (cap < 6) cap = 6;
                int take = Math.Min(cap, left);
                caps.Add(take);
                left -= take;
                outer = radius;
                r++;
            }
            return caps;
        }

        public void SetHosts(List<HostInfo> list)
        {
            hosts = new List<HostInfo>(list);
            DoLayout();
            Invalidate();
        }

        void DoLayout()
        {
            nodes.Clear();
            hubs.Clear();
            SortedDictionary<string, List<HostInfo>> groups = new SortedDictionary<string, List<HostInfo>>(StringComparer.Ordinal);
            foreach (HostInfo h in hosts)
            {
                string k = Prefix(h.Ip);
                if (!groups.ContainsKey(k)) groups[k] = new List<HostInfo>();
                groups[k].Add(h);
            }
            if (groups.Count == 0) { AutoScrollMinSize = new Size(0, 0); return; }
            float maxOuter = 0f;
            foreach (List<HostInfo> grp in groups.Values)
            {
                float o;
                Rings(grp.Count, out o);
                if (o > maxOuter) maxOuter = o;
            }
            float cellW = 2f * (maxOuter + NW) + 40f;
            float cellH = 2f * (maxOuter + NH + 40f) + 40f;
            int cols = (int)Math.Ceiling(Math.Sqrt(groups.Count));
            int idx = 0;
            foreach (KeyValuePair<string, List<HostInfo>> kv in groups)
            {
                int col = idx % cols, row = idx / cols;
                idx++;
                float cx = cellW * (col + 0.5f), cy = cellH * (row + 0.5f);
                MapNode hub = new MapNode();
                hub.Label = kv.Key + ".0/24";
                hub.Count = kv.Value.Count;
                hub.Rect = new RectangleF(cx - 50f, cy - 16f, 100f, 32f);
                hubs.Add(hub);
                List<HostInfo> list = new List<HostInfo>(kv.Value);
                list.Sort(delegate(HostInfo a, HostInfo b)
                {
                    bool ga = a.Ip == gateway, gb = b.Ip == gateway;
                    if (ga != gb) return ga ? -1 : 1;
                    return Targets.ToUInt(a.Ip).CompareTo(Targets.ToUInt(b.Ip));
                });
                float o2;
                List<int> rings = Rings(list.Count, out o2);
                int pos = 0;
                for (int r = 0; r < rings.Count; r++)
                {
                    float radius = 120f + 100f * r;
                    int take = rings[r];
                    for (int i = 0; i < take; i++)
                    {
                        double ang = -Math.PI / 2 + 2 * Math.PI * i / take + (r % 2 == 1 ? Math.PI / take : 0);
                        float x = cx + (float)(radius * Math.Cos(ang));
                        float y = cy + (float)(radius * Math.Sin(ang));
                        MapNode n = new MapNode();
                        n.Host = list[pos++];
                        n.Hub = hub;
                        n.Rect = new RectangleF(x - NW / 2f, y - NH / 2f, NW, NH);
                        nodes.Add(n);
                    }
                }
            }
            contentW = (int)(cellW * cols);
            contentH = (int)(cellH * Math.Ceiling(groups.Count / (double)cols));
            AutoScrollMinSize = new Size(contentW, contentH);
        }

        static GraphicsPath RoundRect(RectangleF r, float rad)
        {
            float d = rad * 2f;
            GraphicsPath p = new GraphicsPath();
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        static PointF Mid(RectangleF r) { return new PointF(r.X + r.Width / 2f, r.Y + r.Height / 2f); }

        void Render(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            if (nodes.Count == 0)
            {
                using (SolidBrush muted = new SolidBrush(Theme.TextMuted))
                    g.DrawString("Нет данных. Запустите сканирование, чтобы построить карту сети.", FIp, muted, 20f, 20f);
                return;
            }
            using (Pen link = new Pen(Color.FromArgb(70, Theme.Electric), 1.4f))
            using (Pen gwLink = new Pen(Theme.Accent, 2.2f))
            {
                foreach (MapNode n in nodes)
                    g.DrawLine(n.Host.Ip == gateway ? gwLink : link, Mid(n.Hub.Rect), Mid(n.Rect));
            }
            foreach (MapNode hub in hubs)
            {
                using (GraphicsPath hp = RoundRect(hub.Rect, 10f))
                {
                    using (LinearGradientBrush hb = new LinearGradientBrush(hub.Rect, Theme.BgCardTop, Theme.BgCardBot, 90f))
                        g.FillPath(hb, hp);
                    using (Pen hbp = new Pen(Theme.BorderCyan, 1.2f)) g.DrawPath(hbp, hp);
                }
                using (SolidBrush ac = new SolidBrush(Theme.Accent)) g.DrawString(hub.Label, FHub, ac, hub.Rect, SfCenter);
                using (SolidBrush muted = new SolidBrush(Theme.TextMuted))
                    g.DrawString("хостов: " + hub.Count, FSmall, muted,
                                 new RectangleF(hub.Rect.X - 20f, hub.Rect.Bottom + 2f, hub.Rect.Width + 40f, 12f), SfCenter);
            }
            foreach (MapNode n in nodes) DrawNode(g, n);
        }

        // Простая векторная иконка устройства по его типу (GW/WIN/NIX/DB/WEB/NET/HOST), без внешних файлов.
        public static void DrawIcon(Graphics g, string kind, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f;
            Pen pen = new Pen(c, 2f);
            SolidBrush fill = new SolidBrush(Color.FromArgb(45, c));
            SolidBrush solid = new SolidBrush(c);
            try
            {
                switch (kind)
                {
                    case "GW": // маршрутизатор: корпус + две антенны + индикаторы
                    {
                        RectangleF body = new RectangleF(cx - 16f, cy - 2f, 32f, 13f);
                        g.FillRectangle(fill, body); g.DrawRectangle(pen, body.X, body.Y, body.Width, body.Height);
                        g.DrawLine(pen, cx - 8f, body.Y, cx - 13f, body.Y - 9f);
                        g.DrawLine(pen, cx + 8f, body.Y, cx + 13f, body.Y - 9f);
                        g.FillEllipse(solid, cx - 15f, body.Y - 12f, 4f, 4f);
                        g.FillEllipse(solid, cx + 11f, body.Y - 12f, 4f, 4f);
                        for (int i = 0; i < 3; i++) g.FillEllipse(solid, body.X + 5f + i * 9f, body.Bottom - 4f, 3f, 3f);
                        break;
                    }
                    case "NET": // коммутатор/сетевое оборудование: корпус с рядом портов
                    {
                        RectangleF body = new RectangleF(cx - 18f, cy - 7f, 36f, 15f);
                        g.FillRectangle(fill, body); g.DrawRectangle(pen, body.X, body.Y, body.Width, body.Height);
                        for (int i = 0; i < 6; i++) g.FillRectangle(solid, body.X + 3f + i * 5.2f, body.Bottom - 5f, 3f, 4f);
                        break;
                    }
                    case "DB": // база данных: классический цилиндр
                    {
                        float w = 26f, h = 24f, eh = 8f;
                        RectangleF topE = new RectangleF(cx - w / 2f, cy - h / 2f, w, eh);
                        RectangleF botE = new RectangleF(cx - w / 2f, cy + h / 2f - eh, w, eh);
                        g.FillRectangle(fill, cx - w / 2f, cy - h / 2f + eh / 2f, w, h - eh);
                        g.DrawLine(pen, cx - w / 2f, cy - h / 2f + eh / 2f, cx - w / 2f, cy + h / 2f - eh / 2f);
                        g.DrawLine(pen, cx + w / 2f, cy - h / 2f + eh / 2f, cx + w / 2f, cy + h / 2f - eh / 2f);
                        g.FillEllipse(fill, topE); g.DrawEllipse(pen, topE);
                        g.DrawArc(pen, botE.X, botE.Y, botE.Width, botE.Height, 0f, 180f);
                        break;
                    }
                    case "WEB": // веб/сервер: стойка из трёх полос с индикатором
                    {
                        RectangleF body = new RectangleF(cx - 15f, cy - 14f, 30f, 28f);
                        g.FillRectangle(fill, body); g.DrawRectangle(pen, body.X, body.Y, body.Width, body.Height);
                        for (int i = 0; i < 3; i++)
                        {
                            float yy = body.Y + 5f + i * 8f;
                            g.DrawLine(pen, body.X + 3f, yy, body.Right - 7f, yy);
                            g.FillEllipse(solid, body.Right - 7f, yy - 1.5f, 3f, 3f);
                        }
                        break;
                    }
                    case "WIN":
                    case "NIX":
                    case "HOST":
                    default: // компьютер: монитор на подставке
                    {
                        RectangleF screen = new RectangleF(cx - 15f, cy - 11f, 30f, 18f);
                        g.FillRectangle(fill, screen); g.DrawRectangle(pen, screen.X, screen.Y, screen.Width, screen.Height);
                        g.DrawLine(pen, cx, screen.Bottom, cx, screen.Bottom + 5f);
                        g.DrawLine(pen, cx - 9f, screen.Bottom + 5f, cx + 9f, screen.Bottom + 5f);
                        break;
                    }
                }
            }
            finally { pen.Dispose(); fill.Dispose(); solid.Dispose(); }
        }

        void DrawNode(Graphics g, MapNode n)
        {
            HostInfo h = n.Host;
            string worst = Worst(h);
            Color c = worst == "" ? Color.FromArgb(22, 163, 74) : Sev.Col(worst);
            RectangleF r = n.Rect;
            if (h == selected || h == hover)
            {
                RectangleF big = r;
                big.Inflate(5f, 5f);
                using (GraphicsPath gp = RoundRect(big, 11f))
                using (Pen hp = new Pen(Theme.Accent, h == selected ? 3f : 1.5f))
                    g.DrawPath(hp, gp);
            }
            using (GraphicsPath path = RoundRect(r, 8f))
            using (SolidBrush cardBg = new SolidBrush(Theme.BgCardBot))
            using (SolidBrush fill = new SolidBrush(Color.FromArgb(40, c)))
            using (Pen pen = new Pen(c, 2f))
            {
                g.FillPath(cardBg, path);
                g.FillPath(fill, path);
                g.DrawPath(pen, path);
            }
            string[] dt = DevType(h, gateway);
            DrawIcon(g, dt[0], r, c);
            using (SolidBrush ipBrush = new SolidBrush(Theme.TextMain))
                g.DrawString(h.Ip, FIp, ipBrush, new RectangleF(r.X - 20f, r.Bottom + 2f, r.Width + 40f, 13f), SfCenter);
            string sub = h.Name != "" ? h.Name : "портов: " + h.Ports.Count;
            using (SolidBrush subBrush = new SolidBrush(Theme.TextMuted))
                g.DrawString(sub, FSmall, subBrush, new RectangleF(r.X - 30f, r.Bottom + 15f, r.Width + 60f, 12f), SfCenter);
            if (h.Findings.Count > 0)
            {
                RectangleF b = new RectangleF(r.Right - 11f, r.Top - 9f, 20f, 18f);
                using (SolidBrush bb = new SolidBrush(c)) g.FillEllipse(bb, b);
                using (SolidBrush cnt = new SolidBrush(Theme.BgDeep))
                    g.DrawString(h.Findings.Count > 99 ? "99+" : h.Findings.Count.ToString(), FSmall, cnt, b, SfCenter);
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(BackColor);
            g.TranslateTransform(AutoScrollPosition.X, AutoScrollPosition.Y);
            Render(g);
        }

        protected override void OnScroll(ScrollEventArgs se)
        {
            base.OnScroll(se);
            Invalidate();
        }

        public void SaveImage(string path)
        {
            Bitmap bmp = new Bitmap(Math.Max(contentW, 300), Math.Max(contentH, 200));
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.White);
                Render(g);
            }
            bmp.Save(path, ImageFormat.Png);
            bmp.Dispose();
        }

        MapNode Hit(Point p)
        {
            float x = p.X - AutoScrollPosition.X, y = p.Y - AutoScrollPosition.Y;
            foreach (MapNode n in nodes) if (n.Rect.Contains(x, y)) return n;
            return null;
        }

        static string TipText(HostInfo h, string gw)
        {
            string[] dt = DevType(h, gw);
            List<string> ports = new List<string>();
            foreach (PortInfo p in h.Ports) { if (ports.Count >= 10) { ports.Add("..."); break; } ports.Add(p.Port.ToString()); }
            int crit = 0, high = 0;
            foreach (Finding f in h.Findings) { if (f.Severity == "critical") crit++; else if (f.Severity == "high") high++; }
            return h.Ip + (h.Name != "" ? "  (" + h.Name + ")" : "") + "\n" + dt[1] + "\n" + (h.Os != "" ? "ОС: " + h.Os + "\n" : "") + (h.Mac != "" ? "MAC: " + h.Mac + (h.Vendor != "" ? " (" + h.Vendor + ")" : "") + "\n" : "") +
                   "Открытые порты: " + (ports.Count == 0 ? "нет" : string.Join(", ", ports.ToArray())) + "\n" +
                   "Находок: " + h.Findings.Count + " (критических: " + crit + ", высоких: " + high + ")";
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            base.OnMouseEnter(e);
            Focus();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            MapNode n = Hit(e.Location);
            HostInfo h = n == null ? null : n.Host;
            if (h != hover)
            {
                hover = h;
                Cursor = h == null ? Cursors.Default : Cursors.Hand;
                if (h == null) tip.Hide(this); else tip.Show(TipText(h, gateway), this, e.X + 16, e.Y + 16);
                Invalidate();
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            hover = null;
            tip.Hide(this);
            Invalidate();
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            MapNode n = Hit(e.Location);
            if (n == null) return;
            selected = n.Host;
            Invalidate();
            if (HostSelected != null) HostSelected(n.Host);
        }

        protected override void OnMouseDoubleClick(MouseEventArgs e)
        {
            base.OnMouseDoubleClick(e);
            MapNode n = Hit(e.Location);
            if (n != null && HostActivated != null) HostActivated(n.Host);
        }
    }

    // ===================== ОКНО =====================
    // Кнопка с полностью ручной отрисовкой: скруглённые углы, тонкая окантовка, мягкое свечение
    // у основной (бирюзовой) кнопки при наведении, состояния hover/pressed/disabled.
    class NeoButton : Button
    {
        public bool Primary;
        bool hover, pressed;

        public NeoButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            ForeColor = Theme.TextMain;
            Cursor = Cursors.Hand;
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        // Без этого под скруглённой формой проступают квадратные углы системной заливки фона -
        // именно это выглядело как "неровная кнопка без полукруглых окончаний".
        protected override void OnPaintBackground(PaintEventArgs e)
        {
            Color bg = Parent != null ? Parent.BackColor : Theme.BgDeep;
            using (SolidBrush b = new SolidBrush(bg)) e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle b = ClientRectangle; b.Inflate(-1, -1);
            if (b.Width <= 0 || b.Height <= 0) return;
            using (GraphicsPath path = Theme.RoundRect(b, 7f))
            {
                Color borderC = Primary ? Theme.Accent : Theme.BorderCyan;
                Color fillTop = !Enabled ? Color.FromArgb(40, 48, 62)
                    : Primary ? (pressed ? Color.FromArgb(40, 170, 160) : hover ? Color.FromArgb(58, 214, 200) : Color.FromArgb(46, 196, 182))
                              : (pressed ? Color.FromArgb(34, 44, 62) : hover ? Color.FromArgb(40, 52, 74) : Color.FromArgb(28, 37, 54));
                Color fillBot = !Enabled ? Color.FromArgb(28, 34, 46) : Primary ? Color.FromArgb(24, 120, 112) : Color.FromArgb(16, 22, 34);
                // Единое мягкое свечение вплотную к контуру кнопки (без вынесенных колец - на маленькой кнопке
                // они выглядели как отдельные "уголки" по краям).
                if (Primary && Enabled && (hover || pressed))
                    using (Pen gp = new Pen(Color.FromArgb(90, Theme.Accent), 2.4f)) g.DrawPath(gp, path);
                using (LinearGradientBrush grad = new LinearGradientBrush(new PointF(0, b.Y), new PointF(0, b.Bottom), fillTop, fillBot))
                    g.FillPath(grad, path);
                using (Pen pen = new Pen(Enabled ? borderC : Theme.TextDim, 1.2f)) g.DrawPath(pen, path);
            }
            Color textC = !Enabled ? Theme.TextDim : (Primary ? Color.FromArgb(6, 24, 22) : Theme.TextMain);
            TextRenderer.DrawText(g, Text, Font, ClientRectangle, textC,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    // Полоса прогресса с ручной отрисовкой в тон теме (системный ProgressBar перекрасить нельзя).
    class NeoProgressBar : Control
    {
        int max = 100, val = 0;
        public int Maximum { get { return max; } set { max = Math.Max(1, value); Invalidate(); } }
        public int Value { get { return val; } set { val = Math.Max(0, Math.Min(max, value)); Invalidate(); } }

        public NeoProgressBar()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            Height = 10;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle b = ClientRectangle;
            if (b.Width <= 2 || b.Height <= 2) return;
            using (GraphicsPath track = Theme.RoundRect(b, b.Height / 2f))
            {
                using (SolidBrush bg = new SolidBrush(Color.FromArgb(24, 31, 46))) g.FillPath(bg, track);
                using (Pen p = new Pen(Theme.BorderDim, 1f)) g.DrawPath(p, track);
            }
            float frac = max > 0 ? (float)val / max : 0f;
            int w = (int)(b.Width * frac);
            if (w > 2)
            {
                Rectangle fillR = new Rectangle(b.X, b.Y, w, b.Height);
                using (GraphicsPath fp = Theme.RoundRect(fillR, b.Height / 2f))
                using (LinearGradientBrush grad = new LinearGradientBrush(fillR, Color.FromArgb(40, 190, 180), Theme.Accent, 0f))
                    g.FillPath(grad, fp);
            }
        }
    }

    class MainForm : Form
    {
        TextBox tbTargets;
        RichTextBox details;
        ComboBox cbProfile;
        CheckBox chkSkip;
        Button btnStart, btnStop, btnExport;
        TabControl tabs;
        TreeView tree;
        ListView lv;
        NeoProgressBar pb;
        Label status;
        SplitContainer split;
        System.Windows.Forms.Timer timer;
        Scanner scanner;
        ScanResult current;
        TextBox vulnDetails;
        RichTextBox mapDetails;
        SplitContainer vsplit, mapSplit;
        NetMapPanel netMap;
        ListView devLv, portLv;
        Button btnMyNet;
        CheckBox chkUdp, chkBrute;
        TextBox tbCustomPorts;
        Button btnUpdateDb;
        ToolTip tip = new ToolTip();
        Button btnFixRes, btnFixVuln;
        Finding curFinding;
        HostInfo curHost;
        List<HostInfo> mapHosts = new List<HostInfo>();

        static int WorstActionableIdx(IEnumerable<Finding> fs)
        {
            int best = 99;
            foreach (Finding f in fs) { int i = Sev.Idx(f.Severity); if (i <= 3 && i < best) best = i; } // idx 4 = "info", не считаем ошибкой
            return best;
        }

        static readonly string[] ProfNames = new string[] { "Быстрый (популярные порты)", "Стандартный (1-1024 и популярные)", "Полный (1-65535)", "Свой диапазон (указать справа)" };
        static readonly string[] ProfPorts = new string[] { "common", "1-1024,1433,1521,2375,3000,3306,3389,5432,5900,5985,6379,8000-8100,8443,9200,27017", "full", "" };
        static readonly int[] ProfTimeout = new int[] { 1000, 1500, 1500, 1500 };
        static readonly int[] ProfThreads = new int[] { 400, 300, 500, 400 };
        const int CustomProfileIdx = 3;

        Panel heroCard, paramsCard, bottomCard;
        Label heroStatus, heroMeta;
        DateTime scanStarted;

        static Panel Glass(Color top, Color bot, Color border, bool glow)
        {
            Panel p = new Panel();
            p.Dock = DockStyle.Fill; // критично: без этого панель остаётся в размере "по умолчанию" (~200x100),
                                     // и все элементы правее/ниже этой границы физически невидимы
            p.BackColor = Theme.BgDeep;
            p.Paint += delegate (object s, PaintEventArgs e) { Theme.PaintGlass(e.Graphics, ((Panel)s).ClientRectangle, top, bot, border, glow); };
            return p;
        }

        static void DarkField(Control c)
        {
            c.BackColor = Color.FromArgb(18, 24, 36);
            c.ForeColor = Theme.TextMain;
        }

        void OnComboDraw(object sender, DrawItemEventArgs e)
        {
            ComboBox cb = (ComboBox)sender;
            e.DrawBackground();
            bool sel = (e.State & DrawItemState.Selected) != 0;
            using (SolidBrush bg = new SolidBrush(sel ? Color.FromArgb(40, 54, 72) : Color.FromArgb(18, 24, 36))) e.Graphics.FillRectangle(bg, e.Bounds);
            if (e.Index >= 0)
                TextRenderer.DrawText(e.Graphics, cb.Items[e.Index].ToString(), cb.Font, e.Bounds, sel ? Theme.Accent : Theme.TextMain,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.Left);
            e.DrawFocusRectangle();
        }

        void OnTabDraw(object sender, DrawItemEventArgs e)
        {
            TabControl tc = (TabControl)sender;
            TabPage page = tc.TabPages[e.Index];
            bool sel = e.Index == tc.SelectedIndex;
            using (SolidBrush bg = new SolidBrush(sel ? Theme.BgCardTop : Theme.BgDeep)) e.Graphics.FillRectangle(bg, e.Bounds);
            if (sel)
                using (SolidBrush ac = new SolidBrush(Theme.Accent))
                    e.Graphics.FillRectangle(ac, e.Bounds.X, e.Bounds.Bottom - 3, e.Bounds.Width, 3);
            TextRenderer.DrawText(e.Graphics, page.Text.ToUpper(), tc.Font, e.Bounds, sel ? Theme.Accent : Theme.TextMuted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        // Общее тёмное оформление строк ListView: цветная полоса серьёзности слева и подсветка выбранной строки бирюзовым.
        void OnLvDrawHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (SolidBrush bg = new SolidBrush(Color.FromArgb(20, 27, 42))) e.Graphics.FillRectangle(bg, e.Bounds);
            using (Pen ln = new Pen(Theme.BorderDim)) e.Graphics.DrawLine(ln, e.Bounds.X, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            TextRenderer.DrawText(e.Graphics, e.Header.Text, e.Font, e.Bounds, Theme.TextMuted, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.LeftAndRightPadding);
        }

        void OnLvDrawItem(object sender, DrawListViewItemEventArgs e) { e.DrawDefault = false; }

        void OnLvDrawSub(object sender, DrawListViewSubItemEventArgs e)
        {
            bool sel = e.Item.Selected;
            Color rowBg = sel ? Color.FromArgb(28, 54, 60) : (e.ItemIndex % 2 == 0 ? Color.FromArgb(15, 20, 32) : Color.FromArgb(12, 16, 26));
            using (SolidBrush bg = new SolidBrush(rowBg)) e.Graphics.FillRectangle(bg, e.Bounds);
            if (sel) using (Pen pen = new Pen(Theme.Accent)) e.Graphics.DrawLine(pen, e.Bounds.X, e.Bounds.Y, e.Bounds.X, e.Bounds.Bottom);
            Color fg = e.Item.ForeColor;
            Rectangle textBounds = e.Bounds;
            if (e.ColumnIndex == 0)
            {
                if (fg.ToArgb() != Theme.TextMain.ToArgb())
                    using (SolidBrush ac = new SolidBrush(fg)) e.Graphics.FillRectangle(ac, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);
                // Маленькая иконка типа устройства перед IP-адресом (только там, где у ListView задан SmallImageList).
                ListView lvOwner = (ListView)sender;
                if (lvOwner.SmallImageList != null && e.Item.ImageKey != "" && lvOwner.SmallImageList.Images.ContainsKey(e.Item.ImageKey))
                {
                    int iy = e.Bounds.Y + (e.Bounds.Height - 16) / 2;
                    e.Graphics.DrawImage(lvOwner.SmallImageList.Images[e.Item.ImageKey], e.Bounds.X + 5, iy, 16, 16);
                    textBounds = new Rectangle(e.Bounds.X + 24, e.Bounds.Y, e.Bounds.Width - 24, e.Bounds.Height);
                }
            }
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, e.Item.Font, textBounds, fg, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.LeftAndRightPadding | TextFormatFlags.EndEllipsis);
        }

        // Небольшие значки типа устройства (роутер, ПК, сервер БД и т.п.) переиспользуют ту же
        // отрисовку, что и карта сети - просто в маленьком размере и с прозрачным фоном.
        static ImageList BuildDeviceIcons()
        {
            ImageList il = new ImageList();
            il.ColorDepth = ColorDepth.Depth32Bit;
            il.ImageSize = new Size(16, 16);
            foreach (string kind in new[] { "GW", "WIN", "NIX", "DB", "WEB", "NET", "HOST" })
            {
                Bitmap bmp = new Bitmap(16, 16, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.Clear(Color.Transparent);
                    NetMapPanel.DrawIcon(g, kind, new RectangleF(-6f, -6f, 28f, 28f), Theme.Electric);
                }
                il.Images.Add(kind, bmp);
            }
            return il;
        }

        void StyleListView(ListView l)
        {
            l.OwnerDraw = true; l.BackColor = Color.FromArgb(15, 20, 32); l.ForeColor = Theme.TextMain;
            l.BorderStyle = BorderStyle.None; l.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            l.DrawColumnHeader += OnLvDrawHeader; l.DrawItem += OnLvDrawItem; l.DrawSubItem += OnLvDrawSub;
        }

        public MainForm()
        {
            Text = "NetWarden 0.5 - аудит безопасности сети";
            ClientSize = new Size(1220, 820);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            BackColor = Theme.BgDeep;

            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill; root.ColumnCount = 1; root.RowCount = 9; root.BackColor = Theme.BgDeep;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 12f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 150f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 10f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 70f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 10f));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 10f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 46f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 12f));
            root.Padding = new Padding(16, 0, 16, 0);

            // ======================= ГЕРОЙ-ПАНЕЛЬ: главный фокус - статус сканирования =======================
            heroCard = Glass(Theme.BgCardTop, Theme.BgCardBot, Theme.BorderCyan, true);
            Label brand = new Label(); brand.Text = "N E T W A R D E N"; brand.Font = new Font("Segoe UI", 15f, FontStyle.Bold);
            brand.ForeColor = Theme.Accent; brand.AutoSize = true; brand.Location = new Point(22, 14); brand.BackColor = Color.Transparent;
            Label brandSub = new Label();
            brandSub.Text = "ЦЕНТР АУДИТА БЕЗОПАСНОСТИ СЕТИ" + (AppPaths.IsPortable ? "   ·   ПОРТАТИВНЫЙ РЕЖИМ" : "");
            brandSub.Font = new Font("Segoe UI", 8f);
            brandSub.ForeColor = Theme.TextMuted; brandSub.AutoSize = true; brandSub.Location = new Point(24, 44); brandSub.BackColor = Color.Transparent;
            heroStatus = new Label(); heroStatus.Text = "СТАТУС: ГОТОВ К СКАНИРОВАНИЮ"; heroStatus.Font = new Font("Segoe UI", 13f, FontStyle.Regular);
            heroStatus.ForeColor = Theme.TextMain; heroStatus.AutoSize = true; heroStatus.Location = new Point(22, 70); heroStatus.BackColor = Color.Transparent;
            heroMeta = new Label(); heroMeta.Text = "Сканируйте только системы, на которые есть разрешение.";
            heroMeta.ForeColor = Theme.TextMuted; heroMeta.AutoSize = false; heroMeta.Location = new Point(24, 102);
            heroMeta.Size = new Size(760, 32); heroMeta.BackColor = Color.Transparent; heroMeta.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            btnStop = new NeoButton(); btnStop.Text = "■  СТОП"; btnStop.Size = new Size(140, 46); btnStop.Location = new Point(1180 - 20 - 140, 76);
            btnStop.Anchor = AnchorStyles.Top | AnchorStyles.Right; btnStop.Enabled = false; btnStop.Click += OnStop;
            btnStart = new NeoButton(); ((NeoButton)btnStart).Primary = true; btnStart.Text = "▶  НАЧАТЬ СКАНИРОВАНИЕ"; btnStart.Size = new Size(230, 46);
            btnStart.Location = new Point(1180 - 20 - 140 - 12 - 230, 76); btnStart.Anchor = AnchorStyles.Top | AnchorStyles.Right; btnStart.Click += OnStart;
            heroCard.Controls.AddRange(new Control[] { brand, brandSub, heroStatus, heroMeta, btnStop, btnStart });

            // ======================= ПАНЕЛЬ ПАРАМЕТРОВ СКАНИРОВАНИЯ =======================
            paramsCard = Glass(Theme.BgPanelTop, Theme.BgPanelBot, Theme.BorderDim, false);
            Label l1 = new Label(); l1.Text = "ЦЕЛИ:"; l1.ForeColor = Theme.TextMuted; l1.Location = new Point(18, 13); l1.AutoSize = true;
            tbTargets = new TextBox(); tbTargets.Location = new Point(70, 9); tbTargets.Width = 420; tbTargets.BorderStyle = BorderStyle.FixedSingle;
            tbTargets.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right; DarkField(tbTargets);
            btnMyNet = new NeoButton(); btnMyNet.Text = "МОЯ СЕТЬ"; btnMyNet.Location = new Point(500, 6); btnMyNet.Size = new Size(96, 26);
            btnMyNet.Anchor = AnchorStyles.Top | AnchorStyles.Right; btnMyNet.Click += OnMyNet;

            cbProfile = new ComboBox(); cbProfile.DropDownStyle = ComboBoxStyle.DropDownList; cbProfile.DrawMode = DrawMode.OwnerDrawFixed;
            cbProfile.DrawItem += OnComboDraw; cbProfile.FlatStyle = FlatStyle.Flat;
            cbProfile.Items.AddRange(ProfNames); cbProfile.SelectedIndex = 0; DarkField(cbProfile);
            cbProfile.Location = new Point(606, 9); cbProfile.Width = 200; cbProfile.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            cbProfile.SelectedIndexChanged += delegate { tbCustomPorts.Enabled = cbProfile.SelectedIndex == CustomProfileIdx; };
            tbCustomPorts = new TextBox(); tbCustomPorts.Location = new Point(814, 9); tbCustomPorts.Width = 70; tbCustomPorts.Enabled = false;
            tbCustomPorts.BorderStyle = BorderStyle.FixedSingle; tbCustomPorts.Text = "1-6000"; tbCustomPorts.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            DarkField(tbCustomPorts);
            tip.SetToolTip(tbCustomPorts, "Список/диапазон портов: 1-6000 или 22,80,443,8000-8100. Выберите профиль \"Свой диапазон\" слева.");

            chkUdp = new CheckBox(); chkUdp.Text = "UDP"; chkUdp.Checked = true; chkUdp.Location = new Point(18, 42); chkUdp.Width = 50;
            chkUdp.ForeColor = Theme.TextMain; chkUdp.FlatStyle = FlatStyle.Flat;
            chkSkip = new CheckBox(); chkSkip.Text = "Без обнаружения"; chkSkip.Location = new Point(73, 42); chkSkip.Width = 140;
            chkSkip.ForeColor = Theme.TextMain; chkSkip.FlatStyle = FlatStyle.Flat;
            tip.SetToolTip(chkSkip, "Режим -Pn: не проверять, \"жив\" ли хост (ARP/ping/TCP), а сразу сканировать порты у всех указанных адресов.\n" +
                "Включайте, если хосты блокируют ping и TCP-пробы обнаружения (тогда без этой галочки они ошибочно считаются выключенными),\n" +
                "например за строгим файрволом. Минус: сканирование идёт по всем адресам диапазона и занимает намного больше времени.");
            chkBrute = new CheckBox(); chkBrute.Text = "Слабые пароли"; chkBrute.Location = new Point(218, 42); chkBrute.Width = 135;
            chkBrute.ForeColor = Theme.TextMain; chkBrute.FlatStyle = FlatStyle.Flat;
            tip.SetToolTip(chkBrute, "Проверка FTP и веб-форм HTTP Basic Auth по короткому встроенному словарю типовых пар логин/пароль (admin/admin и т.п.).\n" +
                "Медленнее обычного скана и создаёт неудачные попытки входа на целевых системах - используйте только на системах с разрешением.\n" +
                "SSH, RDP и большинство СУБД не проверяются: для них нужна полная реализация протокола, которой в этой сборке нет (см. README).");
            btnUpdateDb = new NeoButton(); btnUpdateDb.Text = "ОБНОВИТЬ БАЗЫ CVE"; btnUpdateDb.Location = new Point(365, 37);
            btnUpdateDb.Size = new Size(180, 27); btnUpdateDb.Click += OnUpdateDb;
            paramsCard.Controls.AddRange(new Control[] { l1, tbTargets, btnMyNet, cbProfile, tbCustomPorts, chkUdp, chkSkip, chkBrute, btnUpdateDb });

            ImageList deviceIcons = BuildDeviceIcons();

            // ---- вкладка "Результаты" ----
            split = new SplitContainer(); split.Dock = DockStyle.Fill; split.BackColor = Theme.BorderDim;
            tree = new TreeView(); tree.Dock = DockStyle.Fill; tree.HideSelection = false; tree.AfterSelect += OnTreeSelect;
            tree.ImageList = deviceIcons;
            tree.BackColor = Color.FromArgb(15, 20, 32); tree.ForeColor = Theme.TextMain; tree.BorderStyle = BorderStyle.None; tree.ItemHeight = 22;
            details = new RichTextBox(); details.Dock = DockStyle.Fill; details.ReadOnly = true;
            details.ScrollBars = RichTextBoxScrollBars.Vertical; details.BorderStyle = BorderStyle.None; DarkField(details);
            details.BackColor = Color.FromArgb(24, 32, 48); // чуть светлее обычного тёмного поля, по просьбе
            details.Font = new Font("Segoe UI", 9f);
            split.Panel1.Controls.Add(tree); split.Panel2.Controls.Add(details);
            split.Panel1.BackColor = Color.FromArgb(15, 20, 32); split.Panel2.BackColor = Color.FromArgb(18, 24, 36);
            btnFixRes = MakeFixPanel(split.Panel2);
            TabPage t1 = new TabPage("Результаты"); t1.BackColor = Theme.BgDeep; t1.Controls.Add(split);

            // ---- вкладка "Уязвимости" ----
            lv = new ListView(); lv.Dock = DockStyle.Fill; lv.View = View.Details; lv.FullRowSelect = true; StyleListView(lv);
            lv.Columns.Add("Уровень", 100); lv.Columns.Add("CVSS", 50); lv.Columns.Add("Хост", 110);
            lv.Columns.Add("Порт", 55); lv.Columns.Add("Уязвимость", 420); lv.Columns.Add("CVE", 150);
            lv.Columns.Add("Рекомендация", 600);
            lv.SelectedIndexChanged += OnListSelect;
            vulnDetails = new TextBox(); vulnDetails.Dock = DockStyle.Fill; vulnDetails.Multiline = true; vulnDetails.ReadOnly = true;
            vulnDetails.ScrollBars = ScrollBars.Vertical; vulnDetails.BorderStyle = BorderStyle.None; DarkField(vulnDetails);
            vsplit = new SplitContainer(); vsplit.Dock = DockStyle.Fill; vsplit.Orientation = Orientation.Horizontal; vsplit.BackColor = Theme.BorderDim;
            vsplit.Panel1.Controls.Add(lv); vsplit.Panel2.Controls.Add(vulnDetails);
            vsplit.Panel1.BackColor = Color.FromArgb(15, 20, 32); vsplit.Panel2.BackColor = Color.FromArgb(18, 24, 36);
            btnFixVuln = MakeFixPanel(vsplit.Panel2);
            TabPage t2 = new TabPage("Уязвимости"); t2.BackColor = Theme.BgDeep; t2.Controls.Add(vsplit);

            // ---- вкладка "Карта сети" ----
            netMap = new NetMapPanel(); netMap.Dock = DockStyle.Fill; netMap.BackColor = Color.FromArgb(10, 14, 23);
            netMap.HostSelected += OnMapSelect; netMap.HostActivated += OnMapActivate;
            mapDetails = new RichTextBox(); mapDetails.Dock = DockStyle.Fill; mapDetails.ReadOnly = true;
            mapDetails.ScrollBars = RichTextBoxScrollBars.Vertical; mapDetails.BorderStyle = BorderStyle.None; DarkField(mapDetails);
            mapDetails.BackColor = Color.FromArgb(24, 32, 48);
            mapDetails.Font = new Font("Segoe UI", 9f);
            mapSplit = new SplitContainer(); mapSplit.Dock = DockStyle.Fill; mapSplit.BackColor = Theme.BorderDim;
            mapSplit.Panel1.Controls.Add(netMap); mapSplit.Panel2.Controls.Add(mapDetails);
            mapSplit.Panel2.BackColor = Color.FromArgb(18, 24, 36);
            Panel legend = new Panel(); legend.Height = 34; legend.Dock = DockStyle.Bottom; legend.BackColor = Theme.BgPanelBot; legend.Paint += OnLegendPaint;
            NeoButton bPng = new NeoButton(); bPng.Text = "СОХРАНИТЬ СХЕМУ (PNG)"; bPng.Dock = DockStyle.Right; bPng.Width = 210;
            bPng.Click += OnSaveMap; legend.Controls.Add(bPng);
            TabPage t5 = new TabPage("Карта сети"); t5.BackColor = Theme.BgDeep; t5.Controls.Add(mapSplit); t5.Controls.Add(legend);

            // ---- вкладка "Устройства" ----
            devLv = new ListView(); devLv.Dock = DockStyle.Fill; devLv.View = View.Details; devLv.FullRowSelect = true; StyleListView(devLv);
            devLv.SmallImageList = deviceIcons;
            devLv.ShowItemToolTips = true;
            devLv.Columns.Add("IP-адрес", 110); devLv.Columns.Add("Имя", 150); devLv.Columns.Add("MAC", 125);
            devLv.Columns.Add("Производитель", 150); devLv.Columns.Add("Операционная система", 230); devLv.Columns.Add("Тип", 170);
            devLv.Columns.Add("Портов", 55); devLv.Columns.Add("Службы", 280); devLv.Columns.Add("Находок", 65);
            devLv.DoubleClick += OnDevActivate;
            TabPage tDev = new TabPage("Устройства"); tDev.BackColor = Theme.BgDeep; tDev.Controls.Add(devLv);

            // ---- вкладка "Порты и службы" ----
            portLv = new ListView(); portLv.Dock = DockStyle.Fill; portLv.View = View.Details; portLv.FullRowSelect = true; StyleListView(portLv);
            portLv.Columns.Add("Хост", 110); portLv.Columns.Add("Порт", 55); portLv.Columns.Add("Прот.", 50); portLv.Columns.Add("Служба", 110);
            portLv.Columns.Add("Продукт / версия", 230); portLv.Columns.Add("TLS", 40); portLv.Columns.Add("Баннер / описание", 600);
            TabPage tPorts = new TabPage("Порты и службы"); tPorts.BackColor = Theme.BgDeep; tPorts.Controls.Add(portLv);

            tabs = new TabControl(); tabs.Dock = DockStyle.Fill; tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            tabs.ItemSize = new Size(180, 34); tabs.SizeMode = TabSizeMode.Fixed; tabs.Padding = new Point(0, 0);
            tabs.Font = new Font("Segoe UI", 8.5f, FontStyle.Regular); tabs.DrawItem += OnTabDraw;
            tabs.TabPages.Add(t1); tabs.TabPages.Add(tDev); tabs.TabPages.Add(t5); tabs.TabPages.Add(t2); tabs.TabPages.Add(tPorts);

            // ======================= НИЖНЯЯ ПАНЕЛЬ: прогресс / статус / экспорт =======================
            bottomCard = Glass(Theme.BgPanelTop, Theme.BgPanelBot, Theme.BorderDim, false);
            pb = new NeoProgressBar(); pb.Location = new Point(18, 18); pb.Size = new Size(320, 10); pb.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            status = new Label(); status.Text = "Готов. Сканируйте только системы, на которые есть разрешение.";
            status.ForeColor = Theme.TextMuted; status.Location = new Point(352, 14); status.Size = new Size(680, 20);
            status.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            btnExport = new NeoButton(); btnExport.Text = "ЭКСПОРТ ОТЧЁТА"; btnExport.Location = new Point(1184 - 20 - 150, 8);
            btnExport.Size = new Size(150, 30); btnExport.Anchor = AnchorStyles.Top | AnchorStyles.Right; btnExport.Click += OnExport;
            bottomCard.Controls.AddRange(new Control[] { pb, status, btnExport });

            root.Controls.Add(heroCard, 0, 1);
            root.Controls.Add(paramsCard, 0, 3);
            root.Controls.Add(tabs, 0, 5);
            root.Controls.Add(bottomCard, 0, 7);
            Controls.Add(root);
            tbTargets.Text = LocalNets.DefaultCidr();

            timer = new System.Windows.Forms.Timer();
            timer.Interval = 200;
            timer.Tick += OnTick;
            timer.Start();
            Load += delegate
            {
                split.SplitterDistance = Math.Max(100, split.Width * 6 / 10);
                mapSplit.SplitterDistance = Math.Max(100, mapSplit.Width * 7 / 10);
                vsplit.SplitterDistance = Math.Max(60, vsplit.Height * 6 / 10);

                // К этому моменту heroCard/paramsCard/bottomCard уже получили свой настоящий размер от
                // TableLayoutPanel (Dock=Fill). Пересчитываем позиции всех элементов, привязанных к правому
                // краю (Anchor=Right): при добавлении в конструкторе эти панели ещё имели временный размер
                // "по умолчанию" (~200px), и Anchor запомнил неверное расстояние до правого края - поэтому
                // кнопки "Моя сеть", "Старт", "Стоп", "Экспорт отчёта" и выбор профиля портов пропадали
                // далеко за пределами окна. Установка .Location/.Width здесь заново фиксирует правильную
                // точку отсчёта для Anchor - дальнейшее изменение размера окна пользователем будет работать
                // уже корректно.
                int hw = heroCard.ClientSize.Width;
                btnStop.Location = new Point(hw - 20 - btnStop.Width, 76);
                btnStart.Location = new Point(btnStop.Left - 12 - btnStart.Width, 76);
                heroMeta.Width = Math.Max(200, btnStart.Left - 20 - heroMeta.Left);

                int pw = paramsCard.ClientSize.Width;
                btnMyNet.Location = new Point(pw - 20 - btnMyNet.Width, 6);
                cbProfile.Location = new Point(btnMyNet.Left - 10 - cbProfile.Width, 9);
                tbCustomPorts.Location = new Point(cbProfile.Left - 8 - tbCustomPorts.Width, 9);
                tbTargets.Width = Math.Max(150, tbCustomPorts.Left - 10 - tbTargets.Left);

                int bw = bottomCard.ClientSize.Width;
                btnExport.Location = new Point(bw - 20 - btnExport.Width, 8);
                status.Width = Math.Max(150, btnExport.Left - 10 - status.Left);
            };
            FormClosing += delegate { if (scanner != null) scanner.Cancel = true; };
        }

        void OnStart(object sender, EventArgs e)
        {
            if (scanner != null) return;
            Scanner sc = new Scanner();
            try
            {
                int pi = cbProfile.SelectedIndex;
                sc.TargetsSpec = tbTargets.Text.Trim();
                sc.PortsSpec = pi == CustomProfileIdx ? tbCustomPorts.Text.Trim() : ProfPorts[pi];
                sc.Targets = Targets.Expand(sc.TargetsSpec);
                sc.Ports = Targets.ParsePorts(sc.PortsSpec);
                sc.Timeout = ProfTimeout[pi];
                sc.Threads = ProfThreads[pi];
                sc.SkipDiscovery = chkSkip.Checked;
                sc.ScanUdp = chkUdp.Checked;
                sc.ScanBrute = chkBrute.Checked;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (MessageBox.Show(this, "Целей: " + sc.Targets.Count + ", портов на цель: " + sc.Ports.Length +
                "\n\nПодтверждаете, что имеете разрешение на сканирование этих систем?", "Подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            tree.Nodes.Clear(); lv.Items.Clear(); details.Clear();
            mapHosts.Clear(); netMap.SetHosts(mapHosts); mapDetails.Clear(); vulnDetails.Clear(); devLv.Items.Clear(); portLv.Items.Clear();
            current = null;
            scanner = sc;
            scanStarted = DateTime.Now;
            btnStart.Enabled = false; btnStop.Enabled = true;
            heroStatus.Text = "СТАТУС: СКАНИРОВАНИЕ…"; heroStatus.ForeColor = Theme.Accent;
            heroMeta.Text = "Цель: " + sc.TargetsSpec + "   ·   Хостов в очереди: " + sc.Targets.Count;
            Thread t = new Thread(sc.Run);
            t.IsBackground = true;
            t.Start();
        }

        void OnStop(object sender, EventArgs e)
        {
            if (scanner != null) { scanner.Cancel = true; status.Text = "Остановка…"; heroStatus.Text = "СТАТУС: ОСТАНОВКА…"; }
        }

        static string Elapsed(DateTime since)
        {
            TimeSpan t = DateTime.Now - since;
            return (t.Hours > 0 ? t.Hours + ":" : "") + t.Minutes.ToString(t.Hours > 0 ? "00" : "0") + ":" + t.Seconds.ToString("00");
        }

        void OnTick(object sender, EventArgs e)
        {
            Scanner sc = scanner;
            if (sc == null) return;
            string line;
            while (sc.Log.TryDequeue(out line)) { } // журнал убран из интерфейса; очередь просто осушаем, чтобы не копилась в памяти
            HostInfo h;
            while (sc.Finished.TryDequeue(out h)) AddHost(h);
            long tot = sc.StageTotal, done = sc.StageDone;
            if (tot > 0)
            {
                pb.Maximum = (int)Math.Min(tot, 2000000000L);
                pb.Value = (int)Math.Min(done, (long)pb.Maximum);
            }
            if (!sc.Done)
            {
                int pct = tot > 0 ? (int)(done * 100 / tot) : 0;
                status.Text = sc.Stage + ": " + done + " / " + tot + " (" + pct + "%)   ·   найдено хостов: " + mapHosts.Count +
                              "   ·   время: " + Elapsed(scanStarted);
                heroMeta.Text = sc.Stage + "   ·   " + pct + "%   ·   найдено хостов: " + mapHosts.Count +
                                "   ·   время: " + Elapsed(scanStarted);
            }
            if (sc.Done && sc.Log.IsEmpty && sc.Finished.IsEmpty) FinishScan(sc);
        }

        void FinishScan(Scanner sc)
        {
            scanner = null;
            btnStart.Enabled = true; btnStop.Enabled = false;
            string dur = Elapsed(scanStarted);
            if (sc.Result == null)
            {
                status.Text = "Сканирование не выполнено.";
                heroStatus.Text = "СТАТУС: ОШИБКА"; heroStatus.ForeColor = Theme.Danger;
                return;
            }
            current = sc.Result;
            RebuildViews(); // хосты во время скана добавлялись по мере готовности - теперь выстраиваем по IP-адресу
            FillList(current);
            int[] cnt = new int[Sev.Order.Length];
            foreach (KeyValuePair<HostInfo, Finding> kv in Report.Pairs(current)) cnt[Sev.Idx(kv.Value.Severity)]++;
            StringBuilder sb = new StringBuilder("Хостов: " + current.Hosts.Count);
            for (int i = 0; i < cnt.Length; i++) sb.Append(" | " + Sev.Ru(Sev.Order[i]) + ": " + cnt[i]);
            status.Text = sb.ToString();
            bool anyActionable = cnt[0] + cnt[1] + cnt[2] + cnt[3] > 0;
            heroStatus.Text = "СТАТУС: ЗАВЕРШЕНО"; heroStatus.ForeColor = anyActionable ? Theme.Danger : Theme.Accent;
            heroMeta.Text = "Хостов найдено: " + current.Hosts.Count + "   ·   Находок: " + (cnt[0] + cnt[1] + cnt[2] + cnt[3] + cnt[4]) +
                            "   ·   Время сканирования: " + dur;
        }

        // Пересобирает дерево/устройства/порты/карту из current.Hosts, отсортированных по числовому значению IP
        // (а не по порядку, в котором хосты ответили во время сканирования).
        void RebuildViews()
        {
            tree.Nodes.Clear(); devLv.Items.Clear(); portLv.Items.Clear(); mapHosts.Clear(); netMap.SetHosts(mapHosts);
            if (current == null) return;
            List<HostInfo> sorted = new List<HostInfo>(current.Hosts);
            sorted.Sort(delegate (HostInfo a, HostInfo b) { return Targets.ToUInt(a.Ip).CompareTo(Targets.ToUInt(b.Ip)); });
            foreach (HostInfo h in sorted) AddHost(h);
        }

        void AddHost(HostInfo h)
        {
            mapHosts.Add(h);
            netMap.SetHosts(mapHosts);
            AddDeviceRow(h);
            AddPortRows(h);
            TreeNode root = new TreeNode(h.Ip + "  " + h.Name + (h.Os != "" ? "  - " + h.Os : "") + "   [находок: " + h.Findings.Count + "]");
            root.Tag = h;
            string devKind = NetMapPanel.DevType(h, netMap.Gateway)[0];
            root.ImageKey = devKind; root.SelectedImageKey = devKind;
            int rootWorst = WorstActionableIdx(h.Findings);
            if (rootWorst <= 3) root.ForeColor = Sev.Col(Sev.Order[rootWorst]);
            foreach (PortInfo p in h.Ports)
            {
                TreeNode pn = new TreeNode(p.Port + "/" + p.Proto + "  " + p.Service + (p.Tls ? " (TLS)" : "") + "  " + (p.Product + " " + p.Version).Trim());
                pn.Tag = p;
                string worst = "";
                foreach (Finding f in h.Findings.Where(x => x.Port == p.Port).OrderBy(x => Sev.Idx(x.Severity)))
                {
                    if (worst == "") worst = f.Severity;
                    TreeNode fn = new TreeNode("[" + Sev.Ru(f.Severity) + "] " + f.Title);
                    fn.ForeColor = Sev.Col(f.Severity);
                    fn.Tag = f;
                    pn.Nodes.Add(fn);
                }
                if (worst != "") pn.ForeColor = Sev.Col(worst);
                root.Nodes.Add(pn);
            }
            tree.Nodes.Add(root);
        }

        void FillList(ScanResult r)
        {
            lv.BeginUpdate();
            lv.Items.Clear();
            foreach (KeyValuePair<HostInfo, Finding> kv in Report.Pairs(r))
            {
                Finding f = kv.Value;
                ListViewItem it = new ListViewItem(new string[] {
                    Sev.Ru(f.Severity), f.Cvss.ToString("0.0", CultureInfo.InvariantCulture), kv.Key.Ip, f.Port.ToString(), f.Title, f.Cve, f.Rec });
                it.ForeColor = Sev.Col(f.Severity);
                it.Tag = kv;
                lv.Items.Add(it);
            }
            lv.EndUpdate();
        }

        static string FindingText(Finding f) { return FindingText(f, ""); }

        static string FindingText(Finding f, string host)
        {
            string nl = "\r\n";
            string rec = f.Rec != "" ? f.Rec : "Отдельных рекомендаций нет: убедитесь, что сервис действительно нужен, и ограничьте доступ к нему межсетевым экраном.";
            string attack = f.Attack != "" ? f.Attack : "Описание сценария атаки для этой находки отсутствует; общий принцип - чем раньше устранить находку, тем меньше времени у злоумышленника на её использование.";
            return f.Title + nl + nl +
                   (host != "" ? "Хост: " + host + ":" + f.Port : "Порт: " + f.Port) + nl +
                   "Уровень: " + Sev.Ru(f.Severity) + " (CVSS " + f.Cvss.ToString("0.0", CultureInfo.InvariantCulture) + ")" + nl +
                   "Достоверность: " + (f.Conf == "confirmed" ? "подтверждено" : "вероятно (по версии сервиса)") + nl +
                   "CVE: " + (f.Cve == "" ? "-" : f.Cve) + (f.Cve != "" ? "  (" + Refs.Nvd(f.Cve.Split(',')[0].Trim()) + ")" : "") + nl +
                   "Источник: " + (f.Source != "" ? f.Source : "Встроенная база NetWarden") + nl + nl +
                   (f.Desc != "" ? "Описание:" + nl + f.Desc + nl + nl : "") +
                   "КАК МОЖЕТ ВОСПОЛЬЗОВАТЬСЯ ЗЛОУМЫШЛЕННИК:" + nl + attack + nl + nl +
                   "КАК ИСПРАВИТЬ:" + nl + rec +
                   (f.Evidence != "" ? nl + nl + "Свидетельство: " + f.Evidence : "") +
                   nl + nl + "Проверить по БДУ ФСТЭК (России): " + Refs.Bdu(f.Title);
        }

        void OnTreeSelect(object sender, TreeViewEventArgs e)
        {
            curFinding = e.Node.Tag as Finding;
            curHost = null;
            if (curFinding != null && e.Node.Parent != null && e.Node.Parent.Parent != null) curHost = e.Node.Parent.Parent.Tag as HostInfo;
            if (curHost == null) curFinding = null;
            UpdateFixButtons();
            object tag = e.Node.Tag;
            if (tag is Finding) details.Text = FindingText((Finding)tag, curHost != null ? curHost.Ip : "");
            else if (tag is PortInfo)
            {
                PortInfo p = (PortInfo)tag;
                details.Text = "Порт " + p.Port + "/" + p.Proto + "\r\nСервис: " + p.Service + "\r\nПродукт: " + p.Product + "\r\nВерсия: " + p.Version +
                               "\r\nTLS: " + (p.Tls ? "да" : "нет") + "\r\n\r\nБаннер:\r\n" + p.Banner;
            }
            else if (tag is HostInfo)
            {
                HostInfo h = (HostInfo)tag;
                RenderHostDetails(details, h);
            }
        }

        void OnListSelect(object sender, EventArgs e)
        {
            if (lv.SelectedItems.Count == 0) { vulnDetails.Clear(); curFinding = null; curHost = null; UpdateFixButtons(); return; }
            KeyValuePair<HostInfo, Finding> kv = (KeyValuePair<HostInfo, Finding>)lv.SelectedItems[0].Tag;
            vulnDetails.Text = FindingText(kv.Value, kv.Key.Ip);
            curFinding = kv.Value; curHost = kv.Key; UpdateFixButtons();
        }

        static void RtbAppend(RichTextBox rtb, string text, Color color)
        {
            int start = rtb.TextLength;
            rtb.AppendText(text);
            rtb.Select(start, text.Length);
            rtb.SelectionColor = color;
            rtb.SelectionLength = 0;
        }

        // IP-адрес - ярко-белым (основной заголовок карточки), описание устройства (тип/ОС/MAC) - красным,
        // чтобы сразу бросалось в глаза; списки портов и находок - обычным цветом текста (находки - по
        // своей серьёзности, как и раньше).
        void RenderHostDetails(RichTextBox rtb, HostInfo h)
        {
            rtb.Clear();
            string nl = "\r\n";
            string[] dt = NetMapPanel.DevType(h, netMap.Gateway);
            Color white = Color.White;
            Color red = Theme.Danger;

            RtbAppend(rtb, h.Ip + (h.Name != "" ? "  (" + h.Name + ")" : "") + nl, white);
            RtbAppend(rtb, dt[1] + nl, red);
            RtbAppend(rtb, "ОС: " + (h.Os != "" ? h.Os : "не определена") + (h.OsBasis != "" ? "  [" + h.OsBasis + "]" : "") + nl, red);
            if (h.Mac != "")
            {
                RtbAppend(rtb, "MAC: " + h.Mac + (h.Vendor != "" ? "  (" + h.Vendor + ")" : "") + nl, red);
                if (h.MacInfo != "") RtbAppend(rtb, "Чьё устройство: " + h.MacInfo + nl, red);
            }
            RtbAppend(rtb, nl, Theme.TextMain);
            RtbAppend(rtb, "Открытые порты: " + h.Ports.Count + nl, Theme.TextMain);
            foreach (PortInfo p in h.Ports)
                RtbAppend(rtb, "  " + p.Port + "/" + p.Proto + "  " + p.Service + (p.Tls ? " (TLS)" : "") + "  " + (p.Product + " " + p.Version).Trim() + nl, Theme.TextMain);
            RtbAppend(rtb, nl + "Находки: " + h.Findings.Count + nl, Theme.TextMain);
            List<Finding> fl = new List<Finding>(h.Findings);
            fl.Sort(delegate (Finding x, Finding y) { return Sev.Idx(x.Severity).CompareTo(Sev.Idx(y.Severity)); });
            foreach (Finding f in fl)
            {
                Color fc = Sev.Col(f.Severity);
                RtbAppend(rtb, nl + "[" + Sev.Ru(f.Severity) + "] порт " + f.Port + ": " + f.Title + nl, fc);
                RtbAppend(rtb, "   Как исправить: " + (f.Rec != "" ? f.Rec : "ограничьте доступ к сервису") + nl, Theme.TextMain);
            }
            rtb.Select(0, 0);
        }

        string HostText(HostInfo h)
        {
            string nl = "\r\n";
            string[] dt = NetMapPanel.DevType(h, netMap.Gateway);
            StringBuilder sb = new StringBuilder();
            sb.Append(h.Ip + (h.Name != "" ? "  (" + h.Name + ")" : "") + nl + dt[1] + nl);
            sb.Append("ОС: " + (h.Os != "" ? h.Os : "не определена") + (h.OsBasis != "" ? "  [" + h.OsBasis + "]" : "") + nl);
            if (h.Mac != "")
            {
                sb.Append("MAC: " + h.Mac + (h.Vendor != "" ? "  (" + h.Vendor + ")" : "") + nl);
                if (h.MacInfo != "") sb.Append("Чьё устройство: " + h.MacInfo + nl);
            }
            sb.Append(nl);
            sb.Append("Открытые порты: " + h.Ports.Count + nl);
            foreach (PortInfo p in h.Ports)
                sb.Append("  " + p.Port + "/" + p.Proto + "  " + p.Service + (p.Tls ? " (TLS)" : "") + "  " + (p.Product + " " + p.Version).Trim() + nl);
            sb.Append(nl + "Находки: " + h.Findings.Count + nl);
            List<Finding> fl = new List<Finding>(h.Findings);
            fl.Sort(delegate(Finding x, Finding y) { return Sev.Idx(x.Severity).CompareTo(Sev.Idx(y.Severity)); });
            foreach (Finding f in fl)
                sb.Append(nl + "[" + Sev.Ru(f.Severity) + "] порт " + f.Port + ": " + f.Title + nl +
                          "   Как исправить: " + (f.Rec != "" ? f.Rec : "ограничьте доступ к сервису") + nl);
            return sb.ToString();
        }

        Button MakeFixPanel(Control parent)
        {
            Panel pn = new Panel();
            pn.Height = 46;
            pn.Dock = DockStyle.Bottom;
            pn.BackColor = Color.FromArgb(18, 24, 36);
            NeoButton b = new NeoButton();
            b.Primary = true;
            b.Text = "ИСПРАВИТЬ";
            b.Enabled = false;
            b.Location = new Point(8, 8);
            b.Size = new Size(270, 30);
            b.Click += OnFix;
            pn.Controls.Add(b);
            parent.Controls.Add(pn);
            return b;
        }

        void UpdateFixButtons()
        {
            string text = "Исправить";
            bool en = curFinding != null && curHost != null;
            if (en)
            {
                bool own = LocalNets.IsOwnIp(curHost.Ip);
                text = (own && Fixes.Auto(curFinding) != null) ? "Исправить автоматически..." : "Как исправить (подробно)...";
            }
            btnFixRes.Text = text; btnFixVuln.Text = text;
            btnFixRes.Enabled = en; btnFixVuln.Enabled = en;
        }

        void OnFix(object sender, EventArgs e)
        {
            if (curFinding == null || curHost == null) return;
            bool own = LocalNets.IsOwnIp(curHost.Ip);
            FixAction a = Fixes.Auto(curFinding);
            if (a == null || !own) { ShowManual(curFinding, curHost, a, own); return; }

            StringBuilder sb = new StringBuilder();
            sb.Append("Хост: " + curHost.Ip + " (этот компьютер)\n" + curFinding.Title + "\n\nБудет выполнено:\n");
            foreach (FixStep st in a.Steps) sb.Append("  - " + st.Name + "\n");
            sb.Append("\n" + a.Details + "\n\nWindows запросит подтверждение прав администратора (UAC).\n\n" +
                      "Да - исправить сейчас\nНет - показать подробную инструкцию и скрипт\nОтмена - ничего не делать");
            DialogResult r = MessageBox.Show(this, sb.ToString(), "Автоматическое исправление", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Cancel) return;
            if (r == DialogResult.No) { ShowManual(curFinding, curHost, a, own); return; }

            string res;
            Cursor = Cursors.WaitCursor;
            try { res = Fixes.Run(a, curFinding, curHost); }
            finally { Cursor = Cursors.Default; }
            MessageBox.Show(this, res, "Результат исправления", MessageBoxButtons.OK, MessageBoxIcon.Information);
            status.Text = "Исправление выполнено: " + curFinding.Title + ". Запустите повторное сканирование для проверки.";
        }

        void ShowManual(Finding f, HostInfo h, FixAction a, bool own)
        {
            string nl = "\r\n";
            string text = Fixes.Manual(f, h);
            string script = a != null ? Fixes.Script(a) : "";
            if (a != null && !own)
                text = "Автоматическое исправление NetWarden выполняет только на том компьютере, где запущен. Для хоста " + h.Ip +
                       " воспользуйтесь инструкцией или готовым скриптом ниже - выполните их на самом хосте." + nl + nl + text;
            if (script != "")
                text += nl + nl + "ГОТОВЫЙ СКРИПТ (PowerShell, от имени администратора, на компьютере " + h.Ip + ")" + nl + nl + script;
            string full = text;

            Form dlg = new Form();
            dlg.Text = "Как исправить: " + f.Title;
            dlg.Size = new Size(840, 680);
            dlg.StartPosition = FormStartPosition.CenterParent;
            dlg.BackColor = Theme.BgDeep;
            dlg.Font = Font;
            TextBox tb = new TextBox();
            tb.Multiline = true; tb.ReadOnly = true; tb.ScrollBars = ScrollBars.Vertical;
            tb.Dock = DockStyle.Fill; tb.BorderStyle = BorderStyle.None; tb.Font = new Font("Segoe UI", 10f);
            tb.BackColor = Color.FromArgb(18, 24, 36); tb.ForeColor = Theme.TextMain;
            tb.Text = full;
            Panel bottom = new Panel();
            bottom.Height = 46; bottom.Dock = DockStyle.Bottom; bottom.BackColor = Color.FromArgb(14, 19, 31);
            NeoButton bClose = new NeoButton(); bClose.Primary = true; bClose.Text = "ЗАКРЫТЬ"; bClose.Dock = DockStyle.Right; bClose.Width = 110;
            bClose.Click += delegate { dlg.Close(); };
            NeoButton bCopy = new NeoButton(); bCopy.Text = "КОПИРОВАТЬ ВСЁ"; bCopy.Location = new Point(8, 8); bCopy.Size = new Size(150, 30);
            bCopy.Click += delegate { try { Clipboard.SetText(full); } catch (Exception) { } };
            bottom.Controls.Add(bClose);
            bottom.Controls.Add(bCopy);
            if (script != "")
            {
                NeoButton bSave = new NeoButton(); bSave.Text = "СОХРАНИТЬ СКРИПТ (.PS1)"; bSave.Location = new Point(168, 8); bSave.Size = new Size(190, 30);
                bSave.Click += delegate
                {
                    SaveFileDialog sd = new SaveFileDialog();
                    sd.Filter = "PowerShell (*.ps1)|*.ps1";
                    sd.FileName = "fix-" + f.Id;
                    if (sd.ShowDialog(dlg) == DialogResult.OK) File.WriteAllText(sd.FileName, script, new UTF8Encoding(true));
                };
                bottom.Controls.Add(bSave);
            }
            dlg.Controls.Add(tb);
            dlg.Controls.Add(bottom);
            dlg.Shown += delegate { tb.Select(0, 0); };
            dlg.ShowDialog(this);
            dlg.Dispose();
        }

        void OnMyNet(object sender, EventArgs e) { tbTargets.Text = LocalNets.DefaultCidr(); }

        void OnUpdateDb(object sender, EventArgs e)
        {
            if (current == null || current.Hosts.Count == 0)
            {
                MessageBox.Show(this, "Сначала выполните сканирование - обновление ищет CVE по найденным продуктам и версиям.", "NetWarden");
                return;
            }
            if (MessageBox.Show(this,
                "Будет опрошена публичная база уязвимостей NVD (nvd.nist.gov) по продуктам и версиям, найденным при сканировании.\r\n" +
                "Требуется интернет-соединение; процесс может занять до 1-2 минут из-за пауз между запросами (ограничение NVD без ключа API).\r\n" +
                "Для российской базы БДУ ФСТЭК стабильного публичного API нет - вместо этого к каждой находке добавляется ссылка для ручной проверки.\r\n\r\nПродолжить?",
                "Обновление баз уязвимостей", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            btnUpdateDb.Enabled = false;
            status.Text = "Обновление баз уязвимостей из NVD… это может занять до пары минут.";
            List<HostInfo> hostsCopy = current.Hosts;
            Thread t = new Thread(delegate ()
            {
                int added = 0; string summary;
                try { summary = NvdUpdate.Run(hostsCopy, out added); }
                catch (Exception ex) { summary = "Ошибка обновления: " + ex.Message; added = 0; }
                try
                {
                    Invoke(new MethodInvoker(delegate
                    {
                        btnUpdateDb.Enabled = true;
                        status.Text = "Обновление баз завершено. Добавлено находок: " + added;
                        if (added > 0 && current != null) RebuildViews();
                        MessageBox.Show(this, summary, "Результат обновления баз", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }));
                }
                catch (Exception) { }
            });
            t.IsBackground = true;
            t.Start();
        }

        void OnDevActivate(object sender, EventArgs e)
        {
            if (devLv.SelectedItems.Count > 0) OnMapActivate((HostInfo)devLv.SelectedItems[0].Tag);
        }

        void AddDeviceRow(HostInfo h)
        {
            List<string> svcs = new List<string>();
            foreach (PortInfo p in h.Ports) if (p.Service != "" && !svcs.Contains(p.Service)) svcs.Add(p.Service);
            string[] dt = NetMapPanel.DevType(h, netMap.Gateway);
            ListViewItem it = new ListViewItem(new string[] {
                h.Ip, h.Name, h.Mac, h.Vendor, h.Os + (h.OsBasis != "" ? " (" + h.OsBasis + ")" : ""), dt[1],
                h.Ports.Count.ToString(), string.Join(", ", svcs.ToArray()), h.Findings.Count.ToString() });
            it.ImageKey = dt[0];
            int best = WorstActionableIdx(h.Findings);
            it.ForeColor = best <= 3 ? Sev.Col(Sev.Order[best]) : Theme.TextMain;
            it.Tag = h;
            if (h.MacInfo != "") it.ToolTipText = "По MAC-адресу: " + h.MacInfo;
            devLv.Items.Add(it);
        }

        void AddPortRows(HostInfo h)
        {
            foreach (PortInfo p in h.Ports)
            {
                ListViewItem it = new ListViewItem(new string[] {
                    h.Ip, p.Port.ToString(), p.Proto, p.Service, (p.Product + " " + p.Version).Trim(), p.Tls ? "да" : "", p.Banner });
                int portPort = p.Port; // локальная копия для лямбды
                int best = WorstActionableIdx(h.Findings.Where(f => f.Port == portPort));
                it.ForeColor = best <= 3 ? Sev.Col(Sev.Order[best]) : Theme.TextMain;
                portLv.Items.Add(it);
            }
        }

        void OnMapSelect(HostInfo h) { RenderHostDetails(mapDetails, h); }

        void OnMapActivate(HostInfo h)
        {
            tabs.SelectedIndex = 0;
            foreach (TreeNode n in tree.Nodes)
                if (object.ReferenceEquals(n.Tag, h)) { tree.SelectedNode = n; n.Expand(); break; }
        }

        void OnLegendPaint(object sender, PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            int x = 10;
            string[] names = new string[] { "critical", "high", "medium", "low", "info", "ok" };
            foreach (string s in names)
            {
                Color c = s == "ok" ? Color.FromArgb(22, 163, 74) : Sev.Col(s);
                string t = s == "ok" ? "Нет находок" : Sev.Ru(s);
                using (SolidBrush b = new SolidBrush(c)) g.FillRectangle(b, x, 11, 12, 12);
                using (SolidBrush lt = new SolidBrush(Theme.TextMain)) g.DrawString(t, Font, lt, x + 16, 9);
                x += 16 + (int)g.MeasureString(t, Font).Width + 16;
            }
            using (SolidBrush mt = new SolidBrush(Theme.TextMuted)) g.DrawString("Цвет рамки - самая серьёзная находка на хосте. Клик - детали, двойной клик - к результатам.", Font, mt, x + 10, 9);
        }

        void OnSaveMap(object sender, EventArgs e)
        {
            if (mapHosts.Count == 0) { MessageBox.Show(this, "Карта пуста: сначала выполните сканирование.", "NetWarden"); return; }
            SaveFileDialog d = new SaveFileDialog();
            d.Filter = "PNG (*.png)|*.png";
            d.FileName = "network-map";
            if (d.ShowDialog(this) != DialogResult.OK) return;
            try { netMap.SaveImage(d.FileName); status.Text = "Схема сохранена: " + d.FileName; }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        void OnExport(object sender, EventArgs e)
        {
            if (current == null) { MessageBox.Show(this, "Нет результатов для экспорта.", "NetWarden"); return; }
            SaveFileDialog d = new SaveFileDialog();
            d.Filter = "HTML-отчёт (*.html)|*.html|CSV (*.csv)|*.csv";
            d.FileName = "netwarden-" + current.Id;
            if (d.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                string text = d.FilterIndex == 2 ? Report.Csv(current) : Report.Html(current);
                File.WriteAllText(d.FileName, text, new UTF8Encoding(true));
                status.Text = "Отчёт сохранён: " + d.FileName;
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
