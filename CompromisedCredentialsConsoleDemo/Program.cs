using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace CompromisedCredentialsConsoleDemo
{
    internal class Program
    {
        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<Options>(args)
       .WithParsed(RunOptions)
       .WithNotParsed(HandleParseError);
        }
        static void RunOptions(Options opts)
        {
            if (!ValidateOptions(opts))
            {
                return;
            }
            if (opts.passwordCheck)
            {
                long isCompromised = CompromisedCredentialsChecker.Checker.PasswordCheck(opts.apiKey, opts.userAgent, opts.password);
                if (isCompromised > 0)
                {
                    Console.WriteLine($"Password [{opts.password}] has been compromised");
                }
                else
                {
                    Console.WriteLine($"Password [{opts.password}]  has not been compromised");
                }
            }
            if (opts.getSubscriptionStatus)
            {
                CompromisedCredentialsChecker.HIBPSubscriptionStatus subscriptionStatus = CompromisedCredentialsChecker.Checker.GetSubscriptionStatus(opts.apiKey, opts.userAgent);
                Console.WriteLine($"Subscription Status:");
                Console.WriteLine($"\tSubscription Name:{subscriptionStatus.SubscriptionName}");
                Console.WriteLine($"\tSubscription Description:{subscriptionStatus.Description}");
                Console.WriteLine($"\tSubscription valid through:{subscriptionStatus.SubscribedUntil}");
                Console.WriteLine($"\tRate Limit Request/Minute:{subscriptionStatus.Rpm}");
                Console.WriteLine($"\tDomain Search Max Breached Accounts:{subscriptionStatus.DomainSearchMaxBreachedAccounts}");
            }
            if (opts.getSubscribedDomains)
            {
               // dynamic domains = CompromisedCredentialsChecker.Checker.GetSubscribedDomains(opts.apiKey, opts.userAgent);
               Console.Write("working on this one");
            }
            if (opts.getSingleBreachedSiteByName)
            {
                CompromisedCredentialsChecker.HIBPBreach breach = CompromisedCredentialsChecker.Checker.GetSingleBreachedSiteByName(opts.apiKey, opts.userAgent, opts.breach);
                WriteOutBreach(breach);
            }
            if(opts.getMostRecentBreachAdded)
            {
                CompromisedCredentialsChecker.HIBPBreach breach = CompromisedCredentialsChecker.Checker.GetMostRecentBreachAdded(opts.apiKey, opts.userAgent);
                WriteOutBreach(breach);
            }
            if (opts.getBreachesForEmailAddress)
            {
                List<CompromisedCredentialsChecker.HIBPBreach> breaches = 
                    CompromisedCredentialsChecker.Checker.GetBreachesForEmailAddress(opts.apiKey, opts.userAgent, opts.emailAddress, opts.namesOnly, opts.domainFilter,opts.excludeUnverified);
                Console.WriteLine($"Breaches for {opts.emailAddress}");
                foreach (CompromisedCredentialsChecker.HIBPBreach breach in breaches)
                {
                    WriteOutBreach(breach);
                }
            }
            if (opts.getBreachedEmailsForDomain)
            {
                //List<CompromisedCredentialsChecker.HIBPBreach> breaches = CompromisedCredentialsChecker.Checker.GetBreachedEmailsForDomain(opts.apiKey, opts.userAgent, opts.domainFilter);
                //Console.WriteLine($"Breaches for {opts.domainFilter}");
                //foreach (CompromisedCredentialsChecker.HIBPBreach breach in breaches)
                //{
                //    WriteOutBreach(breach);
                //}
                Console.WriteLine("Not implemented yet");
            }
            if (opts.getAllDataClasses)
            {
                List<string> dataClasses = CompromisedCredentialsChecker.Checker.GetAllDataClasses(opts.apiKey, opts.userAgent);
                Console.WriteLine("Data Classes:");
                foreach (string dataClass in dataClasses)
                {
                    Console.WriteLine($"\t{dataClass}");
                }
            }
            if (opts.getAllBreaches)
            {
                List<CompromisedCredentialsChecker.HIBPBreach> breaches = CompromisedCredentialsChecker.Checker.GetAllBreaches(opts.apiKey, opts.userAgent);
                Console.WriteLine("Breaches:");
                foreach (CompromisedCredentialsChecker.HIBPBreach breach in breaches)
                {
                    WriteOutBreach(breach);
                }
            }
            if (opts.checkPastes)
            {
                List<CompromisedCredentialsChecker.HIBPPaste> pastes = CompromisedCredentialsChecker.Checker.CheckPastes(opts.apiKey, opts.userAgent, opts.emailAddress);
                Console.WriteLine($"Pastes for {opts.emailAddress}");
                foreach (CompromisedCredentialsChecker.HIBPPaste paste in pastes)
                {
                    Console.WriteLine($"\tSource:{paste.Source}");
                    Console.WriteLine($"\tId:{paste.Id}");
                    Console.WriteLine($"\tTitle:{paste.Title}");
                    Console.WriteLine($"\tDate:{paste.Date}");
                    Console.WriteLine($"\tEmailCount:{paste.EmailCount}");
                }
            }
        }

        private static void WriteOutBreach(CompromisedCredentialsChecker.HIBPBreach breach)
        {
            Console.WriteLine($"\tBreach Name:{breach.Name}");
            if (!string.IsNullOrEmpty(breach.Title))
            {
                Console.WriteLine($"\t\tBreach Title:{breach.Title}");
                Console.WriteLine($"\t\tBreach Date:{breach.BreachDate}");
                Console.WriteLine($"\t\tAdded Date:{breach.AddedDate}");
                Console.WriteLine($"\t\tPwnCount:{breach.PwnCount}");
                Console.WriteLine($"\t\tDescription:{breach.Description}");
                Console.WriteLine($"\t\tDataClasses:{string.Join(",", breach.DataClasses)}");
                Console.WriteLine($"\t\tIsVerified:{breach.IsVerified}");
                Console.WriteLine($"\t\tIsFabricated:{breach.IsFabricated}");
                Console.WriteLine($"\t\tIsSensitive:{breach.IsSensitive}");
                Console.WriteLine($"\t\tIsRetired:{breach.IsRetired}");
                Console.WriteLine($"\t\tIsSpamList:{breach.IsSpamList}");
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            Console.WriteLine("Invalid options");
        }

        static bool ValidateOptions(Options opts)
        {
            
            if (opts.getBreachesForEmailAddress && string.IsNullOrEmpty(opts.emailAddress))
            {
                Console.WriteLine("--emailAddress is required for --getBreachesForEmailAddress");
                return false;
            }
            if (opts.checkPastes && string.IsNullOrEmpty(opts.emailAddress))
            {
                Console.WriteLine("--emailAddress is required for --checkPastes");
                return false;
            }
            if (opts.getSingleBreachedSiteByName && string.IsNullOrEmpty(opts.breach))
            {
                Console.WriteLine("--breach is required for --getSingleBreachedSiteByName");
                return false;
            }

            return true;
        }
    }

    public class Options
    {
        [Option("apiKey", Required = true, HelpText = "ApiKey from https://haveibeenpwned.com/API/Key")]
        public string apiKey { get; set; }

        [Option("userAgent", Required = true, HelpText = "UserAgent string passed in to API")]
        public string userAgent { get; set; }

        [Option("emailAddress", Required = false, HelpText = "Email Address for testing pastes, breaches")]
        public string emailAddress { get; set; }

        [Option("password", Required = false, HelpText = "Password to look up")]
        public string password { get; set; }

        [Option("breach", Required = false, HelpText = "Breach name to get more information on breaches")]
        public string breach { get; set; }

        [Option("domainFilter", Required = false, HelpText = "Filter by domain name. Used in getBreachesForeEmailAddress")]
        public string domainFilter { get; set; }

        [Option("checkPastes", Required = false, HelpText = "Check for pastes found including a specified email address")]
        public bool checkPastes { get; set; }

        [Option("getAllBreaches", Required = false, HelpText = "Get all of the breaches in the system")]
        public bool getAllBreaches { get; set; }

        [Option("getAllDataClasses", Required = false, HelpText = "Get all of the data classess in the system")]
        public bool getAllDataClasses { get; set; }

        [Option("getBreachedEmailsForDomain", Required = false, HelpText = "Determine all the breaches for email addresses for a specific domain.")]
        public bool getBreachedEmailsForDomain { get; set; }

        [Option("getBreachesForEmailAddress", Required = false, HelpText = "Determine all the breaches the email address has been involved in. Requires emailAddress. Optional domainFilter and namesOnly")]
        public bool getBreachesForEmailAddress { get; set; }
        
        [Option("namesOnly", Required = false, HelpText = "Return only names in breach information. Used for getBreachesForEmailAddress")]
        public bool namesOnly { get; set; }

        [Option("excludeUnverified", Required = false, HelpText = "Return only breaches marked verified in breach information. Used for getBreachesForEmailAddress")]
        public bool excludeUnverified { get; set; }

        [Option("getMostRecentBreachAdded", Required = false, HelpText = "Return the most recently added breach")]
        public bool getMostRecentBreachAdded { get; set; }

        [Option("getSubscribedDomains", Required = false, HelpText = "Get domains registered to the apiKey")]
        public bool getSubscribedDomains { get; set; }

        [Option("getSubscriptionStatus", Required = false, HelpText = "Get subscription information about the apiKey")]
        public bool getSubscriptionStatus { get; set; }

        [Option("passwordCheck", Required = false, HelpText = "Check to see if password has been compromised")]
        public bool passwordCheck { get; set; }

        [Option("isSpamList", Required = false, HelpText = "Filters the results on wehther a breach has been flagged as a spam list")]
        public bool isSpamList { get; set; }
        [Option("getSingleBreachedSiteByName", Required = false, HelpText = "Filters the results on wehther a breach has been flagged as a spam list")]
        public bool getSingleBreachedSiteByName { get; set; }
    }
}
