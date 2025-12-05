using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityScoreCard_VendorRiskMitigation
{
    public class ComplianceAnalyzer
    {
        // Map SecurityScorecard factors to compliance frameworks
        public class SecurityFactorMapping
        {
            public string Factor { get; set; }
            public List<string> NISTControls { get; set; }
            public List<string> ISO27001Controls { get; set; }
            public List<string> SOC2Criteria { get; set; }
            public List<string> CISControls { get; set; }
            public string Description { get; set; }
        }

        private static readonly Dictionary<string, SecurityFactorMapping> FactorMappings = new()
        {
            ["ApplicationSecurity"] = new SecurityFactorMapping
            {
                Factor = "Application Security",
                Description = "OWASP Top 10 compliance, secure coding practices, WAF implementation",
                NISTControls = new List<string> { "PR.DS-1", "PR.IP-2", "PR.IP-12", "DE.CM-4", "DE.CM-8" },
                ISO27001Controls = new List<string> { "A.8.9", "A.8.25", "A.8.26", "A.14.2.1", "A.14.2.5" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.6", "CC6.7", "CC7.1" },
                CISControls = new List<string> { "CIS-2", "CIS-3", "CIS-16" }
            },
            ["NetworkSecurity"] = new SecurityFactorMapping
            {
                Factor = "Network Security",
                Description = "Firewall configuration, network segmentation, IDS/IPS deployment",
                NISTControls = new List<string> { "PR.AC-3", "PR.AC-5", "PR.PT-4", "DE.CM-1", "DE.AE-1" },
                ISO27001Controls = new List<string> { "A.8.20", "A.8.21", "A.8.22", "A.13.1.1", "A.13.1.3" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.6", "CC7.2" },
                CISControls = new List<string> { "CIS-9", "CIS-11", "CIS-12", "CIS-13" }
            },
            ["DnsHealth"] = new SecurityFactorMapping
            {
                Factor = "DNS Health",
                Description = "DNSSEC, SPF, DKIM, DMARC configuration for email security",
                NISTControls = new List<string> { "PR.DS-2", "PR.AC-4", "DE.CM-7" },
                ISO27001Controls = new List<string> { "A.8.24", "A.13.2.1", "A.13.2.3" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.3" },
                CISControls = new List<string> { "CIS-7", "CIS-9" }
            },
            ["EndpointSecurity"] = new SecurityFactorMapping
            {
                Factor = "Endpoint Security",
                Description = "EDR deployment, anti-malware, device management, USB controls",
                NISTControls = new List<string> { "PR.DS-1", "PR.DS-5", "DE.CM-4", "DE.CM-8", "RS.MI-1" },
                ISO27001Controls = new List<string> { "A.8.1", "A.8.7", "A.8.8", "A.12.2.1" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.8", "CC7.1" },
                CISControls = new List<string> { "CIS-4", "CIS-6", "CIS-10" }
            },
            ["HackerChatter"] = new SecurityFactorMapping
            {
                Factor = "Hacker Chatter",
                Description = "Dark web monitoring, threat intelligence, brand monitoring",
                NISTControls = new List<string> { "ID.RA-2", "ID.RA-3", "DE.AE-4", "RS.AN-5" },
                ISO27001Controls = new List<string> { "A.5.7", "A.5.8", "A.16.1.1" },
                SOC2Criteria = new List<string> { "CC3.2", "CC7.3" },
                CISControls = new List<string> { "CIS-18" }
            },
            ["IpReputation"] = new SecurityFactorMapping
            {
                Factor = "IP Reputation",
                Description = "Malicious activity detection, botnet identification, spam sources",
                NISTControls = new List<string> { "DE.CM-1", "DE.AE-1", "RS.MI-3" },
                ISO27001Controls = new List<string> { "A.8.16", "A.12.6.1", "A.16.1.4" },
                SOC2Criteria = new List<string> { "CC6.1", "CC7.2" },
                CISControls = new List<string> { "CIS-7", "CIS-13" }
            },
            ["InformationLeak"] = new SecurityFactorMapping
            {
                Factor = "Information Leak",
                Description = "Data exposure prevention, credential leak detection, DLP",
                NISTControls = new List<string> { "PR.DS-1", "PR.DS-2", "PR.DS-5", "PR.IP-6", "DE.CM-8" },
                ISO27001Controls = new List<string> { "A.5.33", "A.8.10", "A.8.11", "A.8.12" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.5", "CC6.7", "C1.1", "C1.2" },
                CISControls = new List<string> { "CIS-3", "CIS-14" }
            },
            ["PatchingCadence"] = new SecurityFactorMapping
            {
                Factor = "Patching Cadence",
                Description = "Vulnerability management, patch deployment speed, update cycles",
                NISTControls = new List<string> { "ID.RA-1", "PR.IP-1", "PR.IP-12", "RS.MI-2" },
                ISO27001Controls = new List<string> { "A.8.8", "A.8.19", "A.12.6.1" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.2", "CC7.1" },
                CISControls = new List<string> { "CIS-2", "CIS-7" }
            },
            ["SocialEngineering"] = new SecurityFactorMapping
            {
                Factor = "Social Engineering",
                Description = "Phishing resistance, security awareness training, email security",
                NISTControls = new List<string> { "PR.AT-1", "PR.AT-2", "DE.CM-4", "RS.AN-5" },
                ISO27001Controls = new List<string> { "A.6.3", "A.7.2.2", "A.7.2.3" },
                SOC2Criteria = new List<string> { "CC6.1", "CC6.4" },
                CISControls = new List<string> { "CIS-14" }
            },
            ["CubitScore"] = new SecurityFactorMapping
            {
                Factor = "CUBIT Score",
                Description = "Overall cybersecurity maturity and risk posture",
                NISTControls = new List<string> { "ID.GV-1", "ID.GV-3", "ID.RM-1", "ID.SC-1" },
                ISO27001Controls = new List<string> { "A.5.1", "A.5.2", "A.5.3", "A.5.4" },
                SOC2Criteria = new List<string> { "CC1.1", "CC1.2", "CC3.1", "CC4.1" },
                CISControls = new List<string> { "CIS-1", "CIS-15", "CIS-17" }
            }
        };

        public static string GenerateComplianceReport(Vendor vendor)
        {
            var report = new StringBuilder();
            report.AppendLine($"COMPLIANCE IMPACT ASSESSMENT - {vendor.Company}");
            report.AppendLine("=" + new string('=', 50));
            report.AppendLine();

            var failedFactors = GetFailedSecurityFactors(vendor);
            if (!failedFactors.Any())
            {
                report.AppendLine("✅ No critical compliance failures detected.");
                return report.ToString();
            }

            report.AppendLine("⚠️ COMPLIANCE GAPS IDENTIFIED:");
            report.AppendLine();

            foreach (var factor in failedFactors)
            {
                if (FactorMappings.TryGetValue(factor.Key, out var mapping))
                {
                    report.AppendLine($"📊 {mapping.Factor}: Grade {factor.Value}");
                    report.AppendLine($"   Description: {mapping.Description}");
                    report.AppendLine();

                    report.AppendLine("   NIST CSF Controls Impacted:");
                    foreach (var control in mapping.NISTControls)
                    {
                        report.AppendLine($"   • {control}");
                    }

                    report.AppendLine("   ISO 27001:2022 Controls:");
                    foreach (var control in mapping.ISO27001Controls)
                    {
                        report.AppendLine($"   • {control}");
                    }

                    report.AppendLine("   SOC 2 Trust Criteria:");
                    foreach (var criteria in mapping.SOC2Criteria)
                    {
                        report.AppendLine($"   • {criteria}");
                    }

                    report.AppendLine("   CIS Controls v8:");
                    foreach (var control in mapping.CISControls)
                    {
                        report.AppendLine($"   • {control}");
                    }

                    report.AppendLine();
                }
            }

            // Add regulatory impact
            report.AppendLine("REGULATORY IMPACT:");
            report.AppendLine(DetermineRegulatoryImpact(vendor));

            return report.ToString();
        }

        private static Dictionary<string, string> GetFailedSecurityFactors(Vendor vendor)
        {
            var failures = new Dictionary<string, string>();

            if (IsFailingGrade(vendor.ApplicationSecurity))
                failures["ApplicationSecurity"] = vendor.ApplicationSecurity;
            if (IsFailingGrade(vendor.NetworkSecurity))
                failures["NetworkSecurity"] = vendor.NetworkSecurity;
            if (IsFailingGrade(vendor.DnsHealth))
                failures["DnsHealth"] = vendor.DnsHealth;
            if (IsFailingGrade(vendor.EndpointSecurity))
                failures["EndpointSecurity"] = vendor.EndpointSecurity;
            if (IsFailingGrade(vendor.HackerChatter))
                failures["HackerChatter"] = vendor.HackerChatter;
            if (IsFailingGrade(vendor.IpReputation))
                failures["IpReputation"] = vendor.IpReputation;
            if (IsFailingGrade(vendor.InformationLeak))
                failures["InformationLeak"] = vendor.InformationLeak;
            if (IsFailingGrade(vendor.PatchingCadence))
                failures["PatchingCadence"] = vendor.PatchingCadence;
            if (IsFailingGrade(vendor.SocialEngineering))
                failures["SocialEngineering"] = vendor.SocialEngineering;
            if (IsFailingGrade(vendor.CubitScore))
                failures["CubitScore"] = vendor.CubitScore;

            return failures;
        }

        private static bool IsFailingGrade(string grade)
        {
            return grade == "F" || grade == "D" || grade == "?";
        }

        private static string DetermineRegulatoryImpact(Vendor vendor)
        {
            var impact = new StringBuilder();

            // Check for financial services regulations
            if (vendor.Relationship == "Lender" || vendor.Industry == "financial services")
            {
                impact.AppendLine("• GLBA (Gramm-Leach-Bliley Act): Safeguards Rule violation risk");
                impact.AppendLine("• FDIC/OCC: Third-party risk management requirements");
                impact.AppendLine("• State Banking Regulations: Vendor oversight requirements");
            }

            // Check for real estate regulations
            if (vendor.Relationship == "Title Agency" || vendor.Relationship == "Real Estate Agency")
            {
                impact.AppendLine("• RESPA (Real Estate Settlement Procedures Act): Data security requirements");
                impact.AppendLine("• State Real Estate Commission: License compliance risk");
                impact.AppendLine("• ALTA Best Practices: Title insurance requirements");
            }

            // General data privacy
            impact.AppendLine("• CCPA/CPRA: California privacy law compliance");
            impact.AppendLine("• State Data Breach Laws: Notification requirements");

            // Industry-specific
            if (vendor.InformationLeak == "F" || vendor.InformationLeak == "D")
            {
                impact.AppendLine("• ⚠️ HIGH RISK: Data breach notification triggers in all 50 states");
                impact.AppendLine("• Potential FTC action for unfair/deceptive practices");
            }

            return impact.ToString();
        }

        public static string GenerateTechnicalRequirements(string grade, string factor)
        {
            if (!IsFailingGrade(grade)) return "";

            var requirements = new StringBuilder();
            requirements.AppendLine($"TECHNICAL REQUIREMENTS FOR {factor} (Current Grade: {grade}):");

            switch (factor)
            {
                case "ApplicationSecurity":
                    requirements.AppendLine("• Deploy Web Application Firewall (WAF)");
                    requirements.AppendLine("• Implement SAST/DAST in CI/CD pipeline");
                    requirements.AppendLine("• Conduct OWASP Top 10 assessment");
                    requirements.AppendLine("• Enable Content Security Policy (CSP)");
                    requirements.AppendLine("• Implement API rate limiting and authentication");
                    break;

                case "NetworkSecurity":
                    requirements.AppendLine("• Implement Zero Trust Network Architecture");
                    requirements.AppendLine("• Deploy IDS/IPS systems");
                    requirements.AppendLine("• Configure network segmentation/microsegmentation");
                    requirements.AppendLine("• Enable DDoS protection");
                    requirements.AppendLine("• Implement secure remote access (VPN/ZTNA)");
                    break;

                case "InformationLeak":
                    requirements.AppendLine("• Deploy Data Loss Prevention (DLP) solution");
                    requirements.AppendLine("• Implement secrets management (HashiCorp Vault)");
                    requirements.AppendLine("• Enable database activity monitoring");
                    requirements.AppendLine("• Configure S3 bucket security policies");
                    requirements.AppendLine("• Implement file integrity monitoring");
                    break;

                case "PatchingCadence":
                    requirements.AppendLine("• Implement automated patch management");
                    requirements.AppendLine("• Deploy vulnerability scanning (weekly)");
                    requirements.AppendLine("• Establish patch testing environment");
                    requirements.AppendLine("• Define critical patch SLA (24-48 hours)");
                    requirements.AppendLine("• Implement configuration management database");
                    break;
            }

            return requirements.ToString();
        }
    }
}