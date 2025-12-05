// MainWindow.xaml.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using Microsoft.Win32;

namespace SecurityScoreCard_VendorRiskMitigation
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<Vendor> vendors = new ObservableCollection<Vendor>();
        private ObservableCollection<Vendor> filteredVendors = new ObservableCollection<Vendor>();
        private List<Vendor> allVendors = new List<Vendor>();
        private readonly HttpClient httpClient = new HttpClient();

        public MainWindow()
        {
            InitializeComponent();
            VendorDataGrid.ItemsSource = filteredVendors;

            // Set up event handlers
            VendorDataGrid.SelectionChanged += VendorDataGrid_SelectionChanged;
        }

        private void LoadData_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                if (openFileDialog.ShowDialog() == true)
                {
                    LoadCsvData(openFileDialog.FileName);
                    UpdateStatusText($"Loaded {allVendors.Count} vendors from CSV");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading CSV: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCsvData(string filePath)
        {
            allVendors.Clear();
            vendors.Clear();
            filteredVendors.Clear();

            var lines = File.ReadAllLines(filePath);
            if (lines.Length > 1)
            {
                for (int i = 1; i < lines.Length; i++)
                {
                    var parts = SplitCsvLine(lines[i]);
                    if (parts.Length >= 20)
                    {
                        var vendor = new Vendor
                        {
                            Company = parts[0],
                            Relationship = parts[1],
                            Domain = parts[3],
                            Status = parts[4],
                            Grade = parts[5],
                            Evidence = parts[6],
                            Percentile = parts[7],
                            ThirtyDayChange = parts[8],
                            Industry = parts[9],
                            ApplicationSecurity = parts[10],
                            CubitScore = parts[11],
                            DnsHealth = parts[12],
                            EndpointSecurity = parts[13],
                            HackerChatter = parts[14],
                            IpReputation = parts[15],
                            NetworkSecurity = parts[16],
                            InformationLeak = parts[17],
                            PatchingCadence = parts[18],
                            SocialEngineering = parts[19],
                            Tags = parts.Length > 21 ? parts[21] : "",
                            RiskLevel = DetermineRiskLevel(parts[5])
                        };
                        allVendors.Add(vendor);
                        vendors.Add(vendor);
                        filteredVendors.Add(vendor);
                    }
                }

                PopulateRelationshipFilter();
                UpdateRiskCounts();
            }
        }

        private string[] SplitCsvLine(string line)
        {
            var result = new List<string>();
            var current = new StringBuilder();
            bool inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                if (line[i] == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (line[i] == ',' && !inQuotes)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(line[i]);
                }
            }
            result.Add(current.ToString());
            return result.ToArray();
        }

        private string DetermineRiskLevel(string grade)
        {
            return grade switch
            {
                "A" => "Low",
                "B" or "C" => "Medium",
                "D" or "F" or "?" => "High",
                _ => "Unknown"
            };
        }

        private void PopulateRelationshipFilter()
        {
            RelationshipFilter.Items.Clear();
            RelationshipFilter.Items.Add(new ComboBoxItem { Content = "All Relationships", IsSelected = true });

            var relationships = allVendors.Select(v => v.Relationship).Distinct().OrderBy(r => r);
            foreach (var relationship in relationships)
            {
                if (!string.IsNullOrEmpty(relationship))
                {
                    RelationshipFilter.Items.Add(new ComboBoxItem { Content = relationship });
                }
            }
        }

        private void UpdateRiskCounts()
        {
            int highRisk = filteredVendors.Count(v => v.RiskLevel == "High");
            int mediumRisk = filteredVendors.Count(v => v.RiskLevel == "Medium");
            int lowRisk = filteredVendors.Count(v => v.RiskLevel == "Low");

            HighRiskCount.Text = highRisk.ToString();
            MediumRiskCount.Text = mediumRisk.ToString();
            LowRiskCount.Text = lowRisk.ToString();
        }

        private void ApplyFilters_Click(object sender, RoutedEventArgs e)
        {
            filteredVendors.Clear();

            var selectedRelationship = (RelationshipFilter.SelectedItem as ComboBoxItem)?.Content.ToString();
            var selectedRiskLevel = (RiskFilter.SelectedItem as ComboBoxItem)?.Content.ToString();

            var filtered = allVendors.AsEnumerable();

            if (selectedRelationship != "All Relationships" && !string.IsNullOrEmpty(selectedRelationship))
            {
                filtered = filtered.Where(v => v.Relationship == selectedRelationship);
            }

            if (selectedRiskLevel != "All Risk Levels" && !string.IsNullOrEmpty(selectedRiskLevel))
            {
                if (selectedRiskLevel.Contains("High"))
                    filtered = filtered.Where(v => v.RiskLevel == "High");
                else if (selectedRiskLevel.Contains("Medium"))
                    filtered = filtered.Where(v => v.RiskLevel == "Medium");
                else if (selectedRiskLevel.Contains("Low"))
                    filtered = filtered.Where(v => v.RiskLevel == "Low");
            }

            foreach (var vendor in filtered)
            {
                filteredVendors.Add(vendor);
            }

            UpdateRiskCounts();
            UpdateStatusText($"Showing {filteredVendors.Count} of {allVendors.Count} vendors");
        }

        private void VendorDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedItems = VendorDataGrid.SelectedItems.Cast<Vendor>().ToList();
            SelectedCount.Text = selectedItems.Count.ToString();

            foreach (var vendor in filteredVendors)
            {
                vendor.IsSelected = selectedItems.Contains(vendor);
            }
        }

        private async void GenerateStrategy_Click(object sender, RoutedEventArgs e)
        {
            var selectedVendors = filteredVendors.Where(v => v.IsSelected).ToList();

            if (selectedVendors.Count == 0)
            {
                MessageBox.Show("Please select at least one vendor to generate a risk mitigation strategy.",
                    "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                ShowLoading(true);
                UpdateStatusText("Generating AI-powered risk mitigation strategy...");

                string strategy = await GenerateRiskMitigationStrategy(selectedVendors);
                DisplayStrategy(strategy);

                UpdateStatusText("Risk mitigation strategy generated successfully!");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error generating strategy: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                UpdateStatusText("Failed to generate strategy");
            }
            finally
            {
                ShowLoading(false);
            }
        }

        private async Task<string> GenerateRiskMitigationStrategy(List<Vendor> selectedVendors)
        {
            string apiKey = ConfigurationManager.AppSettings["OpenAI_APIKey"];
            string apiEndpoint = ConfigurationManager.AppSettings["OpenAI_Endpoint"] ?? "https://api.openai.com/v1/chat/completions";
            string model = ConfigurationManager.AppSettings["OpenAI_Model"] ?? "gpt-4";

            if (string.IsNullOrEmpty(apiKey))
            {
                throw new Exception("OpenAI API key not configured. Please update app.config file.");
            }

            // Prepare comprehensive vendor security assessment data
            var vendorSummary = new StringBuilder();
            vendorSummary.AppendLine("COMPREHENSIVE VENDOR SECURITY ASSESSMENT DATA:");
            vendorSummary.AppendLine("==============================================");
            vendorSummary.AppendLine();
            vendorSummary.AppendLine("SECURITY ASSESSMENT BASED ON SECURITYSCORECARD FACTORS:");
            vendorSummary.AppendLine("- Application Security (OWASP Top 10, Secure SDLC)");
            vendorSummary.AppendLine("- CUBIT Score (Cybersecurity Maturity Assessment)");
            vendorSummary.AppendLine("- DNS Health (DNSSEC, SPF, DMARC compliance)");
            vendorSummary.AppendLine("- Endpoint Security (EDR, Anti-malware, Device Management)");
            vendorSummary.AppendLine("- Hacker Chatter (Dark Web Intelligence, Threat Actor Interest)");
            vendorSummary.AppendLine("- IP Reputation (Malicious Activity, Botnet Detection)");
            vendorSummary.AppendLine("- Network Security (Firewall, IDS/IPS, Network Segmentation)");
            vendorSummary.AppendLine("- Information Leak (Data Exposure, Credential Leaks)");
            vendorSummary.AppendLine("- Patching Cadence (Vulnerability Management, Update Frequency)");
            vendorSummary.AppendLine("- Social Engineering (Phishing Susceptibility, Security Awareness)");
            vendorSummary.AppendLine();

            var highRiskVendors = selectedVendors.Where(v => v.RiskLevel == "High").ToList();
            var mediumRiskVendors = selectedVendors.Where(v => v.RiskLevel == "Medium").ToList();
            var lowRiskVendors = selectedVendors.Where(v => v.RiskLevel == "Low").ToList();

            if (highRiskVendors.Any())
            {
                vendorSummary.AppendLine("🔴 CRITICAL RISK VENDORS (IMMEDIATE ACTION REQUIRED):");
                vendorSummary.AppendLine("====================================================");
                foreach (var v in highRiskVendors)
                {
                    vendorSummary.AppendLine($"\nVendor: {v.Company}");
                    vendorSummary.AppendLine($"Relationship Type: {v.Relationship}");
                    vendorSummary.AppendLine($"Overall Grade: {v.Grade} | Percentile: {v.Percentile} | 30-Day Trend: {v.ThirtyDayChange}");
                    vendorSummary.AppendLine($"Domain: {v.Domain} | Industry: {v.Industry}");
                    vendorSummary.AppendLine();
                    vendorSummary.AppendLine("DETAILED SECURITY FACTOR ANALYSIS:");
                    vendorSummary.AppendLine($"├─ Application Security: {v.ApplicationSecurity} - OWASP/Secure Coding Issues");
                    vendorSummary.AppendLine($"├─ CUBIT Score: {v.CubitScore} - Overall Cybersecurity Maturity");
                    vendorSummary.AppendLine($"├─ DNS Health: {v.DnsHealth} - Email/Domain Security Configuration");
                    vendorSummary.AppendLine($"├─ Endpoint Security: {v.EndpointSecurity} - Device/Workstation Protection");
                    vendorSummary.AppendLine($"├─ Hacker Chatter: {v.HackerChatter} - Threat Actor Interest Level");
                    vendorSummary.AppendLine($"├─ IP Reputation: {v.IpReputation} - Network Compromise Indicators");
                    vendorSummary.AppendLine($"├─ Network Security: {v.NetworkSecurity} - Perimeter/Infrastructure Security");
                    vendorSummary.AppendLine($"├─ Information Leak: {v.InformationLeak} - Data Exposure/Breach Risk");
                    vendorSummary.AppendLine($"├─ Patching Cadence: {v.PatchingCadence} - Vulnerability Management");
                    vendorSummary.AppendLine($"└─ Social Engineering: {v.SocialEngineering} - Human Factor Vulnerability");

                    // Identify critical failures
                    var criticalIssues = new List<string>();
                    if (v.ApplicationSecurity == "F" || v.ApplicationSecurity == "D") criticalIssues.Add("Application Security");
                    if (v.NetworkSecurity == "F" || v.NetworkSecurity == "D") criticalIssues.Add("Network Security");
                    if (v.InformationLeak == "F" || v.InformationLeak == "D") criticalIssues.Add("Information Leak");
                    if (v.EndpointSecurity == "F" || v.EndpointSecurity == "D") criticalIssues.Add("Endpoint Security");

                    if (criticalIssues.Any())
                    {
                        vendorSummary.AppendLine($"\n⚠️ CRITICAL FAILURES: {string.Join(", ", criticalIssues)}");
                    }

                    // Add compliance analysis if ComplianceAnalyzer is available
                    try
                    {
                        vendorSummary.AppendLine();
                        vendorSummary.AppendLine("COMPLIANCE MAPPING:");
                        vendorSummary.AppendLine(ComplianceAnalyzer.GenerateComplianceReport(v));
                    }
                    catch
                    {
                        // ComplianceAnalyzer might not be included yet
                    }
                }
            }

            if (mediumRiskVendors.Any())
            {
                vendorSummary.AppendLine("\n🟡 MEDIUM RISK VENDORS (ACTION RECOMMENDED):");
                vendorSummary.AppendLine("==========================================");
                foreach (var v in mediumRiskVendors)
                {
                    vendorSummary.AppendLine($"\nVendor: {v.Company} ({v.Relationship})");
                    vendorSummary.AppendLine($"Grade: {v.Grade} | Percentile: {v.Percentile}");
                    vendorSummary.AppendLine("Key Security Concerns:");
                    if (v.ApplicationSecurity == "C" || v.ApplicationSecurity == "B")
                        vendorSummary.AppendLine($"- Application Security: {v.ApplicationSecurity}");
                    if (v.NetworkSecurity == "C" || v.NetworkSecurity == "B")
                        vendorSummary.AppendLine($"- Network Security: {v.NetworkSecurity}");
                    if (v.PatchingCadence == "C" || v.PatchingCadence == "B")
                        vendorSummary.AppendLine($"- Patching Cadence: {v.PatchingCadence}");
                }
            }

            if (lowRiskVendors.Any())
            {
                vendorSummary.AppendLine("\n🟢 LOW RISK VENDORS (MAINTAIN MONITORING):");
                vendorSummary.AppendLine("========================================");
                foreach (var v in lowRiskVendors)
                {
                    vendorSummary.AppendLine($"- {v.Company} ({v.Relationship}): Grade {v.Grade}, Percentile: {v.Percentile}");
                }
            }

            string prompt = $@"You are a Chief Information Security Officer (CISO) creating a comprehensive vendor risk mitigation strategy for TrueReal.io, a company digitizing real estate transactions. Your analysis must align with industry-standard cybersecurity frameworks and compliance requirements.

{vendorSummary}

COMPLIANCE & FRAMEWORK REQUIREMENTS:
- NIST Cybersecurity Framework (CSF 2.0)
- ISO 27001/27002 Standards
- SOC 2 Type II Requirements
- GLBA (Gramm-Leach-Bliley Act) for Financial Services
- CCPA/GDPR for Data Privacy
- Real Estate Transaction Security Standards
- PCI DSS (if payment processing involved)
- CIS Controls v8

Create a COMPREHENSIVE risk mitigation strategy that addresses:

1. IMMEDIATE CRITICAL ACTIONS (0-72 hours):
   - Emergency response for F-grade security factors
   - Incident response team activation criteria
   - Transaction freezing protocols
   - Customer protection measures

2. SECURITY FACTOR-SPECIFIC REMEDIATION:
   For each failing security factor (D/F grades), provide:
   - Technical root cause analysis
   - Specific remediation requirements
   - Compensating controls during remediation
   - Validation/testing criteria
   - Timeline for improvement

3. VENDOR-SPECIFIC ACTION PLANS:
   - Contractual security requirements amendments
   - Required security certifications (SOC 2, ISO 27001)
   - Penetration testing requirements
   - Security audit schedules
   - SLA for security improvements

4. TECHNICAL CONTROLS IMPLEMENTATION:
   - API security requirements (OAuth 2.0, rate limiting)
   - Data encryption standards (AES-256, TLS 1.3)
   - Zero Trust architecture requirements
   - Multi-factor authentication mandates
   - Security monitoring and SIEM integration

5. BUSINESS CONTINUITY & RESILIENCE:
   - Vendor redundancy requirements
   - Failover procedures
   - Data backup and recovery plans
   - Alternative vendor assessment matrix

6. RISK QUANTIFICATION & METRICS:
   - Financial impact assessment per vendor
   - Cyber insurance implications
   - Risk score targets and timelines
   - KPIs and KRIs for vendor security

7. GOVERNANCE & OVERSIGHT:
   - Board-level reporting structure
   - Vendor risk committee formation
   - Regular assessment schedule
   - Continuous monitoring requirements

Format the response as an executive briefing with:
- Executive Summary with risk heat map
- Prioritized action items with owners
- Budget requirements and ROI calculations
- Implementation roadmap with milestones
- Success metrics and monitoring dashboard requirements

Consider that TrueReal.io handles:
- Sensitive financial information
- Personal identifiable information (PII)
- Legal documents and contracts
- Payment processing
- Multi-party real estate transactions";

            var requestBody = new
            {
                model = model,
                messages = new[]
                {
                    new { role = "system", content = "You are a Chief Information Security Officer (CISO) and cybersecurity expert specializing in vendor risk management for fintech and proptech companies. You have deep expertise in NIST CSF, ISO 27001, SOC 2, and financial services compliance requirements. Provide actionable, technical, and business-aligned security strategies." },
                    new { role = "user", content = prompt }
                },
                temperature = 0.7,
                max_tokens = 3000
            };

            httpClient.DefaultRequestHeaders.Clear();
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await httpClient.PostAsync(apiEndpoint, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"API request failed: {response.StatusCode} - {responseContent}");
            }

            using (JsonDocument doc = JsonDocument.Parse(responseContent))
            {
                var root = doc.RootElement;
                if (root.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
                {
                    var firstChoice = choices[0];
                    if (firstChoice.TryGetProperty("message", out var message))
                    {
                        if (message.TryGetProperty("content", out var contentElement))
                        {
                            return contentElement.GetString();
                        }
                    }
                }
            }

            return "Unable to generate strategy from API response.";
        }

        private void DisplayStrategy(string strategy)
        {
            StrategyOutput.Document.Blocks.Clear();

            var paragraph = new Paragraph();
            var lines = strategy.Split('\n');

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    paragraph.Inlines.Add(new LineBreak());
                    continue;
                }

                Run run = new Run(line);

                // Apply formatting based on content
                if (line.StartsWith("#") || line.Contains("RISK") || line.Contains("STRATEGY") || line.Contains("ACTION"))
                {
                    run.FontWeight = FontWeights.Bold;
                    run.FontSize = 16;
                    run.Foreground = new SolidColorBrush(Color.FromRgb(33, 150, 243));
                }
                else if (line.StartsWith("-") || line.StartsWith("•") || line.StartsWith("*"))
                {
                    run.Foreground = new SolidColorBrush(Color.FromRgb(85, 85, 85));
                }
                else if (line.Contains("HIGH") || line.Contains("CRITICAL") || line.Contains("IMMEDIATE"))
                {
                    run.Foreground = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                    run.FontWeight = FontWeights.SemiBold;
                }
                else if (line.Contains("MEDIUM") || line.Contains("MODERATE"))
                {
                    run.Foreground = new SolidColorBrush(Color.FromRgb(255, 193, 7));
                    run.FontWeight = FontWeights.SemiBold;
                }
                else if (line.Contains("LOW") || line.Contains("MINIMAL"))
                {
                    run.Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                    run.FontWeight = FontWeights.SemiBold;
                }

                paragraph.Inlines.Add(run);
                paragraph.Inlines.Add(new LineBreak());
            }

            StrategyOutput.Document.Blocks.Add(paragraph);
        }

        private void ShowLoading(bool show)
        {
            LoadingProgress.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        }

        private void UpdateStatusText(string text)
        {
            StatusText.Text = text;
        }
    }

    // Vendor Model Class with Comprehensive Security Metrics
    public class Vendor
    {
        public bool IsSelected { get; set; }
        public string Company { get; set; }
        public string Relationship { get; set; }
        public string Domain { get; set; }
        public string Status { get; set; }
        public string Grade { get; set; }
        public string Evidence { get; set; }
        public string Percentile { get; set; }
        public string ThirtyDayChange { get; set; }
        public string Industry { get; set; }

        // SecurityScorecard Security Factors
        public string ApplicationSecurity { get; set; }
        public string CubitScore { get; set; }
        public string DnsHealth { get; set; }
        public string EndpointSecurity { get; set; }
        public string HackerChatter { get; set; }
        public string IpReputation { get; set; }
        public string NetworkSecurity { get; set; }
        public string InformationLeak { get; set; }
        public string PatchingCadence { get; set; }
        public string SocialEngineering { get; set; }

        public string RiskLevel { get; set; }
        public string Tags { get; set; }
    }
}