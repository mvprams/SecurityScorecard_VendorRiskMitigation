# SecurityScorecard Vendor Risk Mitigation

A lightweight WPF utility for quickly drafting a risk mitigation strategy based on SecurityScorecard findings.

## Table of Contents
- Overview
- Features
- Getting Started
- Usage
- Configuration
- Building
- Testing
- Roadmap
- License

## Overview
This app helps security teams and vendor managers collect SecurityScorecard issues, prioritize them, and export a mitigation plan under tight timelines.

## Features
- Import or manually enter SecurityScorecard issues for vendors.
- Categorize findings (e.g., network, application, endpoint, policy).
- Assign severity, owner, and target dates.
- Auto-generate a concise mitigation plan.
- Export summaries for stakeholders (e.g., PDF/Word roadmap; implementation dependent).

## Getting Started
### Prerequisites
- Windows with .NET 6 SDK or later
- Visual Studio 2022 (or `dotnet` CLI) with WPF workloads

### Clone and restore
```
powershell
git clone <repo-url>
cd SecurityScorecard_VendorRiskMitigation
dotnet restore
```

## Usage
1) Open the solution in Visual Studio or run `dotnet run` from the project folder.
2) Enter vendor details and add SecurityScorecard findings.
3) Review auto-prioritized items; adjust severity, owner, and due dates.
4) Export or copy the mitigation plan for stakeholders.

## Configuration
- Default severity mapping and SLA targets can be adjusted in-app (or via config once implemented).
- Logging/output paths: configurable in future iterations.

## Building
```
powershell
dotnet build
```

## Testing
If/when tests exist:
```
powershell
dotnet test
```

## Roadmap
- SecurityScorecard API ingestion for live issue pulls.
- Customizable risk scoring weights.
- Export to PDF/Word.
- Status dashboard for vendor follow-up.
- Authentication/role-based access for shared environments.

## License
Add your license here (e.g., MIT, Apache-2.0).
