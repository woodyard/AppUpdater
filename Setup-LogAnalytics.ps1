<#
.SYNOPSIS
    Sets up an Azure Log Analytics Workspace for WingetUpgradeManager diagnostics.

.DESCRIPTION
    Creates a Resource Group and Log Analytics Workspace using Azure CLI.
    Outputs the Workspace ID and Shared Key needed by the diagnostics script.

.NOTES
    Prerequisites: Azure CLI (az) installed and logged in (az login).
    Run once per customer/tenant to provision the infrastructure.

.EXAMPLE
    .\Setup-LogAnalytics.ps1 -ResourceGroup "rg-winget-diagnostics" -WorkspaceName "law-winget-diag" -Location "westeurope"
#>

param(
    [string]$ResourceGroup   = "rg-winget-diagnostics",
    [string]$WorkspaceName   = "law-winget-diag",
    [string]$Location        = "westeurope",
    [int]$RetentionDays      = 30
)

$ErrorActionPreference = "Stop"

# --- Verify Azure CLI is available and logged in ---
try {
    $account = az account show 2>&1 | ConvertFrom-Json
    if (-not $account.id) { throw "Not logged in" }
    Write-Host "Using subscription: $($account.name) ($($account.id))" -ForegroundColor Cyan
} catch {
    Write-Host "Azure CLI not logged in. Running 'az login'..." -ForegroundColor Yellow
    az login
    $account = az account show 2>&1 | ConvertFrom-Json
    Write-Host "Using subscription: $($account.name) ($($account.id))" -ForegroundColor Cyan
}

# --- Create Resource Group ---
Write-Host "`nCreating resource group '$ResourceGroup' in '$Location'..." -ForegroundColor Cyan
az group create --name $ResourceGroup --location $Location --output none
Write-Host "  Resource group ready." -ForegroundColor Green

# --- Create Log Analytics Workspace ---
Write-Host "Creating Log Analytics Workspace '$WorkspaceName'..." -ForegroundColor Cyan
az monitor log-analytics workspace create `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --location $Location `
    --retention-time $RetentionDays `
    --output none

Write-Host "  Workspace ready." -ForegroundColor Green

# --- Retrieve Workspace ID and Key ---
Write-Host "Retrieving workspace credentials..." -ForegroundColor Cyan

$workspaceId = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --query customerId --output tsv

$sharedKey = az monitor log-analytics workspace get-shared-keys `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --query primarySharedKey --output tsv

# --- Output ---
Write-Host "`n============================================" -ForegroundColor Green
Write-Host " Log Analytics Workspace Provisioned" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Resource Group : $ResourceGroup"
Write-Host "  Workspace Name : $WorkspaceName"
Write-Host "  Location       : $Location"
Write-Host "  Retention      : $RetentionDays days"
Write-Host ""
Write-Host "  Workspace ID   : $workspaceId"
Write-Host "  Shared Key     : $($sharedKey.Substring(0,8))...  (truncated)"
Write-Host ""
Write-Host "Use these values in the diagnostics script:" -ForegroundColor Yellow
Write-Host "  -WorkspaceId '$workspaceId'" -ForegroundColor White
Write-Host "  -SharedKey   '<full key from Azure portal>'" -ForegroundColor White
Write-Host ""
Write-Host "Or set them as Intune script parameters / environment variables." -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Green

# Save to a local config file for convenience
$configPath = Join-Path $PSScriptRoot "diagnostics-config.json"
@{
    WorkspaceId   = $workspaceId
    SharedKey     = $sharedKey
    WorkspaceName = $WorkspaceName
    ResourceGroup = $ResourceGroup
    Location      = $Location
    CreatedAt     = (Get-Date -Format "o")
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

Write-Host "Config saved to: $configPath" -ForegroundColor Cyan
Write-Host "WARNING: This file contains the shared key. Store it securely." -ForegroundColor Red
