function Get-RandomPassword {
    
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword(16,2)
}