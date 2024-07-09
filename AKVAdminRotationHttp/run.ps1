using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

function GeneratePassword([int]$Length){
    $newPassValue = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | Sort-Object {Get-Random})[0..14] -join ''
    $newPassValue = ConvertTo-SecureString $newPassValue -AsPlainText -Force
    return $newPassValue
}

function AddSecretToKeyVault($keyVAultName,$secretName,$newPassValue,$exprityDate,$tags){
    Set-AzKeyVaultSecret -VaultName $keyVAultName -Name $secretName -SecretValue $newPassValue -Tag $tags -Expires $expiryDate
}

function UpdateVM($newPassValue,$credentialId){
    $cred = New-Object System.Management.Automation.PSCredential ("username", $newPassValue)
    $split = $providerAddress -split '/'
    $RgName = $split[4]
    $VmName = $split[-1]
    Set-AzVMAccessExtension -ResourceGroupName $RgName -Location $Location -VMName $VmName -Credential ($cred) -typeHandlerVersion "2.0" -Name VMAccessAgent
}

function RoatateSecret($keyVaultName,$secretName){
    #Retrieve Secret
    $secret = (Get-AzKeyVaultSecret -VaultName $keyVAultName -Name $secretName)
    Write-Host "Secret Retrieved"
    
    #Retrieve Secret Info
    $validityPeriodDays = $secret.Tags["ValidityPeriodDays"]
    $credentialId=  $secret.Tags["CredentialId"]
    $providerAddress = $secret.Tags["ProviderAddress"]
    
    Write-Host "Secret Info Retrieved"
    Write-Host "Validity Period: $validityPeriodDays"
    Write-Host "Credential Id: $credentialId"
    Write-Host "Provider Address: $providerAddress"

    #Regenerate alternate access key in provider
    $newPassValue = GeneratePassword
    Write-Host "Password generated. User Id: $CredentialId Resource Id: $providerAddress"

    #Add new access key to Key Vault
    $newSecretVersionTags = @{}
    $newSecretVersionTags.ValidityPeriodDays = $validityPeriodDays
    $newSecretVersionTags.CredentialId=$CredentialId
    $newSecretVersionTags.ProviderAddress = $providerAddress

    $expiryDate = (Get-Date).AddDays([int]$validityPeriodDays).ToUniversalTime()
    AddSecretToKeyVault $keyVAultName $secretName $newPassValue $expiryDate $newSecretVersionTags
    UpdateVM $newPassValue $credentialId
    Write-Host "New access key added to Key Vault. Secret Name: $secretName"
}


# Write to the Azure Functions log stream.
Write-Host "HTTP trigger function processed a request."

Try{
    #Validate request paramaters
    $keyVAultName = $Request.Query.KeyVaultName
    $secretName = $Request.Query.SecretName
    if (-not $keyVAultName -or -not $secretName ) {
        $status = [HttpStatusCode]::BadRequest
        $body = "Please pass a KeyVaultName and SecretName on the query string"
        break
    }
    
    Write-Host "Key Vault Name: $keyVAultName"
    Write-Host "Secret Name: $secretName"
    
    #Rotate secret
    Write-Host "Rotation started. Secret Name: $secretName"
    RoatateSecret $keyVAultName $secretName

    $status = [HttpStatusCode]::Ok
    $body = "Secret Rotated Successfully"
     
}
Catch{
    $status = [HttpStatusCode]::InternalServerError
    $body = "Error during secret rotation"
    Write-Error "Secret Rotation Failed: $_.Exception.Message"
}
Finally
{
    # Associate values to output bindings by calling 'Push-OutputBinding'.
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $status
        Body = $body
    })
}

