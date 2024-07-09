param($eventGridEvent, $TriggerMetadata)

function GeneratePassword([int]$Length){
    $newPassValue = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | Sort-Object {Get-Random})[0..14] -join ''
    $newPassValue = ConvertTo-SecureString $newPassValue -AsPlainText -Force
    return $newPassValue
}

function AddSecretToKeyVault($keyVAultName,$secretName,$newPassValue,$exprityDate,$tags){
    Set-AzKeyVaultSecret -VaultName $keyVAultName -Name $secretName -SecretValue $newPassValue -Tag $tags -Expires $expiryDate
}

function UpdateVM($newPassValue,$credentialId){
    $cred = New-Object System.Management.Automation.PSCredential ($credentialId, $newPassValue)
    $split = $providerAddress -split '/'
    $RgName = $split[4]
    $VmName = $split[-1]
    Set-AzVMAccessExtension -ResourceGroupName $RgName -name enablevmAccess -VMName $VmName -Credential ($cred) -typeHandlerVersion "2.0"
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

# Make sure to pass hashtables to Out-String so they're logged correctly
$eventGridEvent | ConvertTo-Json | Write-Host

$secretName = $eventGridEvent.subject
$keyVaultName = $eventGridEvent.data.VaultName
Write-Host "Key Vault Name: $keyVAultName"
Write-Host "Secret Name: $secretName"

#Rotate secret
Write-Host "Rotation started."
RoatateSecret $keyVAultName $secretName
Write-Host "Secret Rotated Successfully"

