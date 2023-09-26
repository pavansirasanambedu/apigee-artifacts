# write-output Apigee Artifacts
$token = $env:TOKEN
$org = $env:manualorg
$git_token = $env:git_token
# $baseURL = "https://apigee.googleapis.com/v1/organizations/"
$baseURL = "https://httpbin.org/gt"
$headers = @{Authorization = "Bearer $token"}
$workflowmethod = $env:run

# Access the environment variables
$git_token = $env:GIT_TOKEN
$key = $env:KEY
$org = $env:ORG
$TOKEN = $env:TOKEN
$FieldValuestoEncrypt = $env:FIELD_VALUES
$FIRST_LEVEL_OBJECT = $env:FIRST_LEVEL_OBJECT
$appfieds = $env:APP_FIELDS
$timestamp = $env:TIMESTAMP
$run = $env:RUN
$deployment_org = $env:DEPLOYMENT_ORG
$github_actor = $env:GITHUB_ACTOR

# Now you can use these variables in your script


if ($workflowmethod -eq "manual"){
    Write-Host "Entered into Manual...!"
    # No need to reassign $org in the "manual" branch
    Write-Host $org
}
else{
    Write-Host "Entered into Schedule...!"
    $orgs = $env:org -split ","
    Write-Host $orgs
    foreach ($org in $orgs){
        Write-Host $org
    }
}

Write-Host "Exited out of the IF with: $org"

$path = $baseURL
Invoke-RestMethod -Uri "https://httpbin.org/gt" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "test.json"

if(!(test-path -PathType container apigee)){
      mkdir "apigee"
      cd apigee
      Write-Host "inside if"
}
else {
      cd apigee
      Write-Host "else"
}

if(!(test-path -PathType container apps)){
      mkdir "apps"
      cd apps
      Write-Host "inside if"
}
else {
      cd apps
      Write-Host "else"
}
# Create a hashtable for the output data
$outputData = @{
    Org = $org
    "Folder Names" = $folder_names_string
    "Triggered by" = "$github_actor on branch $env:GITHUB_REF. Status: $env:JOB_STATUS"
}

# Convert the hashtable to JSON
$jsonPayload = $outputData | ConvertTo-Json

# Output the JSON payload
Write-Output $jsonPayload
Write-Host "Folder Names: $folder_names_string"
Write-Host "Triggered by $github_actor on branch $env:GITHUB_REF. Status: $env:JOB_STATUS"


# Set output variables
Write-Output "::set-output name=folder_names_string::$folder_names_string"
Write-Output "::set-output name=github_actor::$github_actor"














# # --------------------Apigee All Artifacts-------------------------------------------


# # ----------------------create apigee organisation level artifacts folder------------
# # if(!(test-path -PathType container apigee)){
# #       mkdir "apigee"
# #       cd apigee
# #       Write-Host "inside if"
# # }
# # else {
# #       cd apigee
# #       Write-Host "else"
# # }

# # # create apigee artifacts non prod folder
# # if(!(test-path -PathType container apigee-x-artifacts-eu-pilot)){
# #       mkdir "apigee-x-artifacts-eu-pilot"
# #       cd apigee-x-artifacts-eu-pilot
# #       Write-Host "inside 1st if"
# # }
# # else {
# #       cd apigee-x-artifacts-eu-pilot
# #       Write-Host "1st else"
      
# # }

# # Specify the directory name
# $directoryName = $org

# # Check if the directory exists
# if (!(Test-Path -PathType Container $directoryName)) {
#     # If it doesn't exist, create it
#     mkdir $directoryName
#     cd $directoryName
#     Write-Host "Directory created: $directoryName"
# } else {
#     Write-Host "Directory already exists: $directoryName"
    
#     # Remove the directory and its contents if it exists
#     Remove-Item -Path $directoryName -Recurse
    
#     # Introduce a 2-second delay
#     Start-Sleep -Seconds 2
    
#     # Recreate the directory
#     mkdir $directoryName
#     cd $directoryName
#     Write-Host "Directory recreated: $directoryName"
# }

# # --------------------------------Proxies - All Revisions-------------------------------------------
#     if(!(test-path -PathType container proxies)){
#         mkdir "proxies"
#         cd proxies
#     }
#     else {
#         cd proxies
#     }

#     $path = $baseURL+$org+"/apis"
#     Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "proxies.json"
#     $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     foreach ($proxy in $($proxies.proxies)) {
#         $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
#         $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#         foreach ($proxyRevs in $($proxyRevs)) {
#             if(!(test-path -PathType container $($proxy.name))){
#             mkdir -p "$($proxy.name)"
#             cd $($proxy.name)
#             }
#             else {
#                 cd $($proxy.name)
#             }
#             $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($proxyRevs)+"?format=bundle"
#             $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($proxyRevs)+".zip"
            
#             $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

#             Expand-Archive -Path $zipFile -Force
#             # Remove-Item -Path $zipFile -Force
#             cd ..
#         }
#     }
#     cd..

# # --------------------------------Proxies- Latest Revision------------------------------------------
#     # if(!(test-path -PathType container proxies)){
#     #     mkdir "proxies"
#     #     cd proxies
#     # }
#     # else {
#     #     cd proxies
#     # }

#     # $path = $baseURL+$org+"/apis"
#     # $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     # foreach ($proxy in $($proxies.proxies)) {
#     #     $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
#     #     $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     #     # Get the latest deployed revision number
#     #     $latestRevision = $proxyRevs | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

#     #     if(!(test-path -PathType container $($proxy.name))){
#     #         mkdir -p "$($proxy.name)"
#     #         cd $($proxy.name)
#     #     }
#     #     else {
#     #         cd $($proxy.name)
#     #     }

#     #     $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($latestRevision)+"?format=bundle"
#     #     $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($latestRevision)+".zip"
        
#     #     $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

#     #     Expand-Archive -Path $zipFile -Force
#     #     Remove-Item -Path $zipFile -Force
#     #     cd..
#     # }
#     # cd..

# # --------------------------------SharedFlows - All Revs---------------------------------------------
#     if(!(test-path -PathType container SharedFlows)){
#         mkdir "SharedFlows"
#         cd SharedFlows
#     }
#     else {
#         cd SharedFlows
#     }

#     $sharedflowpath = $baseURL+$org+"/sharedflows"
#     Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "sharedflows.json"
#     $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     foreach ($sharedflow in $($sharedflows.sharedflows)) {
#         $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
#         $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#         foreach ($FlowRevs in $($FlowRevs)) {
#             if(!(test-path -PathType container $($sharedflow.name))){
#             mkdir -p "$($sharedflow.name)"
#             cd $($sharedflow.name)
#             }
#             else {
#                 cd $($sharedflow.name)
#             }
#             $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($FlowRevs)+"?format=bundle"
#             $sharedflowzipFile = $org+"-sharedflows-"+$($sharedflow.name)+"-rev"+$($FlowRevs)+".zip"

#             $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $sharedflowzipFile

#             Expand-Archive -Path $sharedflowzipFile -Force
#             # Remove-Item -Path $sharedflowzipFile -Force
#             cd ..
#         }
#     }
#     cd ..

# # ------------------------------------SharedFlows - Latest Revision---------------------------------------

#     # if(!(test-path -PathType container SharedFlows)){
#     #     mkdir "SharedFlows"
#     #     cd SharedFlows
#     # }
#     # else {
#     #     cd SharedFlows
#     # }

#     # $sharedflowpath = $baseURL+$org+"/sharedflows"
#     # $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     # foreach ($sharedflow in $($sharedflows.sharedflows)) {
#     #     $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
#     #     $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     #     if(!(test-path -PathType container $($sharedflow.name))){
#     #         mkdir -p "$($sharedflow.name)"
#     #         cd $($sharedflow.name)
#     #     }
#     #     else {
#     #         cd $($sharedflow.name)
#     #     }

#     #     # Get the latest deployed revision number
#     #     $latestFlowRevision = $($FlowRevs) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
#     #     $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($latestFlowRevision)+"?format=bundle"
#     #     $SharedFlowZipFile = $org+"-sharedflow-"+$($sharedflow.name)+"-rev"+$($latestFlowRevision)+".zip"
        
#     #     $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $SharedFlowZipFile

#     #     Expand-Archive -Path $SharedFlowZipFile -Force
#     #     Remove-Item -Path $SharedFlowZipFile -Force
#     #     cd ..
#     # }
#     # cd ..


# # ----------------------------------Org KVMs------------------------------------------------------------
#     if(!(test-path -PathType container org-kvms)){
#         mkdir "org-kvms"
#         cd org-kvms
#     }
#     else {
#         cd org-kvms
#     }

#     $kvmpath = $baseURL+$org+"/keyvaluemaps"
#     Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-kvms.json"

#     $orgkvms = Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#     foreach ($orgkvm in $($orgkvms)) {
#         if(!(test-path -PathType container $orgkvm)){
#         mkdir -p "$orgkvm"
#         cd $orgkvm
#         }
#         else {
#             cd $orgkvm
#         }
#         $kvmpath2 = $kvmpath+"/"+$($orgkvm)+"/entries"
#         $kvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-($($orgkvm)).json"
#         cd ..
#     }
#     cd ..


# # # ----------------------------API Products------------------------------------------
#     if(!(test-path -PathType container apiproducts))
#     {
#         mkdir "apiproducts"
#         cd apiproducts
#     }
#     else {
#         cd apiproducts
#     }

#     $productpath = $baseURL + $org + "/apiproducts"
# 	Invoke-RestMethod -Uri $productpath -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"
# 	$apiproductsResponse = Invoke-RestMethod -Uri $productpath -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60
	
# 	foreach ($product in $apiproductsResponse.apiProduct) {
# 	    $productFolder = $product.name
# 	    if (!(Test-Path -PathType Container $productFolder)) {
# 	        mkdir $productFolder
# 	    }
# 	    cd $productFolder
	
# 	    $apiproductdetail = $baseURL + $org + "/apiproducts/" + $product.name
# 	    Invoke-RestMethod -Uri $apiproductdetail -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$org-$($product.name).json"
	
# 	    cd ..
# 	}
	
# 	cd ..

#     Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"

# # -----------------------------Developers------------------------------------------
#     if(!(test-path -PathType container developers))
#     {
#         mkdir "developers"
#         cd developers
#     }
#     else {
#         cd developers
#     }

#     $developerpath = $baseURL+$org+"/developers"
#     Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"
#     $developer = Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

	
# 	foreach ($developerItem in $developer.developer) {
# 	    Write-Host "Entered into FOREACH...!"
	    
# 	    # Print Developer Email (debugging)
# 	    Write-Host "Developer Email: $($developerItem.email)"
	    
# 	 #    if (!(Test-Path -PathType Container $($developerItem.email))) {
# 		# Write-Host "Creating directory for $($developerItem.email)..."
# 		# mkdir "$($developerItem.email)"
# 		# cd $($developerItem.email)
# 	 #    }
# 	 #    else {
# 		# cd $($developerItem.email)
# 	 #    }
# 	    $developerdetail = $baseURL + $org + "/developers/" + $($developerItem.email)
# 	    Invoke-RestMethod -Uri $developerdetail -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$org-$($developerItem.email).json"
# 	    # cd ..
# 	}
# 	cd ..

#     Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"

# # ------------------------------Apps-------------------------------------------------
#     if(!(test-path -PathType container apps))
#     {
#         mkdir "apps"
#         cd apps
#     }
#     else {
#         cd apps
#     }
	
#     $Apps = $baseURL+$org+"/apps?expand=true"
#     # $Appdetails = Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"
#     $baseURL = "https://apigee.googleapis.com/v1/organizations/"
#     $org = "esi-apigee-x-394004"

#     # Define a function to encrypt data
# 	function Encrypt-Data {
# 	    param (
# 	        [string]$plaintext,
# 	        [string]$keyHex
# 	    )
	
# 	    # Create a new AES object with the specified key and AES mode
# 	    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
# 	    $AES.KeySize = 256  # Set the key size to 256 bits for AES-256
# 	    $AES.Key = [System.Text.Encoding]::UTF8.GetBytes($keyHex.PadRight(32))
# 	    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
	
# 	    # Convert plaintext to bytes (UTF-8 encoding)
# 	    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
	
# 	    # Generate a random initialization vector (IV)
# 	    $AES.GenerateIV()
# 	    $IVBase64 = [System.Convert]::ToBase64String($AES.IV)
	
# 	    # Encrypt the data
# 	    $encryptor = $AES.CreateEncryptor()
# 	    $encryptedBytes = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)
# 	    $encryptedBase64 = [System.Convert]::ToBase64String($encryptedBytes)
	
# 	    # Return the encrypted data and IV
# 	    return @{
# 	        "EncryptedValue" = $encryptedBase64
# 	        "IV" = $IVBase64
# 	    }
# 	}

#  	Write-Host "Current Directory: $(Get-Location)"
	
# 	# Your API endpoint and other variables
# 	$baseURL = "https://apigee.googleapis.com/v1/organizations/"
# 	$org = "esi-apigee-x-394004"
# 	$token = $env:TOKEN
# 	$headers = @{Authorization = "Bearer $token"}
	
# 	# Make the API call to get the list of apps
# 	$AppsEndpoint = "${baseURL}${org}/apps?expand=true"
# 	$AppList = Invoke-RestMethod -Uri $AppsEndpoint -Method Get -Headers $headers -ContentType "application/json" -TimeoutSec 60
	
# 	# Specify the fields you want to encrypt
# 	$appfileds = $env:appfieds -split ","
# 	$encryptedFields = @{}
	
# 	# Loop through the list of apps
# 	foreach ($app in $AppList.app) {
# 	    if ($app.name) {
# 		$appName = $app.name
# 		Write-Host "Entered into FOREACH: $appName"
# 		Write-Host "Current Directory: $(Get-Location)"

# 		if (!(Test-Path -PathType Container $appName)) {
# 		    New-Item -Path . -Name $appName -ItemType Directory
# 		    cd $appName
# 		    Write-Host "Directory created: $appName"
# 		}
# 		else {
# 		    cd $appName
# 		    Write-Host "Directory already exists: $appName"
# 		}

# 		try {
# 		    # Loop through the specified fields and encrypt their values
# 		    foreach ($field in $appfileds) {
# 			# Check if the credentials array exists and has at least one item
# 			if ($($app).credentials.Count -gt 0) {
# 			    # Access the value of the current field
# 			    $plaintext = $($app).credentials[0].$field

# 			    # Encrypt the data using the Encrypt-Data function
# 			    $encryptedData = Encrypt-Data -plaintext $plaintext -keyHex $keyHex

# 			    # Update the JSON data with the encrypted value
# 			    $app.credentials[0].$field = $encryptedData
# 			}
# 		    }

# 		    # Display the modified JSON data with only encrypted values
# 		    $encryptedJsonData = $app | ConvertTo-Json -Depth 10
# 		    Write-Host "Modified JSON Data:"
# 		    Write-Host $encryptedJsonData
# 				# Define the output file name based on environment variables
# 		$fileName = "$org-encrypt-apps-data.json"
	    
# 		    # Save the encrypted data to the file
# 		    $encryptedJsonData | Out-File -FilePath $fileName -Encoding UTF8
		    
# 		    Write-Host "Encrypted data saved to $fileName"
# 		}
# 		catch {
# 		    Write-Host "An error occurred: $_"
# 		}
# 		cd ..
# 	    }
# 	}
#  	cd ..
	
#  	Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"
	
# # ------------------------------master-deployments-proxies----------------------------
#     $masterDeploymentPath = $baseURL+$org+"/deployments"
#     $masterDeployments = Invoke-RestMethod -Uri $masterDeploymentPath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-master-proxy-deployments.json"

# # -----------------------------Environments Start-------------------------------------
#     if(!(test-path -PathType container environments)){
#         mkdir "environments"
#         cd environments
#     }
#     else {
#         cd environments
#     }

#     $envpath = $baseURL+$org+"/environments"
#     Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-env.json"
#     $environments = Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
    
#     #iterate for each environment
#     foreach ($env in $($environments)) {

#         if(!(test-path -PathType container $($env))){
#             mkdir "$($env)"
#             cd $($env)
#         }
#         else {
#             cd $($env)
#         }

#         # -----------------------------Environments - KVMs -------------------------------------
#         if(!(test-path -PathType container env-kvms)){
#             mkdir "env-kvms"
#             cd env-kvms
#         }
#         else {
#             cd env-kvms
#         }

#         $kvmpathenv = $baseURL+$org+"/environments/"+$($env)+"/keyvaluemaps"
#         Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-kvms.json"
#         $envkvms = Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#         foreach ($envkvm in $($envkvms)) {
#             if(!(test-path -PathType container $($envkvm))){
#                 mkdir "$($envkvm)"
#                 cd $($envkvm)
#             }
#             else {
#                 cd $($envkvm)
#             }

#             # $kvmpathenv2 = $kvmpathenv+"/"+$($envkvm)+"/entries"
#             # $envkvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($($envkvm)).json"
#             # cd ..
#             # $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
#             # $headers.Add("Authorization", "Bearer ya29.a0AfB_byCYq525bBvRLE3tibD4O1dOvozhbOrpAbNpIqXtsfkBvD-x8VFNszZKC5vj7mm0h-RypwdqL5H7_iukKjIn4BUxhYwUbPaTEdaZLFlFpu7hs_PwshYQuP1QisNg3bz2lbFTftNHMlS6fOh4oXEYVMoU9-s7htHCCvWqgeYaCgYKAcgSARESFQHsvYlsRs-EXW1LLkfCbK-OgQ9KYg0178")
            
#             # $kvmpthtestpath = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/keyvaluemaps/"+$envkvm+"/entries"

#             # $response = Invoke-RestMethod $kvmpthtestpath -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
#             # $response | ConvertTo-Json
#             # Write-Host "KVM Data: $response"

#             # Define a function to encrypt fields
#             function Encrypt-Fields {
#                 param (
#                     [System.Object]$data,
#                     [System.String[]]$fieldsToEncrypt,
#                     [System.Security.Cryptography.AesCryptoServiceProvider]$AES
#                 )
            
#                 foreach ($field in $fieldsToEncrypt) {
#                     if ($data.$field -ne $null) {
#                         $dataValue = $data.$field
            
#                         $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($dataValue)
            
#                         $AES.GenerateIV()
#                         $IVBase64 = [System.Convert]::ToBase64String($AES.IV)
            
#                         $encryptor = $AES.CreateEncryptor()
#                         $encryptedBytes = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
#                         $encryptedBase64 = [System.Convert]::ToBase64String($encryptedBytes)
            
#                         $data.$field = @{
#                             "EncryptedValue" = $encryptedBase64
#                             "IV" = $IVBase64
#                         }
#                     }
#                 }
            
#                 return $data
#             }
            
#             try {
#                 $git_token = $env:TOKEN
            
#                 # Make the API request to get KVM data
#                 $headers = @{
#                     "Authorization" = "Bearer $token"
#                 }
            
#                 $kvmpthtestpath = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/keyvaluemaps/$($envkvm)/entries"
            
#                 $response = Invoke-RestMethod -Uri $kvmpthtestpath -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60

#                 $itterateobject = $env:FIRST_LEVEL_OBJECT
            
#                 # Check if the response contains data
#                 if ($response -and $response.$itterateobject) {
#                     Write-Host "Entered into IF...!"
#                     Write-Host "KVM Data: $($response | ConvertTo-Json)"
                    
#                     # Decryption key
#                     $keyHex = $env:key
                    
#                     # Specify the fields you want to encrypt
#                     Write-Host "Values: $env:FieldValuestoEncrypt"
#                     $fieldsToEncrypt = $env:FieldValuestoEncrypt -split ","
#                     Write-Host "fieldsToEncrypt: $fieldsToEncrypt"
                    
#                     # Create an AES object for encryption
#                     $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
#                     $AES.KeySize = 256
#                     $AES.Key = [System.Text.Encoding]::UTF8.GetBytes($keyHex.PadRight(32))
#                     $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
            
#                     Write-Host "Trying to enter into FOREACH...!"
            
#                     # Loop through the JSON data and encrypt specified fields
#                     foreach ($entry in $response.$itterateobject) {
#                         Write-Host "Entered into FOREACH...!"
#                         # Call the Encrypt-Fields function to encrypt the specified fields
#                         $entry = Encrypt-Fields -data $entry -fieldsToEncrypt $fieldsToEncrypt -AES $AES
#                     }
                    
#                     # Convert the JSON data back to a string
#                     $encryptedJsonData = $response | ConvertTo-Json -Depth 10
                    
#                     Write-Host "Encrypted data: $encryptedJsonData"
                    
#                     # Define the output file name based on environment variables
#                     $fileName = "$($org)-$($envkvm).json"
                    
#                     # Save the encrypted data to the file
#                     $encryptedJsonData | Out-File -FilePath $fileName -Encoding UTF8
                    
#                     Write-Host "Encrypted data saved to $fileName"
#                 } else {
#                     Write-Host "No data found in the response."
#                 }
#             }
#             catch {
#                 Write-Host "An error occurred: $_"
#             }

            
#             cd ..
#         }
#         cd ..

#         # -------------------------------Environments - Targetservers-----------------------------
#         if(!(test-path -PathType container targetservers)){
#             mkdir "targetservers"
#             cd targetservers
#         }
#         else {
#             cd targetservers
#         }

#         $targetserverpathenv = $baseURL+$org+"/environments/"+$($env)+"/targetservers"
#         Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-targetservers.json"
#         $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

#         Write-Host $envtargetserver

#         foreach ($value in $($envtargetserver)) {
#             if(!(test-path -PathType container $($value))){
#                 mkdir "$($value)"
#                 cd $($value)
#             }
#             else {
#                 cd $($value)
#             }

#             $targetserverpathenv2 = $targetserverpathenv+"/"+$value
#             $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($value).json"
#             cd ..
#         }
#         cd ..

#  	# --------------------------------Environment - keystores--------------------------------------
#         if(!(test-path -PathType container keystores)){
#             mkdir "keystores"
#             cd keystores
#         }
#         else {
#             cd keystores
#         }

#         $keystorepathenv = $baseURL+$org+"/environments/"+$($env)+"/keystores"
#         $envkeystore = Invoke-RestMethod -Uri $keystorepathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-keystores.json"
        
#         cd ..

#  	# --------------------------------Environment - caches--------------------------------------
#         if(!(test-path -PathType container $org-caches)){
#             mkdir "caches"
#             cd caches
#         }
#         else {
#             cd caches
#         }

#         $cachepathenv = $baseURL+$org+"/environments/"+$($env)+"/caches"
#         $envcache = Invoke-RestMethod -Uri $cachepathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-caches.json"
        
#         cd ..

#  	# --------------------------------Environment - flowhooks--------------------------------------
#        # Set the base directory path
# 		$baseDirectory = "flowhooks"
		
# 		# Check if the base directory exists, and create it if not
# 		if (!(Test-Path -PathType Container $baseDirectory)) {
# 		    mkdir $baseDirectory
# 		}
		
# 		$flowhookpathenv = $baseURL + $org + "/environments/" + $env + "/flowhooks"
# 		Invoke-RestMethod -Uri $flowhookpathenv -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$baseDirectory\$org-flowhook.json"
		
# 		# Load the JSON data from the file
# 		$flowhookdetail = Get-Content "$baseDirectory\$org-flowhook.json" | ConvertFrom-Json
		
# 		# Add debugging output to check the contents of $flowhookdetail
# 		Write-Host "JSON Data:$flowhookdetail"
		
		
# 		# Iterate through each value in the response
# 		foreach ($value in $flowhookdetail) {
# 		    Write-Host "Processing value: $value"
# 		    $flowhookpathdetail = $baseURL + $org + "/environments/" + $env + "/flowhooks/" + $value
# 		    Invoke-RestMethod -Uri $flowhookpathdetail -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$baseDirectory\$org-flowhook-$value.json"
# 		}
# 		cd ..

#         # --------------------------------Environment - Proxies--------------------------------------
#         if(!(test-path -PathType container proxies)){
#             mkdir "proxies"
#             cd proxies
#         }
#         else {
#             cd proxies
#         }

#         $proxypathenv = $baseURL+$org+"/environments/"+$($env)+"/deployments"
#         Invoke-RestMethod -Uri $proxypathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxies.json"
        
#         $proxypathenv1 = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/deployments"
#         Invoke-RestMethod -Uri $proxypathenv -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$env-proxies.json"

#         # Load the JSON data from the file
#         $jsonData = Get-Content -Path "$env-proxies.json" | ConvertFrom-Json

#         # Extract the apiproxy and revision values
#         $deployments = $jsonData.deployments
#         foreach ($deployment in $deployments) {
#             $apiproxy = $deployment.apiProxy
#             $revision = $deployment.revision
#             if(!(test-path -PathType container $($proxy.name))){
#                 mkdir -p "$apiproxy"
#                 cd $apiproxy
#             }
#             else {
#                 cd $apiproxy
#             }

#             if(!(test-path -PathType container $revision)){
#                 mkdir -p "$revision"
#                 cd $revision
#             }
#             else {
#                 cd $revision
#             }

#             # Output the extracted values
#             $path2 = $baseURL+$org+"/environments/"+$($env)+"/apis/"+$apiproxy+"/revisions/"+$revision+"/deployments"
#             Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxy-$($proxy.name).json"
#             cd ..
#             cd ..
#         }
        
#         cd ..

#         # # --------------------------------Environment - SharedFlows--------------------------------------
        
# 		if(!(test-path -PathType container shared-flows)){
# 		mkdir "shared-flows"
# 		cd shared-flows
# 	    }
# 	    else {
# 	        cd shared-flows
# 	    }
	
# 	    $sharedflowpath = $baseURL+$org+"/sharedflows"
# 	    $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
	
# 	    foreach ($sharedflow in $($sharedflows.sharedflows)) {
# 	        $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
# 	        $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
	
# 	        if(!(test-path -PathType container $($sharedflow.name))){
# 	            mkdir -p "$($sharedflow.name)"
# 	            cd $($sharedflow.name)
# 	        }
# 	        else {
# 	            cd $($sharedflow.name)
# 	        }
	
# 	        # Get the latest deployed revision number
# 	        $latestFlowRevision = $($FlowRevs) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
# 		 	if(!(test-path -PathType container $($latestFlowRevision))){
# 	            mkdir -p "$($latestFlowRevision)"
# 	            cd $($latestFlowRevision)
# 	        }
# 	        else {
# 	            cd $($latestFlowRevision)
# 	        }
# 	        # $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($latestFlowRevision)+"?format=bundle"
# 		 	$flowDetailRev2 = $baseURL+$org+"/environments/"+$($env)+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($latestFlowRevision)+"/deployments"
# 			# https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/sharedflows/SF-jwt-token/revisions/3/deployments
# 	        # $SharedFlowZipFile = $org+"-sharedflow-"+$($sharedflow.name)+"-rev"+$($latestFlowRevision)+".zip"
# 		 	# Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$($sharedflow.name).json"
	        
# 	        # $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $SharedFlowZipFile
	
# 	        # Expand-Archive -Path $SharedFlowZipFile -Force
# 	        # Remove-Item -Path $SharedFlowZipFile -Force
# 	        cd ..
# 		 	cd ..
# 	    }
# 	    cd ..

 
 
 
 
 
#  		# if(!(test-path -PathType container env-sharedflows)){
#         #     mkdir "env-sharedflows"
#         #     cd env-sharedflows
#         # }
#         # else {
#         #     cd env-sharedflows
#         # }

#         # $sharedflowpathenv = $baseURL+$org+"/environments/"+$($env)+"/sharedflows"
#         # $envsharedflow = Invoke-RestMethod -Uri $sharedflowpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-sharedflow.json"
        
#         # cd ..

#         # --------------------------------Environment - Resource Files--------------------------------------
#         # if(!(test-path -PathType container env-resourcefiles)){
#         #     mkdir "env-resourcefiles"
#         #     cd env-resourcefiles
#         # }
#         # else {
#         #     cd env-resourcefiles
#         # }

#         # $resourcefilespathenv = $baseURL+$org+"/environments/"+$($env)+"/resourcefiles"
#         # $envresourcefiles = Invoke-RestMethod -Uri $envresourcefiles -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-resourcefiles.json"
        
#         cd ..
#     }
#     cd ..

# # -----------------------------Environments Closing-------------------------------------
# cd ..
# cd ..

























# # # write-output Apigee Artifacts
# # $token = $env:TOKEN
# # $org = $env:ORG
# # $baseURL = "https://apigee.googleapis.com/v1/organizations/"
# # $headers = @{Authorization = "Bearer $token"}

# # # --------------------Apigee All Artifacts-------------------------------------------

# # # ----------------------create apigee organisation level artifacts folder------------
# # # if(!(test-path -PathType container apigee)){
# # #       mkdir "apigee"
# # #       cd apigee
# # #       Write-Host "inside if"
# # # }
# # # else {
# # #       cd apigee
# # #       Write-Host "else"
# # # }

# # # create apigee artifacts non prod folder
# # if(!(test-path -PathType container FL-artifacts-nonprod)){
# #       mkdir "FL-artifacts-nonprod"
# #       cd FL-artifacts-nonprod
# #       Write-Host "inside 2nd if"
# # }
# # else {
# #       cd FL-artifacts-nonprod
# #       Write-Host "2nd else"
# # }

# # # --------------------------------Proxies - All Revisions-------------------------------------------
# #     if(!(test-path -PathType container proxies)){
# #         mkdir "proxies"
# #         cd proxies
# #     }
# #     else {
# #         cd proxies
# #     }

# #     $path = $baseURL+$org+"/apis"
# #     Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "proxies.json"
# #     $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     foreach ($proxy in $($proxies.proxies)) {
# #         $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
# #         $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #         foreach ($proxyRevs in $($proxyRevs)) {
# #             if(!(test-path -PathType container $($proxy.name))){
# #             mkdir -p "$($proxy.name)"
# #             cd $($proxy.name)
# #             }
# #             else {
# #                 cd $($proxy.name)
# #             }
# #             $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($proxyRevs)+"?format=bundle"
# #             $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($proxyRevs)+".zip"
            
# #             $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

# #             Expand-Archive -Path $zipFile -Force
# #             # Remove-Item -Path $zipFile -Force
# #             cd ..
# #         }
# #     }
# #     cd..

# # # --------------------------------Proxies- Latest Revision------------------------------------------
# #     # if(!(test-path -PathType container proxies)){
# #     #     mkdir "proxies"
# #     #     cd proxies
# #     # }
# #     # else {
# #     #     cd proxies
# #     # }

# #     # $path = $baseURL+$org+"/apis"
# #     # $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     # foreach ($proxy in $($proxies.proxies)) {
# #     #     $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
# #     #     $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     #     # Get the latest deployed revision number
# #     #     $latestRevision = $proxyRevs | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

# #     #     if(!(test-path -PathType container $($proxy.name))){
# #     #         mkdir -p "$($proxy.name)"
# #     #         cd $($proxy.name)
# #     #     }
# #     #     else {
# #     #         cd $($proxy.name)
# #     #     }

# #     #     $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($latestRevision)+"?format=bundle"
# #     #     $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($latestRevision)+".zip"
        
# #     #     $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

# #     #     Expand-Archive -Path $zipFile -Force
# #     #     Remove-Item -Path $zipFile -Force
# #     #     cd..
# #     # }
# #     # cd..

# # # --------------------------------SharedFlows - All Revs---------------------------------------------
# #     if(!(test-path -PathType container SharedFlows)){
# #         mkdir "SharedFlows"
# #         cd SharedFlows
# #     }
# #     else {
# #         cd SharedFlows
# #     }

# #     $sharedflowpath = $baseURL+$org+"/sharedflows"
# #     Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "sharedflows.json"
# #     $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     foreach ($sharedflow in $($sharedflows.sharedflows)) {
# #         $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
# #         $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #         foreach ($FlowRevs in $($FlowRevs)) {
# #             if(!(test-path -PathType container $($sharedflow.name))){
# #             mkdir -p "$($sharedflow.name)"
# #             cd $($sharedflow.name)
# #             }
# #             else {
# #                 cd $($sharedflow.name)
# #             }
# #             $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($FlowRevs)+"?format=bundle"
# #             $sharedflowzipFile = $org+"-sharedflows-"+$($sharedflow.name)+"-rev"+$($FlowRevs)+".zip"

# #             $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $sharedflowzipFile

# #             Expand-Archive -Path $sharedflowzipFile -Force
# #             # Remove-Item -Path $sharedflowzipFile -Force
# #             cd ..
# #         }
# #     }
# #     cd ..

# # # ------------------------------------SharedFlows - Latest Revision---------------------------------------

# #     # if(!(test-path -PathType container SharedFlows)){
# #     #     mkdir "SharedFlows"
# #     #     cd SharedFlows
# #     # }
# #     # else {
# #     #     cd SharedFlows
# #     # }

# #     # $sharedflowpath = $baseURL+$org+"/sharedflows"
# #     # $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     # foreach ($sharedflow in $($sharedflows.sharedflows)) {
# #     #     $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
# #     #     $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     #     if(!(test-path -PathType container $($sharedflow.name))){
# #     #         mkdir -p "$($sharedflow.name)"
# #     #         cd $($sharedflow.name)
# #     #     }
# #     #     else {
# #     #         cd $($sharedflow.name)
# #     #     }

# #     #     # Get the latest deployed revision number
# #     #     $latestFlowRevision = $($FlowRevs) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
# #     #     $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($latestFlowRevision)+"?format=bundle"
# #     #     $SharedFlowZipFile = $org+"-sharedflow-"+$($sharedflow.name)+"-rev"+$($latestFlowRevision)+".zip"
        
# #     #     $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $SharedFlowZipFile

# #     #     Expand-Archive -Path $SharedFlowZipFile -Force
# #     #     Remove-Item -Path $SharedFlowZipFile -Force
# #     #     cd ..
# #     # }
# #     # cd ..


# # # ----------------------------------Org KVMs------------------------------------------------------------
# #     if(!(test-path -PathType container org-kvms)){
# #         mkdir "org-kvms"
# #         cd org-kvms
# #     }
# #     else {
# #         cd org-kvms
# #     }

# #     $kvmpath = $baseURL+$org+"/keyvaluemaps"
# #     Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-kvms.json"

# #     $orgkvms = Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     foreach ($orgkvm in $($orgkvms)) {
# #         if(!(test-path -PathType container $orgkvm)){
# #         mkdir -p "$orgkvm"
# #         cd $orgkvm
# #         }
# #         else {
# #             cd $orgkvm
# #         }
# #         $kvmpath2 = $kvmpath+"/"+$($orgkvm)+"/entries"
# #         $kvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-($($orgkvm)).json"
# #         cd ..
# #     }
# #     cd ..


# # # ----------------------------API Products------------------------------------------
# #     if(!(test-path -PathType container apiproducts))
# #     {
# #         mkdir "apiproducts"
# #         cd apiproducts
# #     }
# #     else {
# #         cd apiproducts
# #     }

# #     $productpath = $baseURL+$org+"/apiproducts"
# #     Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"
# #     $apiproduct = Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
# #     foreach ($apiproduct in $($apiproducts)) {
# #         if(!(test-path -PathType container $($envapiproduct))){
# #             mkdir "$($envapiproduct)"
# #             cd $($envapiproduct)
# #         }
# #         else {
# #             cd $($envapiproduct)
# #         }
# #         $apiproductdetail = $baseURL+$org+"/apiproducts/"+$apiproduct
# #         Invoke-RestMethod -Uri $apiproductdetail -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-$apiproduct.json"
# #         cd ..
# #     }
# #     cd ..

# #     Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"

# # # -----------------------------Developers------------------------------------------
# #     if(!(test-path -PathType container developers))
# #     {
# #         mkdir "developers"
# #         cd developers
# #     }
# #     else {
# #         cd developers
# #     }

# #     $developerpath = $baseURL+$org+"/developers"
# #     Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"
# #     $developer = Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #     foreach ($developer in $($developers)) {
# #         if(!(test-path -PathType container $($envdeveloper))){
# #             mkdir "$($envdeveloper)"
# #             cd $($envdeveloper)
# #         }
# #         else {
# #             cd $($envdeveloper)
# #         }
# #         $developerdetail = $baseURL+$org+"/developers/"+$developer
# #         Invoke-RestMethod -Uri $developerdetail -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-$apiproduct.json"
# #         cd ..
# #     }
# #     cd ..

# #     Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"

# # # ------------------------------Apps-------------------------------------------------
# #     if(!(test-path -PathType container apps))
# #     {
# #         mkdir "apps"
# #         cd apps
# #     }
# #     else {
# #         cd apps
# #     }

# #     $Apps = $baseURL+$org+"/apps?expand=true"
# #     $Appdetails = Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"
# #     $baseURL = "https://apigee.googleapis.com/v1/organizations/"
# #     $org = "esi-apigee-x-394004"
      
# #     # API endpoint to get the list of apps
# #     $AppsEndpoint = "${baseURL}${org}/apps?expand=true"
      
# #   # Make the API call to get the list of apps
# #   try {
# #      $AppList = Invoke-RestMethod -Uri $AppsEndpoint -Method Get -Headers $headers -ContentType "application/json" -TimeoutSec 60
  
# #      # Loop through the list of apps
# #      foreach ($app in $AppList.app) {  # Access the 'app' property
# # 	 if ($app.name) {
# # 	     Write-Host "Entered into FOREACH: $($app.name)"
  
# # 	     if(!(test-path -PathType container $($app.name)))
# # 	     {
# # 		 mkdir "$($app.name)"
# # 		 cd $($app.name)
# # 		}
# # 		else {
# # 		 cd $($app.name)
# # 		}
# # 		# Define a function to encrypt data
# # 		function Encrypt-Data {
# # 		    param (
# # 			[string]$plaintext,
# # 			[string]$keyHex
# # 		    )
		
# # 		    # Create a new AES object with the specified key and AES mode
# # 		    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
# # 		    $AES.KeySize = 256  # Set the key size to 256 bits for AES-256
# # 		    $AES.Key = [System.Text.Encoding]::UTF8.GetBytes($keyHex.PadRight(32))
# # 		    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
		
# # 		    # Convert plaintext to bytes (UTF-8 encoding)
# # 		    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
		
# # 		    # Generate a random initialization vector (IV)
# # 		    $AES.GenerateIV()
# # 		    $IVBase64 = [System.Convert]::ToBase64String($AES.IV)
		
# # 		    # Encrypt the data
# # 		    $encryptor = $AES.CreateEncryptor()
# # 		    $encryptedBytes = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)
# # 		    $encryptedBase64 = [System.Convert]::ToBase64String($encryptedBytes)
		
# # 		    # Return the encrypted data and IV
# # 		    return @{
# # 			"EncryptedValue" = $encryptedBase64
# # 			"IV" = $IVBase64
# # 		    }
# # 		}
		
# # 		try {
# # 		    $token = $env:TOKEN
# # 		    $headers = @{Authorization = "Bearer $token"}
		
# # 		    # Make the API call to get the data
# # 		    $appdetailget = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/developers/check.developer@gmail.com/apps/test-app" -Method 'GET' -Headers $headers
		
# # 		    # Specify the fields you want to encrypt
# # 		    $appfileds = $env:appfieds -split ","
		    
# # 		    # Encryption key
# # 		    $keyHex = $env:key  # Replace with your encryption key
		
# # 		    # Loop through the specified fields and encrypt their values
# # 		    foreach ($field in $appfileds) {
		
# # 			# Check if the credentials array exists and has at least one item
# # 			if ($appdetailget.credentials.Count -gt 0) {
		
# # 			    # Access the value of the current field
# # 			    $plaintext = $appdetailget.credentials[0].$field
		
# # 			    # Encrypt the data using the Encrypt-Data function
# # 			    $encryptedData = Encrypt-Data -plaintext $plaintext -keyHex $keyHex
		
# # 			    # Store the encrypted value back in the JSON data
# # 			    $appdetailget.credentials[0].$field = $encryptedData
# # 			}
# # 		    }
		
# # 		    # Convert the modified JSON data back to JSON format with a higher depth value
# # 		    $encryptedJsonData = $appdetailget | ConvertTo-Json -Depth 10
		
# # 		    # Display the modified JSON data
# # 		    Write-Host $encryptedJsonData
# # 		}
# # 		catch {
# # 		    Write-Host "An error occurred: $_"
# # 		}

# # 		cd ..
# # 	 }
# # 	 cd ..
# #      }
# #   }
# #   catch {
# #      Write-Host "Error: $($_.Exception.Message)"
# #   }

# #     Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"

# # # ------------------------------master-deployments-proxies----------------------------
# #     $masterDeploymentPath = $baseURL+$org+"/deployments"
# #     $masterDeployments = Invoke-RestMethod -Uri $masterDeploymentPath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-master-proxy-deployments.json"

# # # -----------------------------Environments Start-------------------------------------
# #     if(!(test-path -PathType container environments)){
# #         mkdir "environments"
# #         cd environments
# #     }
# #     else {
# #         cd environments
# #     }

# #     $envpath = $baseURL+$org+"/environments"
# #     Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-env.json"
# #     $environments = Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
    
# #     #iterate for each environment
# #     foreach ($env in $($environments)) {

# #         if(!(test-path -PathType container $($env))){
# #             mkdir "$($env)"
# #             cd $($env)
# #         }
# #         else {
# #             cd $($env)
# #         }

# #         # -----------------------------Environments - KVMs -------------------------------------
# #         if(!(test-path -PathType container env-kvms)){
# #             mkdir "env-kvms"
# #             cd env-kvms
# #         }
# #         else {
# #             cd env-kvms
# #         }

# #         $kvmpathenv = $baseURL+$org+"/environments/"+$($env)+"/keyvaluemaps"
# #         Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-kvms.json"
# #         $envkvms = Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #         foreach ($envkvm in $($envkvms)) {
# #             if(!(test-path -PathType container $($envkvm))){
# #                 mkdir "$($envkvm)"
# #                 cd $($envkvm)
# #             }
# #             else {
# #                 cd $($envkvm)
# #             }

# #             # $kvmpathenv2 = $kvmpathenv+"/"+$($envkvm)+"/entries"
# #             # $envkvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($($envkvm)).json"
# #             # cd ..
# #             # $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
# #             # $headers.Add("Authorization", "Bearer ya29.a0AfB_byCYq525bBvRLE3tibD4O1dOvozhbOrpAbNpIqXtsfkBvD-x8VFNszZKC5vj7mm0h-RypwdqL5H7_iukKjIn4BUxhYwUbPaTEdaZLFlFpu7hs_PwshYQuP1QisNg3bz2lbFTftNHMlS6fOh4oXEYVMoU9-s7htHCCvWqgeYaCgYKAcgSARESFQHsvYlsRs-EXW1LLkfCbK-OgQ9KYg0178")
            
# #             $kvmpthtestpath = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/keyvaluemaps/"+$envkvm+"/entries"

# #             $response = Invoke-RestMethod $kvmpthtestpath -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($($envkvm)).json"
# #             $response | ConvertTo-Json
# #             cd ..
# #         }
# #         cd ..

# #         # -------------------------------Environments - Targetservers-----------------------------
# #         if(!(test-path -PathType container env-Targetservers)){
# #             mkdir "env-Targetservers"
# #             cd env-Targetservers
# #         }
# #         else {
# #             cd env-Targetservers
# #         }

# #         $targetserverpathenv = $baseURL+$org+"/environments/"+$($env)+"/targetservers"
# #         Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-targetservers.json"
# #         $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

# #         Write-Host $envtargetserver

# #         foreach ($value in $($envtargetserver)) {
# #             if(!(test-path -PathType container $($value))){
# #                 mkdir "$($value)"
# #                 cd $($value)
# #             }
# #             else {
# #                 cd $($value)
# #             }

# #             $targetserverpathenv2 = $targetserverpathenv+"/"+$value
# #             $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($value).json"
# #             cd ..
# #         }
# #         cd ..

# #         # --------------------------------Environment - Proxies--------------------------------------
# #         if(!(test-path -PathType container proxies)){
# #             mkdir "proxies"
# #             cd proxies
# #         }
# #         else {
# #             cd proxies
# #         }

# #         $proxypathenv = $baseURL+$org+"/environments/"+$($env)+"/deployments"
# #         Invoke-RestMethod -Uri $proxypathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxies.json"
        
# #         $proxypathenv1 = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/deployments"
# #         Invoke-RestMethod -Uri $proxypathenv -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$env-proxies.json"

# #         # Load the JSON data from the file
# #         $jsonData = Get-Content -Path "$env-proxies.json" | ConvertFrom-Json

# #         # Extract the apiproxy and revision values
# #         $deployments = $jsonData.deployments
# #         foreach ($deployment in $deployments) {
# #             $apiproxy = $deployment.apiProxy
# #             $revision = $deployment.revision
# #             if(!(test-path -PathType container $($proxy.name))){
# #                 mkdir -p "$apiproxy"
# #                 cd $apiproxy
# #             }
# #             else {
# #                 cd $apiproxy
# #             }

# #             if(!(test-path -PathType container $revision)){
# #                 mkdir -p "$revision"
# #                 cd $revision
# #             }
# #             else {
# #                 cd $revision
# #             }

# #             # Output the extracted values
# #             $path2 = $baseURL+$org+"/environments/"+$($env)+"/apis/"+$apiproxy+"/revisions/"+$revision+"/deployments"
# #             Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxy-$($proxy.name).json"
# #             cd ..
# #             cd ..
# #         }
        
# #         cd ..

# #         # # --------------------------------Environment - SharedFlows--------------------------------------
# #         # if(!(test-path -PathType container env-sharedflows)){
# #         #     mkdir "env-sharedflows"
# #         #     cd env-sharedflows
# #         # }
# #         # else {
# #         #     cd env-sharedflows
# #         # }

# #         # $sharedflowpathenv = $baseURL+$org+"/environments/"+$($env)+"/sharedflows"
# #         # $envsharedflow = Invoke-RestMethod -Uri $sharedflowpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-sharedflow.json"
        
# #         # cd ..

# #         # --------------------------------Environment - Resource Files--------------------------------------
# #         # if(!(test-path -PathType container env-resourcefiles)){
# #         #     mkdir "env-resourcefiles"
# #         #     cd env-resourcefiles
# #         # }
# #         # else {
# #         #     cd env-resourcefiles
# #         # }

# #         # $resourcefilespathenv = $baseURL+$org+"/environments/"+$($env)+"/resourcefiles"
# #         # $envresourcefiles = Invoke-RestMethod -Uri $envresourcefiles -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-resourcefiles.json"
        
# #         cd ..
# #     }
# #     cd ..

# # # -----------------------------Environments Closing-------------------------------------
# # cd ..
