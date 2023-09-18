# write-output Apigee Artifacts
$token = $env:TOKEN
$org = $env:ORG
$baseURL = "https://apigee.googleapis.com/v1/organizations/"
$headers = @{Authorization = "Bearer $token"}

# --------------------Apigee All Artifacts-------------------------------------------

# ----------------------create apigee organisation level artifacts folder------------
# if(!(test-path -PathType container apigee)){
#       mkdir "apigee"
#       cd apigee
#       Write-Host "inside if"
# }
# else {
#       cd apigee
#       Write-Host "else"
# }

# create apigee artifacts non prod folder
if(!(test-path -PathType container FL-artifacts-nonprod)){
      mkdir "FL-artifacts-nonprod"
      cd FL-artifacts-nonprod
      Write-Host "inside 2nd if"
}
else {
      cd FL-artifacts-nonprod
      Write-Host "2nd else"
}

# --------------------------------Proxies - All Revisions-------------------------------------------
    if(!(test-path -PathType container proxies)){
        mkdir "proxies"
        cd proxies
    }
    else {
        cd proxies
    }

    $path = $baseURL+$org+"/apis"
    Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "proxies.json"
    $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    foreach ($proxy in $($proxies.proxies)) {
        $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
        $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

        foreach ($proxyRevs in $($proxyRevs)) {
            if(!(test-path -PathType container $($proxy.name))){
            mkdir -p "$($proxy.name)"
            cd $($proxy.name)
            }
            else {
                cd $($proxy.name)
            }
            $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($proxyRevs)+"?format=bundle"
            $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($proxyRevs)+".zip"
            
            $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

            Expand-Archive -Path $zipFile -Force
            # Remove-Item -Path $zipFile -Force
            cd ..
        }
    }
    cd..

# --------------------------------Proxies- Latest Revision------------------------------------------
    # if(!(test-path -PathType container proxies)){
    #     mkdir "proxies"
    #     cd proxies
    # }
    # else {
    #     cd proxies
    # }

    # $path = $baseURL+$org+"/apis"
    # $proxies = Invoke-RestMethod -Uri "https://apigee.googleapis.com/v1/organizations/$org/apis" -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    # foreach ($proxy in $($proxies.proxies)) {
    #     $path1 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions"
    #     $proxyRevs = Invoke-RestMethod -Uri $path1 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    #     # Get the latest deployed revision number
    #     $latestRevision = $proxyRevs | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

    #     if(!(test-path -PathType container $($proxy.name))){
    #         mkdir -p "$($proxy.name)"
    #         cd $($proxy.name)
    #     }
    #     else {
    #         cd $($proxy.name)
    #     }

    #     $path2 = $baseURL+$org+"/apis/"+$($proxy.name)+"/revisions/"+$($latestRevision)+"?format=bundle"
    #     $zipFile = $org+"-proxy-"+$($proxy.name)+"-rev"+$($latestRevision)+".zip"
        
    #     $response = Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $zipFile

    #     Expand-Archive -Path $zipFile -Force
    #     Remove-Item -Path $zipFile -Force
    #     cd..
    # }
    # cd..

# --------------------------------SharedFlows - All Revs---------------------------------------------
    if(!(test-path -PathType container SharedFlows)){
        mkdir "SharedFlows"
        cd SharedFlows
    }
    else {
        cd SharedFlows
    }

    $sharedflowpath = $baseURL+$org+"/sharedflows"
    Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "sharedflows.json"
    $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    foreach ($sharedflow in $($sharedflows.sharedflows)) {
        $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
        $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

        foreach ($FlowRevs in $($FlowRevs)) {
            if(!(test-path -PathType container $($sharedflow.name))){
            mkdir -p "$($sharedflow.name)"
            cd $($sharedflow.name)
            }
            else {
                cd $($sharedflow.name)
            }
            $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($FlowRevs)+"?format=bundle"
            $sharedflowzipFile = $org+"-sharedflows-"+$($sharedflow.name)+"-rev"+$($FlowRevs)+".zip"

            $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $sharedflowzipFile

            Expand-Archive -Path $sharedflowzipFile -Force
            # Remove-Item -Path $sharedflowzipFile -Force
            cd ..
        }
    }
    cd ..

# ------------------------------------SharedFlows - Latest Revision---------------------------------------

    # if(!(test-path -PathType container SharedFlows)){
    #     mkdir "SharedFlows"
    #     cd SharedFlows
    # }
    # else {
    #     cd SharedFlows
    # }

    # $sharedflowpath = $baseURL+$org+"/sharedflows"
    # $sharedflows = Invoke-RestMethod -Uri $sharedflowpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    # foreach ($sharedflow in $($sharedflows.sharedflows)) {
    #     $flowDetailRev = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions"
    #     $FlowRevs = Invoke-RestMethod -Uri $flowDetailRev -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    #     if(!(test-path -PathType container $($sharedflow.name))){
    #         mkdir -p "$($sharedflow.name)"
    #         cd $($sharedflow.name)
    #     }
    #     else {
    #         cd $($sharedflow.name)
    #     }

    #     # Get the latest deployed revision number
    #     $latestFlowRevision = $($FlowRevs) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
    #     $flowDetailRev2 = $baseURL+$org+"/sharedflows/"+$($sharedflow.name)+"/revisions/"+$($latestFlowRevision)+"?format=bundle"
    #     $SharedFlowZipFile = $org+"-sharedflow-"+$($sharedflow.name)+"-rev"+$($latestFlowRevision)+".zip"
        
    #     $response = Invoke-RestMethod -Uri $flowDetailRev2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile $SharedFlowZipFile

    #     Expand-Archive -Path $SharedFlowZipFile -Force
    #     Remove-Item -Path $SharedFlowZipFile -Force
    #     cd ..
    # }
    # cd ..


# ----------------------------------Org KVMs------------------------------------------------------------
    if(!(test-path -PathType container org-kvms)){
        mkdir "org-kvms"
        cd org-kvms
    }
    else {
        cd org-kvms
    }

    $kvmpath = $baseURL+$org+"/keyvaluemaps"
    Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-kvms.json"

    $orgkvms = Invoke-RestMethod -Uri $kvmpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    foreach ($orgkvm in $($orgkvms)) {
        if(!(test-path -PathType container $orgkvm)){
        mkdir -p "$orgkvm"
        cd $orgkvm
        }
        else {
            cd $orgkvm
        }
        $kvmpath2 = $kvmpath+"/"+$($orgkvm)+"/entries"
        $kvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-($($orgkvm)).json"
        cd ..
    }
    cd ..


# ----------------------------API Products------------------------------------------
    if(!(test-path -PathType container apiproducts))
    {
        mkdir "apiproducts"
        cd apiproducts
    }
    else {
        cd apiproducts
    }

    $productpath = $baseURL+$org+"/apiproducts"
    Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"
    $apiproduct = Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
    foreach ($apiproduct in $($apiproducts)) {
        if(!(test-path -PathType container $($envapiproduct))){
            mkdir "$($envapiproduct)"
            cd $($envapiproduct)
        }
        else {
            cd $($envapiproduct)
        }
        $apiproductdetail = $baseURL+$org+"/apiproducts/"+$apiproduct
        Invoke-RestMethod -Uri $apiproductdetail -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-$apiproduct.json"
        cd ..
    }
    cd ..

    Invoke-RestMethod -Uri $productpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apiproducts.json"

# -----------------------------Developers------------------------------------------
    if(!(test-path -PathType container developers))
    {
        mkdir "developers"
        cd developers
    }
    else {
        cd developers
    }

    $developerpath = $baseURL+$org+"/developers"
    Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"
    $developer = Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

    foreach ($developer in $($developers)) {
        if(!(test-path -PathType container $($envdeveloper))){
            mkdir "$($envdeveloper)"
            cd $($envdeveloper)
        }
        else {
            cd $($envdeveloper)
        }
        $developerdetail = $baseURL+$org+"/developers/"+$developer
        Invoke-RestMethod -Uri $developerdetail -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-$apiproduct.json"
        cd ..
    }
    cd ..

    Invoke-RestMethod -Uri $developerpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-developers.json"

# ------------------------------Apps-------------------------------------------------
    if(!(test-path -PathType container apps))
    {
        mkdir "apps"
        cd apps
    }
    else {
        cd apps
    }

    $Apps = $baseURL+$org+"/apps?expand=true"
    $Appdetails = Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"
    $baseURL = "https://apigee.googleapis.com/v1/organizations/"
    $org = "esi-apigee-x-394004"
      
    # API endpoint to get the list of apps
    $AppsEndpoint = "${baseURL}${org}/apps?expand=true"
      
	  # Make the API call to get the list of apps
	  try {
	     $AppList = Invoke-RestMethod -Uri $AppsEndpoint -Method Get -Headers $headers -ContentType "application/json" -TimeoutSec 60
	  
	     # Loop through the list of apps
	     foreach ($app in $AppList.app) {  # Access the 'app' property
		 if ($app.name) {
		     Write-Host "Entered into FOREACH: $($app.name)"
	  
		     if(!(test-path -PathType container ($app.name)))
		     {
			 mkdir "($app.name)"
			 cd ($app.name)
			}
			else {
			 cd ($app.name)
			}
			cd ..
		 }
		 cd ..
	     }
	  }
	  catch {
	     Write-Host "Error: $($_.Exception.Message)"
	  }
    cd ..

    Invoke-RestMethod -Uri $Apps -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-apps.json"

# ------------------------------master-deployments-proxies----------------------------
    $masterDeploymentPath = $baseURL+$org+"/deployments"
    $masterDeployments = Invoke-RestMethod -Uri $masterDeploymentPath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$org-master-proxy-deployments.json"

# -----------------------------Environments Start-------------------------------------
    if(!(test-path -PathType container environments)){
        mkdir "environments"
        cd environments
    }
    else {
        cd environments
    }

    $envpath = $baseURL+$org+"/environments"
    Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60  -OutFile "$org-env.json"
    $environments = Invoke-RestMethod -Uri $envpath -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60
    
    #iterate for each environment
    foreach ($env in $($environments)) {

        if(!(test-path -PathType container $($env))){
            mkdir "$($env)"
            cd $($env)
        }
        else {
            cd $($env)
        }

        # -----------------------------Environments - KVMs -------------------------------------
        if(!(test-path -PathType container env-kvms)){
            mkdir "env-kvms"
            cd env-kvms
        }
        else {
            cd env-kvms
        }

        $kvmpathenv = $baseURL+$org+"/environments/"+$($env)+"/keyvaluemaps"
        Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-kvms.json"
        $envkvms = Invoke-RestMethod -Uri $kvmpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

        foreach ($envkvm in $($envkvms)) {
            if(!(test-path -PathType container $($envkvm))){
                mkdir "$($envkvm)"
                cd $($envkvm)
            }
            else {
                cd $($envkvm)
            }

            # $kvmpathenv2 = $kvmpathenv+"/"+$($envkvm)+"/entries"
            # $envkvm = Invoke-RestMethod -Uri $kvmpath2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($($envkvm)).json"
            # cd ..
            # $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            # $headers.Add("Authorization", "Bearer ya29.a0AfB_byCYq525bBvRLE3tibD4O1dOvozhbOrpAbNpIqXtsfkBvD-x8VFNszZKC5vj7mm0h-RypwdqL5H7_iukKjIn4BUxhYwUbPaTEdaZLFlFpu7hs_PwshYQuP1QisNg3bz2lbFTftNHMlS6fOh4oXEYVMoU9-s7htHCCvWqgeYaCgYKAcgSARESFQHsvYlsRs-EXW1LLkfCbK-OgQ9KYg0178")
            
            $kvmpthtestpath = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/keyvaluemaps/"+$envkvm+"/entries"

            $response = Invoke-RestMethod $kvmpthtestpath -Method 'GET' -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($($envkvm)).json"
            $response | ConvertTo-Json
            cd ..
        }
        cd ..

        # -------------------------------Environments - Targetservers-----------------------------
        if(!(test-path -PathType container env-Targetservers)){
            mkdir "env-Targetservers"
            cd env-Targetservers
        }
        else {
            cd env-Targetservers
        }

        $targetserverpathenv = $baseURL+$org+"/environments/"+$($env)+"/targetservers"
        Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-targetservers.json"
        $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60

        Write-Host $envtargetserver

        foreach ($value in $($envtargetserver)) {
            if(!(test-path -PathType container $($value))){
                mkdir "$($value)"
                cd $($value)
            }
            else {
                cd $($value)
            }

            $targetserverpathenv2 = $targetserverpathenv+"/"+$value
            $envtargetserver = Invoke-RestMethod -Uri $targetserverpathenv2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-($value).json"
            cd ..
        }
        cd ..

        # --------------------------------Environment - Proxies--------------------------------------
        if(!(test-path -PathType container proxies)){
            mkdir "proxies"
            cd proxies
        }
        else {
            cd proxies
        }

        $proxypathenv = $baseURL+$org+"/environments/"+$($env)+"/deployments"
        Invoke-RestMethod -Uri $proxypathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxies.json"
        
        $proxypathenv1 = "https://apigee.googleapis.com/v1/organizations/esi-apigee-x-394004/environments/eval/deployments"
        Invoke-RestMethod -Uri $proxypathenv -Method Get -Headers $headers -ContentType "application/json" -ErrorAction Stop -TimeoutSec 60 -OutFile "$env-proxies.json"

        # Load the JSON data from the file
        $jsonData = Get-Content -Path "$env-proxies.json" | ConvertFrom-Json

        # Extract the apiproxy and revision values
        $deployments = $jsonData.deployments
        foreach ($deployment in $deployments) {
            $apiproxy = $deployment.apiProxy
            $revision = $deployment.revision
            if(!(test-path -PathType container $($proxy.name))){
                mkdir -p "$apiproxy"
                cd $apiproxy
            }
            else {
                cd $apiproxy
            }

            if(!(test-path -PathType container $revision)){
                mkdir -p "$revision"
                cd $revision
            }
            else {
                cd $revision
            }

            # Output the extracted values
            $path2 = $baseURL+$org+"/environments/"+$($env)+"/apis/"+$apiproxy+"/revisions/"+$revision+"/deployments"
            Invoke-RestMethod -Uri $path2 -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-proxy-$($proxy.name).json"
            cd ..
            cd ..
        }
        
        cd ..

        # # --------------------------------Environment - SharedFlows--------------------------------------
        # if(!(test-path -PathType container env-sharedflows)){
        #     mkdir "env-sharedflows"
        #     cd env-sharedflows
        # }
        # else {
        #     cd env-sharedflows
        # }

        # $sharedflowpathenv = $baseURL+$org+"/environments/"+$($env)+"/sharedflows"
        # $envsharedflow = Invoke-RestMethod -Uri $sharedflowpathenv -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-sharedflow.json"
        
        # cd ..

        # --------------------------------Environment - Resource Files--------------------------------------
        # if(!(test-path -PathType container env-resourcefiles)){
        #     mkdir "env-resourcefiles"
        #     cd env-resourcefiles
        # }
        # else {
        #     cd env-resourcefiles
        # }

        # $resourcefilespathenv = $baseURL+$org+"/environments/"+$($env)+"/resourcefiles"
        # $envresourcefiles = Invoke-RestMethod -Uri $envresourcefiles -Method:Get -Headers $headers -ContentType "application/json" -ErrorAction:Stop -TimeoutSec 60 -OutFile "$env-resourcefiles.json"
        
        cd ..
    }
    cd ..

# -----------------------------Environments Closing-------------------------------------
cd ..
