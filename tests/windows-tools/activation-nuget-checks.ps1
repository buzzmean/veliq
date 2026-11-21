# Uses an isolated NuGet.Config and the real SDK; no network/restore/user config writes.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $root 'tools/windows/activation-nuget.ps1')
function Check($Value,[string]$Message){if(!$Value){throw $Message}}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('veliq-nuget-fixture-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
try{
 $config=Join-Path $fixture 'NuGet.Config'
 [IO.File]::WriteAllText($config,'<configuration><packageSources><clear/></packageSources></configuration>')
 Initialize-ActivationNuGetSource -ConfigFile $config
 [xml]$emptyResult=[IO.File]::ReadAllText($config)
 Check (@($emptyResult.configuration.packageSources.add).Count -eq 1) 'Clean PC without any sources was not configured'
 [IO.File]::WriteAllText($config,'<configuration><packageSources><clear/><add key="existing" value="https://example.invalid/v3/index.json" /></packageSources></configuration>')
 Initialize-ActivationNuGetSource -ConfigFile $config
 [xml]$xml=[IO.File]::ReadAllText($config)
 $entries=@($xml.configuration.packageSources.add)
 Check ($entries.Count -eq 2) 'Missing feed was not added beside existing source'
 Check (@($entries|Where-Object {$_.key -eq 'existing' -and $_.value -eq 'https://example.invalid/v3/index.json'}).Count -eq 1) 'Existing feed changed'
 $before=[IO.File]::ReadAllText($config)
 Initialize-ActivationNuGetSource -ConfigFile $config
 Check ([IO.File]::ReadAllText($config) -ceq $before) 'Repeated preflight changed configuration'
 [IO.File]::WriteAllText($config,$before.Replace('key="nuget.org"','key="alternate-name"'))
 $before=[IO.File]::ReadAllText($config)
 Initialize-ActivationNuGetSource -ConfigFile $config
 Check ([IO.File]::ReadAllText($config) -ceq $before) 'Feed detection incorrectly depends on name'
 [IO.File]::WriteAllText($config,'<configuration><packageSources><clear/><add key="nuget.org" value="https://example.invalid/v3/index.json" /></packageSources></configuration>')
 $before=[IO.File]::ReadAllText($config);$rejected=$false
 try{Initialize-ActivationNuGetSource -ConfigFile $config}catch{$rejected=$_.Exception.Message.StartsWith('NUGET_ORG_SOURCE_ADD_FAILED')}
 Check $rejected 'Conflicting source name should fail explicitly'
 Check ([IO.File]::ReadAllText($config) -ceq $before) 'Conflicting feed was overwritten'
 [IO.File]::WriteAllText($config,'<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources><disabledPackageSources><add key="nuget.org" value="true" /></disabledPackageSources></configuration>')
 $before=[IO.File]::ReadAllText($config);$rejected=$false
 try{Initialize-ActivationNuGetSource -ConfigFile $config}catch{$rejected=$_.Exception.Message.StartsWith('NUGET_ORG_SOURCE_DISABLED')}
 Check $rejected 'Disabled feed should be diagnosed explicitly'
 Check ([IO.File]::ReadAllText($config) -ceq $before) 'Explicitly disabled feed changed'
 Write-Host 'PASS NuGet missing/existing/alternate-name/repeated/conflict/disabled; user sources untouched'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
