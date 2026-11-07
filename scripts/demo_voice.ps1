param(
  [Parameter(Mandatory=$true)][string]$TextFile,
  [Parameter(Mandatory=$true)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Media.SpeechSynthesis.SpeechSynthesizer, Windows.Media.SpeechSynthesis, ContentType=WindowsRuntime] | Out-Null
$synth = New-Object Windows.Media.SpeechSynthesis.SpeechSynthesizer
$voice = [Windows.Media.SpeechSynthesis.SpeechSynthesizer]::AllVoices | Where-Object { $_.Language -eq 'zh-CN' -and $_.Gender.ToString() -eq 'Male' -and $_.DisplayName -like '*Kangkang*' } | Select-Object -First 1
if (-not $voice) { throw 'Microsoft Kangkang Chinese male voice is unavailable' }
$synth.Voice = $voice
$text = [System.IO.File]::ReadAllText($TextFile, [System.Text.Encoding]::UTF8)
$operation = $synth.SynthesizeTextToStreamAsync($text)
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1
if (-not $asTask) { throw 'Windows Runtime async bridge is unavailable' }
$task = $asTask.MakeGenericMethod([Windows.Media.SpeechSynthesis.SpeechSynthesisStream]).Invoke($null, @($operation))
$stream = $task.GetAwaiter().GetResult()
$inputStream = [System.IO.WindowsRuntimeStreamExtensions]::AsStreamForRead($stream)
$outputStream = [System.IO.File]::Create($OutputFile)
try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose(); $stream.Dispose(); $synth.Dispose() }
