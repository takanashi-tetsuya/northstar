$files = @('src\policy.rs', 'src\subscription.rs', 'src\summary.rs')
$target = '#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]'
foreach ($f in $files) {
    $content = [System.IO.File]::ReadAllText((Resolve-Path $f).Path)
    $content = $content.Replace("$target`r`n", "")
    $content = $content.Replace("$target`n", "")
    [System.IO.File]::WriteAllText((Resolve-Path $f).Path, $content)
}
