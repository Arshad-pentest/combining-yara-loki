rule Suspicious_Keywords
{
    strings:
        $x = "powershell"
        $y = "cmd.exe"
        $z = "base64"

    condition:
        any of them
}
