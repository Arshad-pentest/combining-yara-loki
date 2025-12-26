rule Test_Malware_String
{
    strings:
        $a = "malware"
        $b = "virus"

    condition:
        any of them
}
