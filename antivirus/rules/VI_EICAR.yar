rule EICAR_Virus {
    meta:
        description = "This is a rule to detect the EICAR test file"
        author = "Community"
        reference = "http://www.eicar.org/86-0-Intended-use.html"
        date = "2023-01-01"
        hash = "44d88612fea8a8f36de82e1278abb02f"
    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar_pattern = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D }
    condition:
        any of them
}

rule EICAR_COM_Virus {
    meta:
        description = "Detects EICAR malware test file"
        author = "Community"
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D }
    condition:
        $eicar at 0
}