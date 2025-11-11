include "Utility/General.tcl"

proc Header {} {
    section "header" {
        hex 32 "hmac"
        uint16 "version"
        set plen [uint24 "payload len"]
        uint8_bits 0 "terminal block"
    }
    return $plen
}

proc AlgAndIV {} {
    set alg [uint16 "alg #"]
    switch $alg {
        1 {
            set ivLen 12
            set algName 'AES-GCM'
        }
        2 {
            set ivLen 24
            set algName 'X20-PLY'
        }
        3 {
            set ivLen 32
            set algName 'AEGIS-256'
        }
    }
    entry "alg name" $algName 2 [expr [pos]-2]
    hex $ivLen "init vector"

    return "$ivLen $algName"
}


proc BlockN {number} {
    section "block${number}" {
        set plen [Header]
        section "payload" {
            section "additional data" {
                lassign [AlgAndIV] ivLen algName
            }
            section "encrypted data" {
                bytes [expr $plen - 2 - $ivLen] "data encrypted"
            }
        }
    }
}

section "block0" {
    set plen [Header]
    section "payload" {
        section "additional data" {
            lassign [AlgAndIV] ivLen algName
            hex 16 "salt"
            uint32 "iterations"
            uint8_bits 7,6,5,4 "loop end"
            move -1
            uint8_bits 3,2,1,0 "loop"
            set hintLen [uint8 "hint len"]
            if {$hintLen > 0} {
                bytes $hintLen "hint encrypted"
            }
        }
        bytes [expr $plen - 2 - $ivLen - 16 - 4 - 1 - 1 - $hintLen] "encrypted data"
    }
}

set N 1
while {![end] && $N <= 350} {
    puts [BlockN $N]
    incr N 1
}
