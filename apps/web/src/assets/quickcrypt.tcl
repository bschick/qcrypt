include "Utility/General.tcl"

# Unified Hex Fiend template for Quick Crypt versions 4, 5, and 6.
#
# All three versions share the same per-block layout:
#   header | additional data | encrypted data
# but they differ in where the 1-byte "flags" lives:
#   V4 — header trailer, byte unused (reserved, always 0)
#   V5 — header trailer, bit 0 = terminal-block flag
#   V6 — payload AD prefix, bit 0 = terminal-block flag
#
# So V4/V5 headers are 38 bytes (32 mac + 2 ver + 3 size + 1 flags);
# V6 headers are 37 bytes (32 mac + 2 ver + 3 size). The version field
# is repeated in every block's header, so the per-block branch below
# handles mixed expectations gracefully.

# Reads the per-block header. Returns [list payloadSize headerVersion].
proc Header {} {
    set headerVer 0
    set plen 0
    section "header" {
        hex 32 "hmac"
        set headerVer [uint16 "version"]
        set plen [uint24 "payload len"]
        if {$headerVer == 4} {
            uint8 "flags (reserved)"
        } elseif {$headerVer == 5} {
            uint8_bits 0 "terminal block"
        }
    }
    return [list $plen $headerVer]
}

# Reads alg id and IV. Returns [list ivBytes algName].
proc AlgAndIV {} {
    set alg [uint16 "alg #"]
    set ivLen 0
    set algName "unknown"
    switch $alg {
        1 { set ivLen 12; set algName "AES-GCM" }
        2 { set ivLen 24; set algName "X20-PLY" }
        3 { set ivLen 32; set algName "AEGIS-256" }
    }
    entry "alg name" $algName 2 [expr [pos]-2]
    hex $ivLen "init vector"
    return [list $ivLen $algName]
}

proc Block0 {} {
    section "block0" {
        lassign [Header] plen ver
        # V6+ moves the flags byte from header into payload AD.
        set flagsBytes [expr $ver >= 6 ? 1 : 0]
        section "payload" {
            section "additional data" {
                if {$ver >= 6} {
                    uint8_bits 0 "terminal block"
                }
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
            section "encrypted data" {
                bytes [expr $plen - $flagsBytes - 2 - $ivLen - 16 - 4 - 1 - 1 - $hintLen] "data encrypted"
            }
        }
    }
}

proc BlockN {number} {
    section "block${number}" {
        lassign [Header] plen ver
        set flagsBytes [expr $ver >= 6 ? 1 : 0]
        section "payload" {
            section "additional data" {
                if {$ver >= 6} {
                    uint8_bits 0 "terminal block"
                }
                lassign [AlgAndIV] ivLen algName
            }
            section "encrypted data" {
                bytes [expr $plen - $flagsBytes - 2 - $ivLen] "data encrypted"
            }
        }
    }
}

Block0
set N 1
while {![end] && $N <= 350} {
    BlockN $N
    incr N 1
}
