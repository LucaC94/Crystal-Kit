x64:
    pack $NOP "b" 0x90

    ised insert "push r10" $NOP +after
    ised insert "call rax" $NOP +before
