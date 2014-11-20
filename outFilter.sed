#!/bin/sed -f
/[ ][ ][ ]ID: /d
/Function: /d
/Result: /d
/Comment: /d
/Duration: /d
/Started: /d
/Name: /d
/Changes: /d
/pid:$/{N
s/\n//
}
/retcode:$/{N
s/\n//
}
/stderr:$/{N
s/\n//
}
/stdout:$/d
/pid:/d
/retcode:/d
/stderr:/d
/^[ ][ ]*---/d
