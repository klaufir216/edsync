import std/strformat

proc humanBytes*(size: int): string = 
    var units = @["","K","M","G","T","P"]
    var fsize = float(size)
    var i = 0
    while i <= 5 and fsize > 1024.0:
        fsize /= 1024.0
        i += 1

    return fmt"{fsize:.2f} {units[i]}B"