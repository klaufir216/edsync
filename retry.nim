import os

proc retryVoid*[T](f: proc(): void, max_tries: int, sleep_time_sec: int) =
    var n_tries: int = 0
    while true:
        try:
            f()
            return
        except T as e:
            n_tries += 1
            var verb = "retrying"
            if n_tries >= max_tries:
                verb = "giving up"
            stderr.writeLine("error: " & e.msg & ". " & verb & " (" & $n_tries & "/" & $max_tries & ")")
            if n_tries >= max_tries:
                return
            
            os.sleep(sleep_time_sec * 1000)
            
proc retry*[T,V](f: proc(): V, max_tries: int, sleep_time_sec: int):V =
    var n_tries: int = 0
    while true:
        try:
            return f()
        except T as e:
            n_tries += 1
            var verb = "retrying"
            if n_tries >= max_tries:
                verb = "giving up"
            stderr.writeLine("error: " & e.msg & ". " & verb & " (" & $n_tries & "/" & $max_tries & ")")
            if n_tries >= max_tries:
                return result

            
            os.sleep(sleep_time_sec * 1000)


# usage:
#retry[ValueError](proc() =
#    discard parseInt("a"),
#    5, 5)