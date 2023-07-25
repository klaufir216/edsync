when defined(windows):
  proc getch(): char {.header: "<conio.h>", importc: "getch".}
  proc kbhit(): int {.header: "<conio.h>", importc: "kbhit".}
else:
  {.compile: "getch.c".}

  proc enable_raw_mode() {.importc.}
  proc disable_raw_mode() {.importc.}
  proc getch(): char {.importc.}
  proc kbhit(): int {.importc.}

  proc cleanExit*() =
    disable_raw_mode()

# returns -1 when no key pressed
proc getPressedKey*(): int =
  when not defined(windows):
    enable_raw_mode()

  var r = kbhit()
  if r != 0:
    result = int(getch()) 
  else:
    result = -1

  when not defined(windows):
    disable_raw_mode()
