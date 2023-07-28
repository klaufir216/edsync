when defined(unix):
  {.compile: "terminfo_linux.c".}
elif defined(windows):
  {.compile: "terminfo_windows.c".}
proc get_term_width*(): cint {.importc.}
proc get_term_height*(): cint {.importc.}
