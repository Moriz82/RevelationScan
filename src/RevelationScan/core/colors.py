# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the colors module. This module will allow the application to:

# 1. Define color codes for terminal output (because plain text is boring)

# 2. Check if the terminal supports colors (not all terminals are fancy)

# 3. Apply colors to text strings (make things pretty!)

# 4. Enable/disable color output (for when you want to be boring)

from __future__ import annotations

import os
import sys

###########################################################################

"""

Name: Palette

Function: A class that holds all the ANSI color escape codes. It's like a

paint palette, but for your terminal instead of a canvas.

Arguments: None (it's a class with constants)

Returns: No value returned

"""

class Palette:
    ### Red color - for when things are really bad (like critical issues)
    RED = "\033[91m"
    ### Yellow color - for warnings (like "hey, maybe check this out")
    YELLOW = "\033[93m"
    ### Green color - for good things (like "everything is fine!")
    GREEN = "\033[92m"
    ### Blue color - for informational stuff (like "here's some info")
    BLUE = "\033[94m"
    ### Cyan color - for when you want to be fancy
    CYAN = "\033[96m"
    ### Magenta color - for when you're feeling purple (but it's called magenta)
    MAGENTA = "\033[95m"
    ### Bold text - make things stand out (like shouting, but in text)
    BOLD = "\033[1m"
    ### Dim text - make things subtle (like whispering, but in text)
    DIM = "\033[2m"
    ### Reset code - turn off all the fancy formatting and go back to normal
    RESET = "\033[0m"

#$ End Palette

###########################################################################

"""

Name: supports_color

Function: Check if the terminal stream supports color output. Some terminals

are old and boring and don't support colors, so we need to check first.

Arguments: stream - the output stream to check (defaults to stdout)

Returns: Boolean - True if colors are supported, False otherwise

"""

def supports_color(stream: object = sys.stdout) -> bool:
    ### Check if the stream has an isatty method AND it returns True (it's a TTY)
    ### AND the TERM environment variable isn't set to "dumb" (which means no colors)
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM", "") != "dumb"

#$ End supports_color

### Check once at module load time if we support colors
SUPPORTS_COLOR = supports_color()
### Set the global flag to enable/disable colors (starts as whatever supports_color says)
ENABLE_COLOR = SUPPORTS_COLOR

###########################################################################

"""

Name: apply_color

Function: Apply color codes to a text string. If colors are disabled or the

text is empty, just return the text as-is (no fancy stuff).

Arguments: text - the string to colorize, *codes - variable number of color codes

Returns: The colored string (or plain string if colors are disabled)

"""

def apply_color(text: str, *codes: str) -> str:
    ### If the text is empty or colors are disabled, just return the text unchanged
    if not text or not ENABLE_COLOR:
        return text
    ### Join all the color codes together, add the text, then add the reset code
    return "".join(codes) + text + Palette.RESET

#$ End apply_color

###########################################################################

"""

Name: set_color_enabled

Function: Enable or disable color output globally. Sometimes you want to turn

off colors (like when redirecting to a file that doesn't understand ANSI codes).

Arguments: enabled - boolean to enable (True) or disable (False) colors

Returns: No value returned

"""

def set_color_enabled(enabled: bool) -> None:
    ### Use global keyword so we can modify the module-level variable
    global ENABLE_COLOR
    ### Set the global flag to whatever the user wants
    ENABLE_COLOR = enabled

#$ End set_color_enabled
