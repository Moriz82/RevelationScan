# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the spinner module. This module will allow the application to:

# 1. Display a spinning animation in the terminal (like a loading indicator)

# 2. Show that something is happening even when it takes a while

# 3. Make the terminal look fancy with animated characters

from __future__ import annotations

import sys
import threading
import time

from .colors import Palette, apply_color, ENABLE_COLOR

###########################################################################

"""

Name: Spinner

Function: A class that displays an animated spinner in the terminal. It runs

in a separate thread so it doesn't block the main program. Think of it like

a loading bar, but cooler because it spins!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class Spinner:
    ###########################################################################

    """

    Name: __init__

    Function: Constructor that sets up the spinner with a prefix, animation

    frames, and update interval.

    Arguments: prefix - text to show before the spinner (default: "    ")

                frames - list of characters to cycle through (default: ["|", "/", "-", "\\"])

                interval - how long to wait between frame updates (default: 0.1 seconds)

    Returns: No value returned

    """

    def __init__(self, prefix: str = "    ", frames: list[str] | None = None, interval: float = 0.1) -> None:
        ### Text to display before the spinner animation
        self.prefix = prefix
        ### Characters to cycle through (default is the classic spinner: | / - \)
        self.frames = frames or ["|", "/", "-", "\\"]
        ### How long to wait between each frame (in seconds)
        self.interval = interval
        ### Event to signal when we should stop spinning
        self._stop = threading.Event()
        ### Thread that runs the animation (None when not running)
        self._thread: threading.Thread | None = None

#$ End __init__

    ###########################################################################

    """

    Name: start

    Function: Start the spinner animation in a background thread. If it's

    already running or colors are disabled, do nothing.

    Arguments: None

    Returns: No value returned

    """

    def start(self) -> None:
        ### If already running or colors are disabled, don't start
        if self._thread is not None or not ENABLE_COLOR:
            return
        ### Clear the stop event (in case it was set before)
        self._stop.clear()
        ### Create a daemon thread to run the animation (daemon means it dies when main thread dies)
        self._thread = threading.Thread(target=self._animate, daemon=True)
        ### Start the thread
        self._thread.start()

#$ End start

    ###########################################################################

    """

    Name: stop

    Function: Stop the spinner animation and clean up the display. If it's

    not running or colors are disabled, do nothing.

    Arguments: None

    Returns: No value returned

    """

    def stop(self) -> None:
        ### If not running or colors are disabled, don't try to stop
        if self._thread is None or not ENABLE_COLOR:
            return
        ### Signal the thread to stop
        self._stop.set()
        ### Wait for the thread to finish (with 1 second timeout)
        self._thread.join(timeout=1)
        ### Clear the thread reference
        self._thread = None
        ### Erase the spinner by writing spaces and moving cursor back
        sys.stdout.write("\r" + " " * (len(self.prefix) + 4) + "\r")
        sys.stdout.flush()

#$ End stop

    ###########################################################################

    """

    Name: _animate

    Function: The animation loop that runs in a separate thread. It cycles

    through the frames and displays them one at a time.

    Arguments: None

    Returns: No value returned

    """

    def _animate(self) -> None:
        ### Start at frame index 0
        idx = 0
        ### Keep spinning until we're told to stop
        while not self._stop.is_set():
            ### Get the current frame (use modulo to wrap around)
            frame = self.frames[idx % len(self.frames)]
            ### Write the prefix, colored frame, and a space (overwrite the line)
            sys.stdout.write(f"\r{self.prefix}{apply_color(frame, Palette.DIM)} ")
            sys.stdout.flush()
            ### Sleep for the interval duration
            time.sleep(self.interval)
            ### Move to the next frame
            idx += 1

#$ End _animate

#$ End Spinner
