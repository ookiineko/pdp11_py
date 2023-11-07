import sys
import threading
import tty
import traceback

from pdp11 import *
from cons import *

def onkey():
    while True:
        which = ord(sys.stdin.read(1))
        addchar(which)
        threading.Timer(0.1, exec, (f'''\
import traceback
try:
    specialchar({which})
except:
    traceback.print_exc()
''', globals(), locals()))

tty.setcbreak(sys.stdin)
threading.Thread(target=onkey, daemon=True).start()

reset(); rkinit()
print('type `unix` at the `@` prompt to load the kernel, enjoy! faq: http://aiju.de/code/pdp11/faq')
run()
try:
    threading.Event().wait()
except KeyboardInterrupt:
    stop()
