"""Small executable stand-in used by the runner integration tests."""
import pathlib
import sys
import time

tool, *args = sys.argv[1:]
if "--version" in args:
    print(f"{tool} version 9.99-test")
    raise SystemExit(0)
if "--help" in args:
    print(f"{tool} test help")
    raise SystemExit(0)
if "--sleep" in args:
    print("started", flush=True)
    time.sleep(30)
if tool == "nmap" and "-oX" in args:
    target = pathlib.Path(args[args.index("-oX") + 1])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="127.0.0.1"/><hostnames><hostname name="localhost"/></hostnames>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="Test server" version="1.0"/></port></ports></host>'
        '<runstats><finished summary="1 host up"/></runstats></nmaprun>',
        encoding="utf-8",
    )
print("tool=" + tool)
print("args=" + repr(args))
