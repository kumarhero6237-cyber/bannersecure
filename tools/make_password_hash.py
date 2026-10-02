"""Naya admin password hash banao:  python tools/make_password_hash.py
Output ko env variable ADMIN_PASSWORD_HASH me daalo (Vercel -> Settings -> Environment Variables)."""
import getpass, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from access_control import make_password_hash

pw = getpass.getpass("New admin password: ")
if len(pw) < 10:
    print("Warning: 10+ characters rakho (letters + numbers) - chhota password crack ho jata hai.")
if pw != getpass.getpass("Repeat: "):
    sys.exit("Passwords match nahi hue.")
print("\nADMIN_PASSWORD_HASH=" + make_password_hash(pw))
