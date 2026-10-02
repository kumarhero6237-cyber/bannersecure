# Admin Panel + Domain Lock — Setup

## Kya naya hai
- `/admin` — admin panel: key generate, domain add/edit, disable, rotate, delete, usage dekhna.
- Har key sirf **us key me saved domains** par chalti hai. **Nayi key par default me koi domain nahi hota → kahin nahi chalegi** jab tak aap domain add na karo.
- Purani hardcoded key `RAM-SAGAR` hata di gayi hai. Ab sirf admin panel se bani keys chalengi.
- `/status` aur `/refresh` ab sirf admin login ke baad khulte hain (pehle public the).
- Extra: expiry date, max requests limit, key rotate, server-IP allowlist.

## Setup (Vercel) - bas upload karna hai
Upstash Redis aur admin password pehle se code me set hain, koi env variable nahi chahiye.
1. Is zip ke saare files GitHub repo me daalo (repo **PRIVATE** rakho, kyunki `access_control.py` me database token hai).
2. Vercel apne aap deploy kar deta hai -> `https://TUMHARA-DOMAIN/admin` kholo -> login.
3. Env variables (`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`) daaloge to wo built-in values ko override karenge.
   Token reset karna ho to Upstash me reset karo aur naya token Vercel env me daalo.

## Admin password (hashed, plain nahi)
- Password code me kahin plain text me nahi hai, sirf salted **PBKDF2-SHA256** hash (260k rounds) `access_control.py` me hai.
- Password badalna ho: `python tools/make_password_hash.py` chalao, jo `ADMIN_PASSWORD_HASH=...` dega, use Vercel env me daalo. Env wala hash built-in wale ko override karta hai.
- Chhota/numeric password (jaise sirf 7 digit) agar hash leak ho jaye to kuch second me crack ho jata hai. Isliye repo **private** rakho aur 10+ characters (letters + numbers) wala password set karo.
- Login par brute-force limit hai (10 minute me 8 galat try).

## Setup (VPS / local)
```
pip install -r requirements.txt
python app.py
```
Keys `data/keys.json` me save hoti hain (ya `KEYS_FILE` path me).

## Key use kaise karein
```
GET /uc-main?uid=123456789&key=RVN-xxxx
GET /uc-info?uid=123456789&key=RVN-xxxx
GET /uc-banner?uid=123456789&key=RVN-xxxx
```
Key header me bhi bhej sakte ho: `X-API-Key: RVN-xxxx`.

## Domain lock ke rules
| Rule | Matlab |
|---|---|
| `example.com` | sirf example.com (www.example.com **alag** hai, dono add karo) |
| `*.example.com` | saare subdomains (a.example.com), apex nahi |
| Domain list khali | key kahin nahi chalegi (default) |
| Browser call | request ka `Origin` (nahi to `Referer`) header domain list se match hona chahiye |
| Server-to-server call (no Origin/Referer) | sirf tab chalegi jab uska IP key ke "Allowed server IPs" me ho |

Origin/Referer galat ho ya `null` ho to block.

## Zaruri baat (limitation)
Domain lock `Origin/Referer` header par based hai. Browser me ye header JavaScript fake nahi kar sakta, isliye
kisi aur website par key chori karke lagana block hota hai. Lekin koi apne server/curl se header manually
set kare aur use aapke allowed domain ka naam pata ho, to wo spoof kar sakta hai. Isliye:
- Key sirf frontend par lagani ho to domain lock kaafi hai.
- Server-side use ke liye "Allowed server IPs" use karo (spoof nahi hota).
- Leak ho to panel se **ROTATE KEY** ya **DISABLE** karo.

## Note
`app.py` me `_env_probe()` check hai jo `JWT_API_URL` badalne par app band kar deta hai.
Maine use touch nahi kiya; JWT URL change karna ho to pehle ye check hatana padega.
