from fastapi import FastAPI, Request, status
from datetime import datetime
import uuid
import aioredis
import asyncio
import json, typing
from starlette.responses import Response
from ua_parser import user_agent_parser

app = FastAPI()
rdb = None # global redis client
# headers to be used for HTTP signaturing
IMPORTANT_HEADERS = ['user-agent', 'accept', 'accept-encoding', 'accept-language']
# Dictionary containing mappings between browser and version to expected header order
HEADERS_SIGNATURES = None
# Dictionary mapping JA3 hashes to observed clients
JA3_HASHES = None

class PrettyJSONResponse(Response):
    # Response type to render JSON prettier in browser
    # https://stackoverflow.com/questions/67783530/is-there-a-way-to-pretty-print-prettify-a-json-response-in-fastapi
    media_type = "application/json"

    def render(self, content) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(", ", ": "),
        ).encode("utf-8")

@app.on_event('startup')
async def startup():
    # Create a Redis connection, load the header sigs and JA3 hashes
    global rdb, HEADER_SIGNATURES, JA3_HASHES
    rdb = await aioredis.from_url('redis://redis:6379')

    with open('header_signatures.json') as f:
        HEADER_SIGNATURES = json.loads(f.read().strip())
    
    with open('ja3_hashes.json') as f:
        JA3_HASHES = json.loads(f.read().strip())

async def get_from_redis(key, max_tries=25):
    # Function to retrive value from Redis, but retries for up to 5s
    result = None
    while max_tries > 0:
        result = await rdb.get(key)
        if result is not None:
            #await rdb.delete(key)
            break
        max_tries -= 1
        await asyncio.sleep(0.2)
    return result.decode() if result else None

def check_tcp_spoofing(parsed_ua, p0f_result):
    if not p0f_result:
        return None

    p0f_class, p0f_name = p0f_result.split(':', 1)
    if parsed_ua['os']['family'] == 'Windows' and p0f_class == 'win':
        return False
    elif parsed_ua['os']['family'] == 'Windows' and p0f_class != 'win':
        return True
    elif parsed_ua['os']['family'] == 'Mac OS X':
        return p0f_name != 'Mac OS X'
    elif parsed_ua['os']['family'] in ['Linux', 'Ubuntu']:
        return p0f_class != "unix"
    else:
        return None # spoofing status unknown

def check_http_spoofing(parsed_ua, seen_headers):
    known_header_strings = HEADER_SIGNATURES.get(parsed_ua['user_agent']['family'], {}) \
                                            .get(parsed_ua['user_agent']['major'], [])

    for header_string in known_header_strings:
        headers = header_string.split(', ')
        seen_headers = seen_headers.split(', ')
        orders = []

        if 'user-agent' in headers:
            try:
                # user-agent must always be present in the correct location
                r = (headers.index('user-agent') == seen_headers.index('user-agent'))
                if r == False:
                    return True
            except ValueError:
                return True
        
        # other optional headers like Accept-Language can be missing but
        # headers must still be in same relative order
        for h in seen_headers:          
            orders.append(headers.index(h))
        
        if orders != sorted(orders):
            return True
    
    return False if known_header_strings else None


def check_tls_spoofing(parsed_ua, ja3_hash):
    if JA3_HASHES.get(ja3_hash) is None:
        return (None, None)
    else:
        browser = parsed_ua['user_agent']['family']
        major = parsed_ua['user_agent']['major']
        minor = parsed_ua['user_agent']['minor']
        version = f"{major}.{minor}"
        if JA3_HASHES[ja3_hash].get(browser) and version in JA3_HASHES[ja3_hash][browser]:
            return (False, JA3_HASHES[ja3_hash])
        else:
            return (True, JA3_HASHES[ja3_hash])


@app.get("/", response_class=PrettyJSONResponse)
async def fingerprint(request: Request, debug: typing.Union[str, None] = None):
    
    real_src_ip = request.headers.get('X-FP-IP')
    real_src_port = request.headers.get('X-FP-Port')
    user_agent = request.headers.get('User-Agent')

    if not (real_src_ip and real_src_port and user_agent):
        return {"status": status.HTTP_400_BAD_REQUEST,
                "msg": "User-Agent header is required."
                }

    key_str = f"{real_src_ip}:{real_src_port}"
    parsed_ua = user_agent_parser.Parse(user_agent)
    observed_headers = ", ".join([header for header in filter(lambda h: h in IMPORTANT_HEADERS,
                                                              request.headers.keys())])
    
    p0f_sig = await get_from_redis(f"{key_str}_tcp")
    p0f_result_string = await get_from_redis(f"{key_str}_tcp_result")
    ja3 = await get_from_redis(f"{key_str}_ja3")
    ja3_hash = await get_from_redis(f"{key_str}_ja3_hash")

    is_tcp_spoofing = check_tcp_spoofing(parsed_ua, p0f_result_string)
    is_http_spoofing = check_http_spoofing(parsed_ua, observed_headers)
    is_tls_spoofing, matching_clients = check_tls_spoofing(parsed_ua, ja3_hash)
    
    filename = str(uuid.uuid4())

    response = {"ts": str(datetime.now()),
                "status": 200,
                "id": filename,
                "src": {
                    "ip": real_src_ip,
                    "port": real_src_port,
                    "ua": user_agent
                },
                "tcp": {
                    "raw_signature": p0f_sig,
                    "detected_os": p0f_result_string,
                    "spoof": is_tcp_spoofing
                },
                "tls": {
                    "ja3": ja3,
                    "ja3_hash": ja3_hash,
                    "spoof": is_tls_spoofing,
                    "known_clients": matching_clients
                },
                "http": {
                    "headers": observed_headers,
                    "spoof": is_http_spoofing
                }
            }

    if debug is not None:
        with open(f'output/{filename}.txt','w') as f:
            f.write(json.dumps(response) + '\n')
            f.write(json.dumps({k: v for k,v in request.headers.items()}) + '\n')
    
    return response

@app.get("/debug", response_class=PrettyJSONResponse)
async def debug(request: Request):
    r = await fingerprint(request, 'yes')
    return r