import logging
import boto3
import base64
import hashlib
from selectolax.parser import HTMLParser
from secrets import token_bytes
from botocore.exceptions import ClientError

client = boto3.client('s3')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

stashed = {}
style_hashes = None
script_hashes = None
nonce_replace = 'ew26COJKMG8qrA/bjTcl0w=='
style_replace = '[style-hashes]'
script_replace = '[script-hashes]'

# CSP script-src has:
#   - Hashes of the inline <script> and the integrity attrs on <script src=...>
#     (populated at runtime via the {script_replace} placeholder).
#   - 'self' so dynamic import() of lazy chunks is authorized. Per CSP3 spec, hash-source only
#     matches external scripts when the browser has integrity metadata for them; ES dynamic imports
#     can't carry integrity, so 'self' (URL-based) is how they get authorized. 'strict-dynamic'
#     was tried but Chrome does not reliably propagate hash-based trust to dynamic imports.
#   - 'wasm-unsafe-eval' for libsodium.
csp_base = f"base-uri 'self'; default-src 'none'; style-src 'self' 'nonce-ew26COJKMG8qrA/bjTcl0w==' {style_replace}; script-src {script_replace} 'self' 'wasm-unsafe-eval'; img-src 'self'; object-src 'none'; font-src 'self' https://fonts.gstatic.com/; connect-src 'self' https://api.pwnedpasswords.com/; frame-src 'none'; frame-ancestors 'none'; form-action 'self'; trusted-types angular angular#components; require-trusted-types-for 'script'; upgrade-insecure-requests; report-to csp-endpoint; report-uri https://o4511265226555392.ingest.us.sentry.io/api/4511265232650240/security/?sentry_key=a7be4684d4608abd82e299fea1b65927;"

def lambda_handler(event, context):
    global stashed, style_hashes, script_hashes

    key = 'index.html'
    if rq_ctx := event.get('requestContext', None):
        if http := rq_ctx.get('http', None):
            if path := http.get('path', None):
                if 'maintenance.html' in path.lower():
                    key = 'maintenance.html'
    etag, tree = stashed.get(key, ('',None))

    try:
        response = client.get_object(Bucket='quickcrypt', IfNoneMatch=etag, Key=key)
        # if etag matches, this raises 304 and we don't reparse
        if response and response['ResponseMetadata']['HTTPStatusCode'] == 200:
            base_html = response['Body'].read().decode('utf8')
            tree = HTMLParser(base_html)
            (style_hashes, script_hashes) = fix_csp(tree)
            tree = tree.html
            stashed[key] = (response['ETag'], tree)
    except ClientError as ce:
        if ce.response['Error']['Code'] != '304':
            raise ce

    if tree:
        nonce = token_bytes(16)
        nonce_b64 = base64.standard_b64encode(nonce).decode()

        csp = csp_base.replace(nonce_replace, nonce_b64)
        body = tree.replace(nonce_replace, nonce_b64)

        md5 = hashlib.md5(body.encode())
        etag = md5.hexdigest()

        # could do this a better way since the locations are known...
        style_list = ''
        if style_hashes:
            style_list = ' '.join([f"'{hash}'" for hash in style_hashes])

        script_list = ''
        if script_hashes:
            script_list = ' '.join([f"'{hash}'" for hash in script_hashes])

        csp = csp.replace(style_replace, style_list)
        csp = csp.replace(script_replace, script_list)

        return {
            'statusCode': 200,
            'headers': {
                "content-type": "text/html",
                'Content-Security-Policy': csp,
                'Etag': etag,
                'Cache-Control': 'public, max-age=3600',
            },
            'body':body,
        }
    else:
        return {
            'statusCode': response['ResponseMetadata']['HTTPStatusCode'] if response else 500,
            'body': 'cloud not load content from s3'
        }


def fix_csp(tree):
    style_hashes = update_hashes(tree, 'style')
    script_hashes = update_hashes(tree, 'script')

    # Angular adds integrity on stylesheet links; collect those for style-src.
    # modulepreload links also have integrity (for SRI), but their chunk
    # hashes are covered by the post-build script's `csp-hash` comments, so
    # we don't need to scrape them here.
    for element in tree.css('link'):
        if 'nonce' in element.attrs:
            del element.attrs['nonce']

        if 'integrity' in element.attributes and element.attributes.get('rel') == 'stylesheet':
            style_hashes.add(element.attributes['integrity'])

    return (style_hashes, script_hashes)


def update_hashes(tree, tag):
    hashes = set()
    for element in tree.css(tag):
        # nonce needs to exist to handling inline script injected nonce values
        # (by angular), but we don't want to use it on any static script/style
        # elements that all use sha384
        if 'nonce' in element.attrs:
            del element.attrs['nonce']

        if 'integrity' not in element.attributes:
            sha384 = hashlib.sha384(element.text().encode())
            b64 = base64.standard_b64encode(sha384.digest())
            integHash = 'sha384-' + b64.decode()
            element.attrs['integrity'] = integHash
            hashes.add(integHash)
        else:
            hashes.add(element.attributes['integrity'])

    return hashes