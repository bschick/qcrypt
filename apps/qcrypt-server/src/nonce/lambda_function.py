import logging
import boto3
import base64
import hashlib
from selectolax.parser import HTMLParser
from secrets import token_bytes
from botocore.exceptions import ClientError


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

stashed = {}
style_hashes = None
script_hashes = None
nonce_replace = 'ew26COJKMG8qrA/bjTcl0w=='
style_replace = '[style-hashes]'
script_replace = '[script-hashes]'

# Fragile since this must be upudate when the Cloudfront QC-NoCORS-and-StrictSecurity policy changes
csp_base = f"base-uri 'self'; default-src 'none'; style-src 'self' 'nonce-ew26COJKMG8qrA/bjTcl0w==' {style_replace}; script-src {script_replace} 'wasm-unsafe-eval'; img-src 'self'; object-src 'none'; font-src 'self' https://fonts.gstatic.com/; connect-src 'self' https://api.pwnedpasswords.com/; frame-src 'none'; frame-ancestors 'none'; form-action 'self'; trusted-types angular angular#components; require-trusted-types-for 'script'; upgrade-insecure-requests;"

def lambda_handler(event, context):
    global stashed, style_hashes, script_hashes

    key = 'index.html'
    if rq_ctx := event.get('requestContext', None):
        if http := rq_ctx.get('http', None):
            if path := http.get('path', None):
                if 'maintenance.html' in path.lower():
                    key = 'maintenance.html'
    etag, tree = stashed.get(key, ('',None))

    client = boto3.client('s3')
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
                'Cache-Control': 'public, max-age=86400',
            },
            'body':body,
        }
    else:
        return {
            'statusCode': response['ResponseMetadata']['HTTPStatusCode'] if response else 500,
            'body': 'could not load content from s3'
        }


def fix_csp(tree):
    style_hashes = update_hashes(tree, 'style')
    script_hashes = update_hashes(tree, 'script')

    # angular adds integrity for css link, so collect those as well
    # (done't want to add sha hash to links, however)
    for element in tree.css('link'):
        if 'nonce' in element.attrs:
            del element.attrs['nonce']

        if 'integrity' in element.attributes and element.attributes['rel'] == 'stylesheet':
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