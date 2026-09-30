from base64 import b64decode, b64encode
from ckan.plugins.toolkit import g, redirect_to, request, config
from flask import Blueprint
from urllib.parse import urlencode
from urllib.parse import parse_qs, urljoin
import ckan.plugins as p
import hashlib
import hmac
import logging
import os


log = logging.getLogger(__name__)

# Environment variable takes priority
sso_secret = config.get('discourse.sso.secret')
sso_secret = os.environ.get('CKAN_DISCOURSE_SSO_SECRET', sso_secret)
if sso_secret is None:
    raise Exception("Config 'discourse.sso.secret' or environment variable "
                    "CKAN_DISCOURSE_SSO_SECRET must be set")

discourse_url = config.get('discourse.url')
discourse_url = os.environ.get('CKAN_DISCOURSE_URL', discourse_url)
if discourse_url is None:
    raise Exception("Config 'discourse.url' or environment variable "
                    "CKAN_DISCOURSE_URL must be set")

def get_discourse_url():
    return discourse_url


bp = Blueprint('discourse', __name__, url_prefix='/discourse')

class DiscourseSSOPlugin(p.SingletonPlugin):

    p.implements(p.IBlueprint, inherit=True)
    p.implements(p.ITemplateHelpers)

    def get_blueprint(self):
        return [bp]

    def get_helpers(self):
        return {'get_discourse_url': get_discourse_url}

def sso_view():
    if not g.userobj:
        return redirect_to(controller='user',
                           action='login', came_from=request.url)

    if not signature_is_valid(request):
        raise Exception('Incorrect Discourse SSO Signature to CKAN')

    payload_b64 = make_payload(request, g.userobj)
    signature_hash = sign(payload_b64)
    query_string = urlencode({
        'sso': payload_b64,
        'sig': signature_hash.hexdigest(),
    })

    return_endpoint = urljoin(discourse_url, '/session/sso_login')
    return redirect_to(return_endpoint + "?" + query_string)

bp.add_url_rule('/sso', view_func=sso_view)

def signature_is_valid(request):
    payload_b64 = request.params.get('sso')
    log.debug("Payload Base64-encoded %s", payload_b64)
    their_sig = request.params.get('sig')
    log.debug("Their signature %r", their_sig)

    log_safer_secret = "%s...hidden...%s" % (sso_secret[:3], sso_secret[-3:])
    log.debug("SSO Secret %s", log_safer_secret)

    hash = sign(payload_b64)
    our_sig = str(hash.hexdigest())
    log.debug("Our signature %r", our_sig)

    return hmac.compare_digest(their_sig, our_sig)


def make_payload(payload_b64, userobj):
    payload_b64 = request.params.get('sso')
    payload = b64decode(payload_b64).decode('utf-8')
    log.debug("Payload %s", payload)
    nonce = parse_qs(payload)['nonce'][0]
    log.debug("Nonce %s", nonce)

    return b64encode(urlencode({
        'nonce': nonce,
        'email': userobj.email,
        'external_id': userobj.id,
        'username': userobj.name,
        'name': userobj.fullname,
        'bio': userobj.about,
        'require_activation': 'true',
    }).encode('utf-8')).decode('utf-8')


def sign(payload_b64):
    return hmac.new(sso_secret.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256)
