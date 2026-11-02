from base64 import b64decode, b64encode
from flask import Blueprint, redirect
from urllib.parse import urlencode
from urllib.parse import parse_qs, urljoin
import ckan.plugins as p
from ckan.plugins import toolkit
import hashlib
import hmac
import logging
import os


log = logging.getLogger(__name__)


def get_discourse_url():
    return toolkit.config.get('discourse.url')


bp = Blueprint('discourse', __name__, url_prefix='/discourse')

class DiscourseSSOPlugin(p.SingletonPlugin):

    p.implements(p.IConfigurer, inherit=True)
    p.implements(p.IConfigDeclaration)
    p.implements(p.IBlueprint, inherit=True)
    p.implements(p.ITemplateHelpers)

    def declare_config_options(self, declaration, key):
        # Not marked as required, as they can be set via environment
        # variables instead. update_config() checks they are present.
        declaration.annotate("ckanext-discourse-sso")
        declaration.declare(key.discourse.sso.secret).set_description(
            "Shared secret, same as the sso_secret setting in Discourse. "
            "Can be set via the CKAN_DISCOURSE_SSO_SECRET env var.")
        declaration.declare(key.discourse.url).set_description(
            "URL of the Discourse instance. "
            "Can be set via the CKAN_DISCOURSE_URL env var.").set_example(
            "https://discourse.example.com/")

    def update_config(self, config_):
        # Environment variable takes priority
        sso_secret = os.environ.get(
            'CKAN_DISCOURSE_SSO_SECRET', config_.get('discourse.sso.secret'))
        if not sso_secret:
            raise Exception("Config 'discourse.sso.secret' or environment "
                            "variable CKAN_DISCOURSE_SSO_SECRET must be set")

        discourse_url = os.environ.get(
            'CKAN_DISCOURSE_URL', config_.get('discourse.url'))
        if not discourse_url:
            raise Exception("Config 'discourse.url' or environment variable "
                            "CKAN_DISCOURSE_URL must be set")

        config_['discourse.sso.secret'] = sso_secret
        config_['discourse.url'] = discourse_url

    def get_blueprint(self):
        return [bp]

    def get_helpers(self):
        return {'get_discourse_url': get_discourse_url}

def sso_view():
    if not toolkit.current_user.is_authenticated:
        return toolkit.redirect_to('user.login', next=toolkit.request.url)

    if not signature_is_valid(toolkit.request):
        toolkit.abort(400, 'Incorrect Discourse SSO Signature to CKAN')

    payload_b64 = make_payload(toolkit.request, toolkit.current_user)
    signature_hash = sign(payload_b64)
    query_string = urlencode({
        'sso': payload_b64,
        'sig': signature_hash.hexdigest(),
    })

    return_endpoint = urljoin(get_discourse_url(), '/session/sso_login')
    return redirect(return_endpoint + "?" + query_string)

bp.add_url_rule('/sso', view_func=sso_view)

def signature_is_valid(request):
    payload_b64 = request.args.get('sso')
    log.debug("Payload Base64-encoded %s", payload_b64)
    their_sig = request.args.get('sig')
    log.debug("Their signature %r", their_sig)

    if not payload_b64 or not their_sig:
        return False

    sso_secret = toolkit.config.get('discourse.sso.secret')
    log_safer_secret = "%s...hidden...%s" % (sso_secret[:3], sso_secret[-3:])
    log.debug("SSO Secret %s", log_safer_secret)

    hash = sign(payload_b64)
    our_sig = hash.hexdigest()
    log.debug("Our signature %r", our_sig)

    return hmac.compare_digest(their_sig, our_sig)


def make_payload(request, userobj):
    payload_b64 = request.args.get('sso')
    payload = b64decode(payload_b64).decode('utf-8')
    log.debug("Payload %s", payload)
    nonce = parse_qs(payload)['nonce'][0]
    log.debug("Nonce %s", nonce)

    return b64encode(urlencode({
        'nonce': nonce,
        'email': userobj.email,
        'external_id': userobj.id,
        'username': userobj.name,
        'name': userobj.fullname or '',
        'bio': userobj.about or '',
        'require_activation': 'true',
    }).encode('utf-8')).decode('utf-8')


def sign(payload_b64):
    sso_secret = toolkit.config.get('discourse.sso.secret')
    return hmac.new(sso_secret.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256)
