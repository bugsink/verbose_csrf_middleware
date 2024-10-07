from django.test import TestCase as DjangoTestCase
from django.test import Client
from django.test.utils import override_settings


class VerboseCsrfMiddlewareTest(DjangoTestCase):
    maxDiff = None

    def _test(self, origin=None, referer=None, secure=False, reason=None):
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        if referer is not None:
            headers["Referer"] = referer

        client = Client(enforce_csrf_checks=True)

        response = client.get('/admin/login/')
        self.assertEqual(response.status_code, 200)
        token = str(response.context['csrf_token'])

        # username/password not provided, but that's not our focus
        response = client.post('/admin/login/', {'csrfmiddlewaretoken': token}, headers=headers, secure=secure)

        expected_status_code = 200 if reason is None else 403
        self.assertEqual(response.status_code, expected_status_code)

        if reason is not None:
            self.assertEqual(response.context['reason'], reason)

    def test_good_origin_given(self):
        # this matches the first branch in the original code, as well as what happens in local development w/ browser
        self._test(origin="http://testserver")

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://subdomain.example.org"])
    def test_trusted_origin_configured_and_matching(self):
        self._test(origin="https://subdomain.example.org")

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.org"])
    def test_trusted_origin_wildcard_configured_and_matching(self):
        self._test(origin="https://subdomain.example.org")

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://subdomain.example.org"])
    def test_trusted_origin_given_but_still_no_match_exact(self):
        self._test(
            origin="https://thisiswrong.example.org", secure=True,
            reason="Origin header does not match (deduced) Host: 'https://thisiswrong.example.org' != "
                   "'https://testserver'; nor any of the CSRF_TRUSTED_ORIGINS: ['https://subdomain.example.org']")

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.configured.org"])
    def test_trusted_origin_given_but_still_no_match_subdomain(self):
        self._test(
            origin="https://nonmatching.given.org", secure=True,
            reason="Origin header does not match (deduced) Host: 'https://nonmatching.given.org' != "
                   "'https://testserver'; nor any of the CSRF_TRUSTED_ORIGINS: ['https://*.configured.org']")

    @override_settings(CSRF_TRUSTED_ORIGINS=["http://*.example.org"])  # http, not https
    def test_trusted_origin_given_but_still_no_match_subdomain_not_used_when_wrong_scheme(self):
        self._test(
            origin="https://anything.example.org", secure=True,
            reason="Origin header does not match (deduced) Host: 'https://anything.example.org' != "
                   "'https://testserver'; nor any of the CSRF_TRUSTED_ORIGINS: ['http://*.example.org (wrong scheme)']")

    def test_origin_non_matching_schemes(self):
        self._test(
            origin="https://testserver", reason="Origin header does not match (deduced) Host: "
            "'https://testserver' != 'http://testserver' (wrong scheme)"
            )

    @override_settings(VERBOSE_CSRF_REASON_SCHEME_MISMATCH="(wrong scheme); fix your proxy's X-Forwarded-Proto")
    def test_origin_non_matching_schemes_different_message(self):
        # The principled/general case for "any given Django site" is simply the detection of differing schemes. In
        # 'theory' this could happen also when someone makes a request from a secure to non-secure server, so
        # verbose_csrf_middleware cannot be 100% sure that the cause for this is proxy-misconfiguration.
        #
        # For a particular piece of softare that happens to be implemented in Django, but is intended to be self-hosted
        # by many different individuals and organisations (e.g. Bugsink) one might know that there's never any
        # intentional cross-scheme POSTing going on. In that case "wrong scheme" always just means "Django's confused
        # about is_secure", and you'd want to point people in the right direction.
        self._test(
            origin="https://testserver", reason="Origin header does not match (deduced) Host: "
            "'https://testserver' != 'http://testserver' (wrong scheme); fix your proxy's X-Forwarded-Proto"
            )

    def test_non_matching_origin_given(self):
        # this is what you'd get if you tried to POST to the server from a different domain, or (more likely) if your
        # proxy is misconfigured and mangles the Origin header
        self._test(
            origin="http://nonmatching", reason="Origin header does not match (deduced) Host: "
            "'http://nonmatching' != 'http://testserver'"
            )

    def test_null_origin_given(self):
        # Like 'test_non_matching_origin_given', but with a null origin (specifically observed in the wild for
        # misconfigured proxies)
        self._test(
            origin="null", reason="Origin header does not match (deduced) Host: 'null' != 'http://testserver'"
            )

    def test_malformed_origin_given(self):
        self._test(
            origin="http://invalid[ipv6/",
            reason="Origin header does not match (deduced) Host: 'http://invalid[ipv6/' != 'http://testserver'; "
                   "Origin header is malformed: 'http://invalid[ipv6/'"
            )

    def test_referer_is_given_not_secure(self):
        self._test(referer="http://anythinggoes/debug/csrf/")  # not secure: referrer check is skipped

    def test_referer_given_secure_and_referrer_correct(self):
        self._test(referer="https://testserver/debug/csrf/", secure=True)

    def test_no_origin_no_referer_secure(self):
        # this is what you'd get if your referer is _missing for whatever reason, e.g. if your proxy is misconfigured.
        # (while not sending an Origin header at all, or the proxy hiding that too)
        self._test(
            secure=True,
            reason="Referer checking failed - no Referer.",
            )

    def test_referer_malformed(self):
        # this is what you'd get if your referer is _malformed_ for whatever reason, e.g. if your proxy is
        # misconfigured. (while not sending an Origin header at all)
        self._test(
            referer='null', secure=True,
            reason="Referer checking failed - Referer is malformed.",
            )

    def test_referer_non_matching(self):
        # this is what you'd get if your referer is _wrong_ for whatever reason, e.g. if your proxy is misconfigured.
        # (while not sending an Origin header at all)
        self._test(
            referer='https://www.wrong.org/', secure=True,
            reason="Referer checking failed - 'www.wrong.org' does not match any of ['testserver' (host)].",
            )

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://csrf_trusted_origin.org"])
    def test_referer_matches_neither_host_nor_explicitly_trusted_origins(self):
        self._test(
            referer='https://refererheader.org/', secure=True,
            reason="Referer checking failed - 'refererheader.org' does not match any of "
                   "['csrf_trusted_origin.org' (trusted), 'testserver' (host)].",
            )

    @override_settings(CSRF_TRUSTED_ORIGINS=["http://domainmatchestoo.org"])  # note: http, not https
    def test_no_origin_referer_wrong_secure_csrf_trusted_origins_provided_wrong_scheme_is_no_problem(self):
        # this is in contrast to the Origin header, where the scheme must match.
        # (I haven't checked _why_ this is the case, these tests are just to document the current behavior)
        self._test(referer='https://domainmatchestoo.org/', secure=True)

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.org"])
    def test_csrf_trusted_origins_with_subdomains_and_match_with_referer(self):
        self._test(referer='https://subdomain.example.org/', secure=True)

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://www.example.org"])
    def test_crsf_trusted_origins_with_exact_match_and_referer(self):
        self._test(referer='https://www.example.org/', secure=True)

    @override_settings(CSRF_COOKIE_DOMAIN="expected.example.org")
    def test_csrf_cookie_domain_configured_but_not_matching_referer(self):
        self._test(
            referer='https://nonmatching.example.org/', secure=True,
            reason="Referer checking failed - 'nonmatching.example.org' does not match any of "
                   "['expected.example.org' (csrf_cookie)]."
            )

    @override_settings(CSRF_USE_SESSIONS=True, SESSION_COOKIE_DOMAIN="expected.example.org")
    def test_session_cookie_domain_configured_but_not_matching_referer(self):
        self._test(
            referer='https://nonmatching.example.org/', secure=True,
            reason="Referer checking failed - 'nonmatching.example.org' does not match any of "
                   "['expected.example.org' (session_cookie)]."
            )

    @override_settings(CSRF_COOKIE_DOMAIN="expected.example.org")
    def test_csrf_cookie_domain_configured_and_matching_referer(self):
        self._test(referer='https://expected.example.org/', secure=True)

    def test_referer_given_but_insecure_on_secure_host(self):
        self._test(
            referer="http://testserver/admin/login/", secure=True,
            reason="Referer checking failed - Referer is insecure while host is secure.")

    def test_just_token_checks(self):
        self._test()  # no origin, no referer, not secure: no checks at all (other than CSRF token, of course)
