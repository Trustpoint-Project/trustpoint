"""Contains all the views of Signer App."""

import json
import urllib
from collections.abc import Sequence
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import BaseModelForm
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from .forms import SignerForm
from .models import SignedMessage, Signer
from .util.keygen import load_private_key_object, generate_private_key


class SignerListView(LoginRequiredMixin, ListView[Signer]):
    """Class View for List of Signers."""

    model = Signer
    paginate_by = 10
    template_name = 'signer/signers.html'
    context_object_name = 'signers'

    def get_ordering(self) -> str | Sequence[str] | None:
        """Returns the sort parameters as a list.

        Returns:
           The sort parameters, if any. Otherwise the default sort parameter.
        """
        return ['-created_on']


class SignerDeleteView(DeleteView[Signer, BaseModelForm[Signer]]):
    """Class View for Deleting a Signer."""

    model = Signer
    paginate_by = 10
    success_url = reverse_lazy('signerList')


class SignerEditView(UpdateView[Signer, SignerForm]):
    """Class View for Updating/Editing the Signer."""

    model = Signer
    success_url = reverse_lazy('signerList')
    form_class = SignerForm
    template_name = 'addSigner.html'
    context_object_name = 'signer'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the title to the context.

        Args:
            **kwargs: All keyword arguments are passed to super().get_context_data.

        Returns:
            The context for the page.
        """
        context = super().get_context_data(**kwargs)
        context['form_title'] = _('Edit Signer')

        return context


class SignerDetailView(DetailView[Signer]):
    """View Class for Signer Details."""

    model = Signer
    paginate_by = 10
    template_name = 'signer_detail.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds signed messages object and certificate object to the context.

        Args:
            **kwargs: All keyword arguments are passed to super().get_context_data.

        Returns: Gives the context data containing the signed messages object and certificate object fields.

        """
        context = super().get_context_data(**kwargs)

        context['signed_messages'] = self.object.signed_messages.all()

        try:
            cert_obj = x509.load_pem_x509_certificate(self.object.certificate.encode())
            context['cert_details'] = {
                'subject': cert_obj.subject.rfc4514_string(),
                'issuer': cert_obj.issuer.rfc4514_string(),
                'serial_number': cert_obj.serial_number,
                'not_valid_before': cert_obj.not_valid_before,
                'not_valid_after': cert_obj.not_valid_after,
                'certificate': cert_obj.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'),
            }
        except ValueError:
            messages.add_message(self.request, messages.ERROR, 'Failed to parse certificate.')

        return context


    pass


class SignerCreateView(CreateView[Signer, SignerForm]):
    """For Signer Create View."""

    model = Signer
    form_class = SignerForm
    template_name = 'signer/addSigner.html'
    success_url = reverse_lazy('signerList')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the title to the context.

        Args:
            **kwargs: All keyword arguments are passed to super().get_context_data.

        Returns:
            The context for the page.
        """
        context = super().get_context_data(**kwargs)
        context['form_title'] = 'Add Signer'
        return context

    def form_valid(self, form: SignerForm) -> HttpResponse:
        """Creates the keypair and certificate, and stores it in the db.

        Args:
            form: The SignerForm to create new signer.

        Returns:
            The HttpResponse corresponding to the success url.
        """
        signer = form.save(commit=False)

        signer.private_key = generate_private_key(
            algorithm_oid_str=signer.signing_algorithm,
            curve_name=signer.curve,
            key_size=signer.key_length,
        )

        private_key_obj = load_private_key_object(signer.private_key)
        public_key = private_key_obj.public_key()

        # Create self-signed certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(x509.NameOID.COMMON_NAME, signer.unique_name),
                    ]
                )
            )
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(x509.NameOID.COMMON_NAME, signer.unique_name),
                    ]
                )
            )
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(timezone.now())
            .not_valid_after(signer.expires_by)
        )

        certificate = builder.sign(private_key=private_key_obj, algorithm=hashes.SHA256())

        signer.certificate = certificate.public_bytes(serialization.Encoding.PEM).decode()

        signer.save()
        return super().form_valid(form)


@method_decorator(csrf_exempt, name='dispatch')
class SignHashAPIView(View):
    """API view for sending POST request to get Signature."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Send POST request when API is called.

        Args:
            request:POST

        Returns:
            HTTPResponse containing the signature object.

        """
        pem_raw = request.META.get('HTTP_X_SSL_CLIENT_CERT')
        if not pem_raw or request.META.get('HTTP_X_SSL_CLIENT_VERIFY') != 'SUCCESS':
            return JsonResponse({'error': 'mTLS client cert required'}, status=401)

        # Decode PEM
        try:
            pem = urllib.parse.unquote(pem_raw)
            cert = x509.load_pem_x509_certificate(pem.encode('utf-8'))
            subject = cert.subject.rfc4514_string()  # human-readable DN

        except (ValueError, UnsupportedAlgorithm):
            return JsonResponse({'error': 'Invalid certificate format'}, status=400)

        try:
            data = json.loads(request.body)
            signer_id = data.get('signer_id')
            hash_hex = data.get('hash')

            if not signer_id or not hash_hex:
                return JsonResponse({'error': 'Missing signer_id, token key or hash'}, status=400)

            signer = Signer.objects.get(pk=signer_id)
            private_key = load_private_key_object(signer.private_key)
            hash_bytes = bytes.fromhex(hash_hex)

            if isinstance(private_key, rsa.RSAPrivateKey):  # RSA
                signature = private_key.sign(hash_bytes, padding.PKCS1v15(), getattr(hashes, signer.hash_function)())
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):  # ECC
                signature = private_key.sign(hash_bytes, ec.ECDSA(getattr(hashes, signer.hash_function)()))
            else:
                return JsonResponse({'error': 'Unsupported algorithm'}, status=400)

            SignedMessage.objects.create(
                signer=signer, cert_subject=subject, hash_value=hash_hex, signature=signature.hex()
            )

            return JsonResponse({'signature': signature.hex()}, status=200)

        except Signer.DoesNotExist:
            return JsonResponse({'error': 'Signer not found'}, status=404)
