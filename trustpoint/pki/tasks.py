import logging
import threading
import time
from datetime import datetime, timedelta
from heapq import heapify, heappop, heappush

from django.conf import settings
from django.utils import timezone

from .models import IssuingCaModel

crl_schedule = []

log = logging.getLogger('tp.pki')


def initialize_crl_schedule() -> None:
    """Initialize the CRL schedule for all IssuingCas."""
    for entry in IssuingCaModel.objects.all():
        crl = entry.get_issuing_ca().get_crl_as_x509()
        if crl:
            next_crl_time = crl.next_update_utc
            heappush(crl_schedule, (next_crl_time, entry))
        else:
            generate_crl(entry)
    log.debug('All CRLs initialized: %s', crl_schedule)


def add_crl_to_schedule(instance) -> bool:
    """Adds new CRL instance to scheduler"""
    if isinstance(instance, IssuingCaModel):
        schedule_next_crl(instance)
        log.debug('%s added to CRL schedule.', instance)
        return True
    raise TypeError


def remove_crl_from_schedule(instance) -> bool:
    """Removes CRL instance from scheduler after instance got deleted"""
    global crl_schedule
    if isinstance(instance, IssuingCaModel):
        original_length = len(crl_schedule)
        crl_schedule = [(time, inst) for time, inst in crl_schedule if inst != instance]
        heapify(crl_schedule)
        if len(crl_schedule) < original_length:
            log.debug('%s removed from CRL schedule.', instance)
        return True
    raise TypeError


def schedule_next_crl(issuing_ca: IssuingCaModel) -> None:
    """Schedule the next CRL generation for the given issuing instance.

    Args:
        entry (IssuingCa or DomainProfile): The issuing instance for which to schedule the next CRL generation.
    """
    crl = issuing_ca.get_issuing_ca().get_crl_as_x509()
    next_crl_time = crl.next_update_utc if crl else datetime.now() + timedelta(minutes=issuing_ca.next_crl_generation_time)
    heappush(crl_schedule, (next_crl_time, issuing_ca))


def generate_crl(issuing_instance) -> None:
    """Generate a CRL for the given issuing instance and schedule the next generation.

    Args:
        issuing_instance (IssuingCa or DomainProfile): The issuing instance for which to generate a CRL.
    """
    if isinstance(issuing_instance, IssuingCaModel):
        issuing_instance.get_issuing_ca().generate_crl()
    schedule_next_crl(issuing_instance)


def crl_scheduler() -> None:
    """Scheduler function that runs in a separate thread to manage CRL generation."""
    log.debug('CRL scheduler started.')
    while True:
        if crl_schedule:
            next_crl_time, issuing_instance = crl_schedule[0]
            sleep_time = (next_crl_time - timezone.now()).total_seconds()

            if sleep_time > 0:
                log.debug('CRL scheduler sleeping for %s seconds', sleep_time)
                time.sleep(sleep_time)
            else:
                heappop(crl_schedule)
                generate_crl(issuing_instance)
        else:
            log.debug('No CRL scheduled, sleeping for 1 hour')
            time.sleep(60 * 60)


def start_crl_generation_thread() -> None:
    """Start the CRL generation thread."""
    log.info('CRL thread started.')
    initialize_crl_schedule()
    crl_thread = threading.Thread(target=crl_scheduler, daemon=True)
    crl_thread.start()
