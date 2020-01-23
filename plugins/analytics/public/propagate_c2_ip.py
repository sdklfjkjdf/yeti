from __future__ import unicode_literals
from datetime import timedelta

from plugins.analytics.public.process_url import ProcessUrl
from core.analytics import ScheduledAnalytics
from mongoengine import Q
import logging


class PropagateC2Ip(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "PropagateC2Ip",
        "description": "Propagates malware from URLs to hostnames",
    }

    ACTS_ON = 'Hostname'  # act on Urls only

    CUSTOM_FILTER = Q(tags__name="c2")  # filter only tagged elements

    EXPIRATION = None

    @staticmethod
    def each(obj):
        n = obj.neighbors(neighbor_type="Ip").values()[0]
        # logging.debug('there n')
        # logging.debug(n)
        # logging.debug('there for')
        for link in n:
            # logging.debug(link)
            # logging.debug('after iteration')
            link[1].tag('c2')
        # if n:
        #     for link in n[0]:
        #         link[1].tag('phishing')
        # else:
        #     h = ProcessUrl.each(obj)
        #     if h is not None:
        #         h.tag('phishing')
